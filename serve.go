package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// serveState remembers which scheduled jobs already ran today, so a service
// restart doesn't re-run them.
type serveState struct {
	LastUpdate string `json:"last_update"` // "2006-01-02"
	LastScan   string `json:"last_scan"`
}

func (c *Config) serveStateFile() string { return filepath.Join(c.BaseDir, "serve-state.json") }

func loadServeState(cfg *Config) *serveState {
	st := &serveState{}
	data, err := os.ReadFile(cfg.serveStateFile())
	if err == nil {
		_ = json.Unmarshal(data, st)
	}
	return st
}

func saveServeState(cfg *Config, st *serveState) {
	if err := cfg.ensureDirs(); err != nil {
		return
	}
	data, _ := json.Marshal(st)
	_ = os.WriteFile(cfg.serveStateFile(), data, 0o644)
}

// dueToday reports whether the daily job scheduled at hhmm should run now:
// the time has passed and it has not run today yet.
func dueToday(lastRun string, now time.Time, hhmm string) bool {
	t, err := time.ParseInLocation("15:04", hhmm, now.Location())
	if err != nil {
		return false
	}
	sched := time.Date(now.Year(), now.Month(), now.Day(), t.Hour(), t.Minute(), 0, 0, now.Location())
	if now.Before(sched) {
		return false
	}
	return lastRun != now.Format("2006-01-02")
}

// runServe is the resident mode used by the Windows service (and available
// in the foreground for testing): it runs the watcher continuously and the
// self-scheduler for the daily update and scan. Jobs take the single-run
// lock, so the Task Scheduler fallback never overlaps with them.
func runServe(cfg *Config, ctx context.Context, logFile string) error {
	if err := cfg.ensureDirs(); err != nil {
		return err
	}
	if logFile != "" {
		f, err := os.OpenFile(logFile, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
		if err != nil {
			return err
		}
		defer f.Close()
		prev := logf
		logf = func(format string, args ...any) {
			line := fmt.Sprintf(time.Now().Format("2006-01-02 15:04:05 ")+format, args...)
			_, _ = f.WriteString(line)
			prev("%s", line)
		}
		defer func() { logf = prev }()
	}

	logf("WAMB serve: starting (update %s, scan %s, system=%v)\n", cfg.ScheduleUpdate, cfg.ScheduleScan, isSystemUser())

	watchCtx, cancelWatch := context.WithCancel(ctx)
	defer cancelWatch()
	go func() {
		if err := watchLoop(cfg, watchCtx); err != nil {
			logf("serve: watcher stopped: %v\n", err)
		}
	}()

	st := loadServeState(cfg)
	tick := time.NewTicker(30 * time.Second)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			logf("WAMB serve: stopped.\n")
			return nil
		case now := <-tick.C:
			if dueToday(st.LastUpdate, now, cfg.ScheduleUpdate) {
				st.LastUpdate = now.Format("2006-01-02")
				saveServeState(cfg, st)
				serveUpdate(cfg)
			}
			if dueToday(st.LastScan, now, cfg.ScheduleScan) {
				st.LastScan = now.Format("2006-01-02")
				saveServeState(cfg, st)
				serveScan(cfg)
			}
		}
	}
}

func serveUpdate(cfg *Config) {
	release, err := acquireLock(cfg)
	if err != nil {
		logf("serve: update skipped (%v)\n", err)
		return
	}
	defer release()
	out, err := runUpdate(cfg)
	if err != nil {
		logf("serve: freshclam failed: %v\n%s\n", err, out)
		return
	}
	logf("serve: signature update done\n")
}

func serveScan(cfg *Config) {
	release, err := acquireLock(cfg)
	if err != nil {
		logf("serve: scan skipped (%v)\n", err)
		return
	}
	defer release()
	targets := cfg.effectiveTargets()
	rep, err := executeScan(cfg, scanOptions{Targets: targets, Mode: "scheduled"})
	if err != nil {
		logf("serve: scan failed: %v\n", err)
		return
	}
	protected := effectiveProtected()
	if cookies := protectedCookieFiles(protected); len(cookies) > 0 {
		if extra, err := executeScan(cfg, scanOptions{FileList: cookies, Mode: "scheduled"}); err == nil {
			mergeReport(rep, extra)
		}
	}
	postProcess(cfg, rep, false, true)
	refreshHistory(cfg, targets, protected)
	logf("serve: scheduled scan %s: %d file(s), %d detection(s)\n", rep.ID, rep.ScannedFiles, len(rep.Detections))
}
