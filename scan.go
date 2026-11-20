package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

type Detection struct {
	Path      string `json:"path"`
	Signature string `json:"signature"`
}

type Report struct {
	ID           string      `json:"id"`
	Mode         string      `json:"mode"` // scan | changed | watch
	StartedAt    time.Time   `json:"started_at"`
	EndedAt      time.Time   `json:"ended_at"`
	Level        int         `json:"level"`
	Targets      []string    `json:"targets"`
	ScannedFiles int         `json:"scanned_files"`
	Infected     int         `json:"infected_files"`
	Detections   []Detection `json:"detections"`
	Quarantined  []string    `json:"quarantined,omitempty"`
	Warnings     []string    `json:"warnings,omitempty"`
	Errors       []string    `json:"errors,omitempty"`
	ExitCode     int         `json:"clamscan_exit_code"`
}

func newReportID(t time.Time) string { return t.Format("20060102-150405") }

// levelArgs maps the sensitivity level to extra clamscan flags.
func levelArgs(level int) []string {
	switch level {
	case 1: // low: official signatures only, nothing extra
		return nil
	case 3: // high: level 2 + PUA and phishing extras
		return []string{
			"--alert-broken=yes", "--alert-encrypted=yes",
			"--detect-pua=yes", "--alert-macros=yes",
			"--alert-phishing-ssl=yes", "--alert-phishing-cloak=yes",
		}
	default: // 2: standard
		return []string{"--alert-broken=yes", "--alert-encrypted=yes"}
	}
}

type scanOptions struct {
	Targets       []string // folders (recursive) — mutually exclusive with FileList
	FileList      []string // explicit files to scan
	Quarantine    bool
	Notify        bool
	Mode          string
	ExtraWarnings []string
}

// executeScan executes clamscan once and returns the filled report.
// Saving, quarantining and notifying are postProcess's job, so callers can
// merge several passes (folders + protected cookie files) into one report.
func executeScan(cfg *Config, opts scanOptions) (*Report, error) {
	protected := effectiveProtected()
	patterns, warnings := cfg.EffectiveExcludes(protected)
	warnings = append(warnings, opts.ExtraWarnings...)

	rep := &Report{
		ID:         newReportID(time.Now()),
		Mode:       opts.Mode,
		StartedAt:  time.Now(),
		Level:      cfg.Level,
		Targets:    opts.Targets,
		Detections: []Detection{},
	}
	if opts.FileList != nil {
		rep.Targets = opts.FileList
	}

	args := []string{"--infected", "--stdout", "--no-summary=false"}
	if cfg.DatabaseDir != "" {
		args = append(args, "--database="+cfg.DatabaseDir)
	}
	args = append(args, levelArgs(cfg.Level)...)
	for _, p := range patterns {
		args = append(args, "--exclude="+p)
	}

	var listFile string
	if opts.FileList != nil {
		f, err := os.CreateTemp("", "wamb-filelist-*.txt")
		if err != nil {
			return nil, err
		}
		listFile = f.Name()
		w := bufio.NewWriter(f)
		for _, p := range opts.FileList {
			fmt.Fprintln(w, p)
		}
		w.Flush()
		f.Close()
		defer os.Remove(listFile)
		args = append(args, "--file-list="+listFile)
	} else {
		args = append(args, "-r")
		args = append(args, opts.Targets...)
	}

	cmd := exec.Command(cfg.ClamScanPath, args...)
	out, runErr := cmd.CombinedOutput() // clamscan sends warnings to stderr; keep them
	exitCode := 0
	if ee, ok := runErr.(*exec.ExitError); ok {
		exitCode = ee.ExitCode()
	} else if runErr != nil {
		return nil, fmt.Errorf("cannot run clamscan (%s): %w", cfg.ClamScanPath, runErr)
	}
	rep.ExitCode = exitCode
	parseClamscanOutput(rep, string(out))
	rep.Warnings = append(rep.Warnings, warnings...)
	rep.EndedAt = time.Now()
	return rep, nil
}

// mergeReport folds an extra pass (e.g. protected cookie files) into rep.
func mergeReport(rep, extra *Report) {
	rep.ScannedFiles += extra.ScannedFiles
	rep.Detections = append(rep.Detections, extra.Detections...)
	rep.Infected = len(rep.Detections)
	rep.Errors = append(rep.Errors, extra.Errors...)
	rep.Warnings = append(rep.Warnings, extra.Warnings...)
	rep.Targets = append(rep.Targets, extra.Targets...)
	if extra.ExitCode != 0 && rep.ExitCode == 0 {
		rep.ExitCode = extra.ExitCode
	}
	rep.EndedAt = time.Now()
}

// postProcess quarantines (when asked), saves the report and notifies.
func postProcess(cfg *Config, rep *Report, quarantine, notify bool) {
	if quarantine && len(rep.Detections) > 0 {
		for _, d := range rep.Detections {
			if _, err := QuarantineFile(cfg, d, rep.ID); err != nil {
				rep.Errors = append(rep.Errors, "quarantine failed: "+d.Path+": "+err.Error())
			} else {
				rep.Quarantined = append(rep.Quarantined, d.Path)
			}
		}
	}
	if err := saveReport(cfg, rep); err != nil {
		rep.Errors = append(rep.Errors, "save report: "+err.Error())
	}
	if notify && cfg.NotifyOnDetect && len(rep.Detections) > 0 {
		if err := NotifyDiscord(cfg, rep); err != nil {
			rep.Errors = append(rep.Errors, "notify: "+err.Error())
		}
	}
}

// parseClamscanOutput extracts FOUND lines and the summary block.
func parseClamscanOutput(rep *Report, out string) {
	sc := bufio.NewScanner(strings.NewReader(out))
	sc.Buffer(make([]byte, 1024*1024), 1024*1024)
	for sc.Scan() {
		line := sc.Text()
		if strings.HasSuffix(line, " FOUND") {
			if idx := strings.LastIndex(line, ": "); idx > 0 {
				rep.Detections = append(rep.Detections, Detection{
					Path:      line[:idx],
					Signature: strings.TrimSuffix(line[idx+2:], " FOUND"),
				})
			}
			continue
		}
		if v, ok := summaryValue(line, "Scanned files:"); ok {
			rep.ScannedFiles = v
		}
		if v, ok := summaryValue(line, "Infected files:"); ok {
			rep.Infected = v
		}
		if (strings.Contains(line, "ERROR") && !strings.Contains(line, "Total errors")) ||
			strings.Contains(line, "Can't open file") || strings.HasPrefix(line, "LibClamAV Error") {
			rep.Errors = append(rep.Errors, line)
		}
	}
	if rep.Infected == 0 {
		rep.Infected = len(rep.Detections)
	}
}

func summaryValue(line, key string) (int, bool) {
	if !strings.HasPrefix(line, key) {
		return 0, false
	}
	n, err := strconv.Atoi(strings.TrimSpace(strings.TrimPrefix(line, key)))
	return n, err == nil
}

func saveReport(cfg *Config, rep *Report) error {
	if err := cfg.ensureDirs(); err != nil {
		return err
	}
	data, err := json.MarshalIndent(rep, "", "  ")
	if err != nil {
		return err
	}
	name := "scan-" + rep.ID + ".json"
	if err := os.WriteFile(filepath.Join(cfg.reportsDir(), name), data, 0o644); err != nil {
		return err
	}
	if cfg.MirrorDir != "" {
		if err := os.MkdirAll(cfg.MirrorDir, 0o755); err == nil {
			_ = os.WriteFile(filepath.Join(cfg.MirrorDir, name), data, 0o644)
			_ = os.WriteFile(filepath.Join(cfg.MirrorDir, "latest.json"), data, 0o644)
		}
	}
	return nil
}

// runUpdate executes freshclam.
func runUpdate(cfg *Config) (string, error) {
	args := []string{}
	if cfg.FreshClamConf != "" {
		args = append(args, "--config-file="+cfg.FreshClamConf)
	}
	if cfg.DatabaseDir != "" {
		args = append(args, "--datadir="+cfg.DatabaseDir)
	}
	cmd := exec.Command(cfg.FreshClamPath, args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return string(out), fmt.Errorf("freshclam failed: %w", err)
	}
	return string(out), nil
}
