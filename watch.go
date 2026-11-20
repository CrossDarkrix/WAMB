package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"sort"
	"strings"
	"sync"
	"time"
)

// logf is the package logger: console by default, redirected to a file when
// running as a service (see serve.go).
var logf = func(format string, args ...any) {
	fmt.Printf(format, args...)
}

// runWatch is the lightweight real-time scan: it watches the target folders
// (plus the protected browser stores, always) and scans only the files that
// changed, after a short quiet period (debounce).
func runWatch(cfg *Config) error {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	return watchLoop(cfg, ctx)
}

func watchLoop(cfg *Config, ctx context.Context) error {
	protected := effectiveProtected()
	rootSet := map[string]bool{}
	var roots []string
	addRoot := func(p string) {
		if p == "" || rootSet[p] {
			return
		}
		if st, err := os.Stat(p); err == nil && st.IsDir() {
			rootSet[p] = true
			roots = append(roots, p)
		}
	}
	for _, t := range cfg.effectiveTargets() {
		addRoot(t)
	}
	for _, p := range protected {
		addRoot(p)
	}
	if len(roots) == 0 {
		return fmt.Errorf("no existing folders to watch")
	}

	events := make(chan string, 4096)
	stop, err := startDirWatcher(roots, events)
	if err != nil {
		return err
	}
	defer stop()

	logf("WAMB watch: monitoring %d folder(s); debounce %ds.\n", len(roots), cfg.WatchDebounceSec)
	for _, r := range roots {
		logf("  - %s\n", r)
	}

	var mu sync.Mutex
	pending := map[string]bool{}
	go func() {
		for p := range events {
			if skipWatchPath(cfg, p, protected) {
				continue
			}
			mu.Lock()
			pending[p] = true
			mu.Unlock()
		}
	}()

	debounce := time.Duration(cfg.WatchDebounceSec) * time.Second
	if debounce <= 0 {
		debounce = 3 * time.Second
	}
	tick := time.NewTicker(500 * time.Millisecond)
	defer tick.Stop()
	var lastEvent time.Time
	for {
		select {
		case <-ctx.Done():
			logf("WAMB watch: stopped.\n")
			return nil
		case <-tick.C:
			mu.Lock()
			n := len(pending)
			mu.Unlock()
			if n == 0 {
				lastEvent = time.Time{}
				continue
			}
			if lastEvent.IsZero() {
				lastEvent = time.Now()
				continue
			}
			if time.Since(lastEvent) < debounce {
				continue
			}
			mu.Lock()
			files := make([]string, 0, len(pending))
			for p := range pending {
				if st, err := os.Stat(p); err == nil && !st.IsDir() {
					files = append(files, p)
				}
			}
			pending = map[string]bool{}
			mu.Unlock()
			lastEvent = time.Time{}
			if len(files) == 0 {
				continue
			}
			sort.Strings(files)
			rep, err := executeScan(cfg, scanOptions{FileList: files, Mode: "watch"})
			if err != nil {
				logf("watch scan error: %v\n", err)
				continue
			}
			postProcess(cfg, rep, cfg.WatchQuarantine, true)
			logf("[%s] watch scan: %d file(s), %d detection(s)\n",
				time.Now().Format("15:04:05"), rep.ScannedFiles, len(rep.Detections))
			for _, d := range rep.Detections {
				logf("  FOUND %s (%s)\n", d.Path, d.Signature)
			}
		}
	}
}

// skipWatchPath filters out WAMB's own working files and excluded paths.
func skipWatchPath(cfg *Config, p string, protected []string) bool {
	for _, base := range []string{cfg.BaseDir, cfg.QuarantineDir, cfg.MirrorDir} {
		if base != "" {
			nb, np := normPath(base), normPath(p)
			if np == nb || strings.HasPrefix(np, nb+"/") {
				return true
			}
		}
	}
	return cfg.IsExcludedFile(p, protected)
}
