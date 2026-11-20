//go:build !windows

package main

import (
	"time"
)

// startDirWatcher is the non-Windows fallback (development/tests): it polls
// the roots every 5 seconds and emits files whose size/mtime changed.
func startDirWatcher(roots []string, out chan<- string) (func(), error) {
	done := make(chan struct{})
	cfg := &Config{}
	prev := &History{Files: map[string]FileState{}}
	for _, r := range roots {
		for p, st := range collectCurrent(cfg, []string{r}, nil) {
			prev.Files[p] = st
		}
	}
	go func() {
		t := time.NewTicker(5 * time.Second)
		defer t.Stop()
		for {
			select {
			case <-done:
				return
			case <-t.C:
				cur := map[string]FileState{}
				for _, r := range roots {
					for p, st := range collectCurrent(cfg, []string{r}, nil) {
						cur[p] = st
					}
				}
				for _, p := range ChangedFiles(prev, cur) {
					select {
					case out <- p:
					default:
					}
				}
				prev.Files = cur
			}
		}
	}()
	return func() { close(done) }, nil
}
