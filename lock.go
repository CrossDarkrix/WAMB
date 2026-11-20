package main

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

// acquireLock takes the single-run lock so the service scheduler and the
// Task Scheduler fallback never scan at the same time. A lock older than
// 6 hours (or with an unreadable body) is treated as stale.
func acquireLock(cfg *Config) (func(), error) {
	if err := cfg.ensureDirs(); err != nil {
		return nil, err
	}
	path := cfg.lockFile()
	try := func() (bool, error) {
		f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o644)
		if err != nil {
			if os.IsExist(err) {
				return false, nil
			}
			return false, err
		}
		fmt.Fprintf(f, "%d %d", os.Getpid(), time.Now().Unix())
		f.Close()
		return true, nil
	}
	ok, err := try()
	if err != nil {
		return nil, err
	}
	if !ok {
		stale := true
		if data, err := os.ReadFile(path); err == nil {
			parts := strings.Fields(string(data))
			if len(parts) == 2 {
				pid, perr := strconv.Atoi(parts[0])
				ts, terr := strconv.ParseInt(parts[1], 10, 64)
				if perr == nil && terr == nil {
					// Stale when the owner is gone, whatever the clock says;
					// the age rule only guards against PID reuse.
					stale = !pidAlive(pid) || time.Since(time.Unix(ts, 0)) > 6*time.Hour
				}
			}
		}
		if !stale {
			return nil, fmt.Errorf("another wamb run is in progress (lock: %s)", path)
		}
		_ = os.Remove(path)
		ok, err = try()
		if err != nil || !ok {
			return nil, fmt.Errorf("could not take the run lock")
		}
	}
	return func() { _ = os.Remove(path) }, nil
}
