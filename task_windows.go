//go:build windows

package main

import (
	"fmt"
	"os/exec"
)

// installTasks registers the insurance jobs in Task Scheduler: the same
// daily update and scan the service runs itself, so they still fire if the
// service is stopped. system=true registers them as SYSTEM (needs admin);
// system=false registers them for the current user.
func installTasks(cfg *Config, cfgPath string, system bool) error {
	exe, err := exePath()
	if err != nil {
		return err
	}
	jobs := []struct{ name, action, at string }{
		{"WAMB Update", "update", cfg.ScheduleUpdate},
		{"WAMB Scan", "scan", cfg.ScheduleScan},
	}
	for _, j := range jobs {
		tr := fmt.Sprintf(`"%s" %s --config "%s"`, exe, j.action, cfgPath)
		args := []string{"/create", "/tn", j.name, "/sc", "daily", "/st", j.at, "/tr", tr, "/f"}
		if system {
			args = append(args, "/ru", "SYSTEM", "/rl", "highest")
		}
		out, err := exec.Command("schtasks", args...).CombinedOutput()
		if err != nil {
			return fmt.Errorf("schtasks %s: %v (%s)", j.name, err, out)
		}
	}
	return nil
}

func uninstallTasks() error {
	for _, name := range []string{"WAMB Update", "WAMB Scan"} {
		out, err := exec.Command("schtasks", "/delete", "/tn", name, "/f").CombinedOutput()
		if err != nil {
			return fmt.Errorf("schtasks delete %s: %v (%s)", name, err, out)
		}
	}
	return nil
}
