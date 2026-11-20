//go:build !windows

package main

func installTasks(cfg *Config, cfgPath string, system bool) error { return errWindowsOnly }
func uninstallTasks() error                                       { return errWindowsOnly }
