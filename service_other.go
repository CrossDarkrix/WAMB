//go:build !windows

package main

import "fmt"

var errWindowsOnly = fmt.Errorf("service management is Windows-only")

func isWindowsService() bool         { return false }
func runWindowsService(string) error { return errWindowsOnly }
func installService(string) error    { return errWindowsOnly }
func uninstallService() error        { return errWindowsOnly }
func startService() error            { return errWindowsOnly }
func stopService() error             { return errWindowsOnly }
func statusService() (string, error) { return "", errWindowsOnly }
