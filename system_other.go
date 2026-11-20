//go:build !windows

package main

// isSystemUser is always false outside Windows (development/tests).
func isSystemUser() bool { return false }
