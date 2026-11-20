//go:build !windows

package main

import (
	"os"
	"syscall"
)

// pidAlive reports whether a process with this PID currently exists.
func pidAlive(pid int) bool {
	if pid <= 0 {
		return false
	}
	p, err := os.FindProcess(pid)
	if err != nil {
		return false
	}
	return p.Signal(syscall.Signal(0)) == nil
}
