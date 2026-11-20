//go:build windows

package main

import "syscall"

const processQueryLimitedInformation = 0x1000

// pidAlive reports whether a process with this PID currently exists.
func pidAlive(pid int) bool {
	if pid <= 0 {
		return false
	}
	h, err := syscall.OpenProcess(processQueryLimitedInformation, false, uint32(pid))
	if err != nil {
		return false
	}
	syscall.CloseHandle(h)
	return true
}
