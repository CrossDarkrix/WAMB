//go:build windows

package main

import (
	"strings"

	"golang.org/x/sys/windows"
)

// isSystemUser reports whether the process runs as LocalSystem (S-1-5-18),
// which is how the WAMB service runs.
func isSystemUser() bool {
	tok := windows.GetCurrentProcessToken()
	u, err := tok.GetTokenUser()
	if err != nil {
		return false
	}
	return strings.EqualFold(u.User.Sid.String(), "S-1-5-18")
}
