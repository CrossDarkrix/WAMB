//go:build windows

package main

import (
	"fmt"
	"path/filepath"
	"syscall"
	"unsafe"
)

var (
	kernel32                 = syscall.NewLazyDLL("kernel32.dll")
	procReadDirectoryChanges = kernel32.NewProc("ReadDirectoryChangesW")
)

const (
	fileListDirectory       = 0x0001
	fileShareAll            = 0x0001 | 0x0002 | 0x0004
	openExisting            = 3
	fileFlagBackupSemantics = 0x02000000
	notifyFilter            = 0x0001 | 0x0002 | 0x0004 | 0x0008 | 0x0010 // name|attr|size|last-write
	actionAdded             = 0x00000001
	actionModified          = 0x00000003
	actionRenamedNew        = 0x00000005
)

// startDirWatcher emits changed file paths for every root (subtrees
// included) using ReadDirectoryChangesW — event-driven, no polling.
func startDirWatcher(roots []string, out chan<- string) (func(), error) {
	done := make(chan struct{})
	for _, root := range roots {
		go watchRoot(root, out, done)
	}
	return func() { close(done) }, nil
}

func watchRoot(root string, out chan<- string, done chan struct{}) {
	pathPtr, err := syscall.UTF16PtrFromString(root)
	if err != nil {
		return
	}
	h, err := syscall.CreateFile(pathPtr, fileListDirectory, fileShareAll, nil, openExisting, fileFlagBackupSemantics, 0)
	if err != nil {
		fmt.Println("watch: cannot open", root, ":", err)
		return
	}
	defer syscall.CloseHandle(h)
	buf := make([]byte, 64*1024)
	for {
		select {
		case <-done:
			return
		default:
		}
		var returned uint32
		r, _, _ := procReadDirectoryChanges.Call(
			uintptr(h),
			uintptr(unsafe.Pointer(&buf[0])),
			uintptr(len(buf)),
			1, // watch subtree
			uintptr(notifyFilter),
			uintptr(unsafe.Pointer(&returned)),
			0, 0,
		)
		if r == 0 || returned == 0 {
			continue
		}
		offset := 0
		for {
			rec := buf[offset:]
			next := uint32(rec[0]) | uint32(rec[1])<<8 | uint32(rec[2])<<16 | uint32(rec[3])<<24
			action := uint32(rec[4]) | uint32(rec[5])<<8 | uint32(rec[6])<<16 | uint32(rec[7])<<24
			nameLen := int(uint32(rec[8]) | uint32(rec[9])<<8 | uint32(rec[10])<<16 | uint32(rec[11])<<24)
			if nameLen > 0 && 12+nameLen <= len(rec) {
				u16 := make([]uint16, nameLen/2)
				for i := range u16 {
					u16[i] = uint16(rec[12+2*i]) | uint16(rec[12+2*i+1])<<8
				}
				name := syscall.UTF16ToString(u16)
				if action == actionAdded || action == actionModified || action == actionRenamedNew {
					select {
					case out <- filepath.Join(root, name):
					default: // never block the watcher on a full queue
					}
				}
			}
			if next == 0 {
				break
			}
			offset += int(next)
			if offset >= int(returned) {
				break
			}
		}
	}
}
