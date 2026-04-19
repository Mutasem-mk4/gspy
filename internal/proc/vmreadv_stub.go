// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2024 Mutasem Kharma <mutasem@gspy.dev>

//go:build !linux

// Package proc stub for non-Linux platforms.
package proc

import (
	"fmt"
	"runtime"
)

// ProcessVMReadv is not available on non-Linux platforms.
func ProcessVMReadv(pid int, addr uintptr, size int) ([]byte, error) {
	return nil, fmt.Errorf("process_vm_readv not available on %s", runtime.GOOS)
}

// NewLinuxReadFunc returns a ReadFunc that always errors on non-Linux.
func NewLinuxReadFunc() ReadFunc {
	return func(pid int, addr uintptr, size int) ([]byte, error) {
		return nil, fmt.Errorf("process_vm_readv not available on %s", runtime.GOOS)
	}
}

// ReadPointer is not available on non-Linux platforms.
func ReadPointer(pid int, addr uintptr) (uint64, error) {
	return 0, fmt.Errorf("process_vm_readv not available on %s", runtime.GOOS)
}
