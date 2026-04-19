// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2024 Mutasem Kharma <mutasem@gspy.dev>

//go:build linux

// Package proc provides the Linux-specific process_vm_readv implementation.
package proc

import (
	"fmt"
	"unsafe"

	"golang.org/x/sys/unix"
)

// ProcessVMReadv reads memory from a remote process using the
// process_vm_readv(2) system call. This is the ONLY mechanism used
// by gspy to read target process memory.
//
// FORENSIC GUARANTEE: process_vm_readv is a read-only system call.
// It cannot modify the target process's memory, address space,
// registers, or file descriptors. There is no write counterpart
// used by gspy.
//
// See: man 2 process_vm_readv
func ProcessVMReadv(pid int, addr uintptr, size int) ([]byte, error) {
	buf := make([]byte, size)

	localIov := unix.Iovec{
		Base: &buf[0],
		Len:  uint64(size),
	}

	remoteIov := unix.RemoteIovec{
		Base: addr,
		Len:  size,
	}

	n, err := unix.ProcessVMReadv(
		pid,
		[]unix.Iovec{localIov},
		[]unix.RemoteIovec{remoteIov},
		0,
	)
	if err != nil {
		return nil, fmt.Errorf("process_vm_readv(pid=%d, addr=0x%x, size=%d): %w",
			pid, addr, size, err)
	}

	if n != size {
		return buf[:n], fmt.Errorf(
			"process_vm_readv: short read %d/%d bytes at 0x%x",
			n, size, addr)
	}

	return buf, nil
}

// NewLinuxReadFunc returns a ReadFunc backed by process_vm_readv(2).
// This is the production memory reader used on Linux.
func NewLinuxReadFunc() ReadFunc {
	return func(pid int, addr uintptr, size int) ([]byte, error) {
		return ProcessVMReadv(pid, addr, size)
	}
}

// ReadPointer reads a single 64-bit pointer from the target process.
func ReadPointer(pid int, addr uintptr) (uint64, error) {
	buf, err := ProcessVMReadv(pid, addr, 8)
	if err != nil {
		return 0, err
	}
	return *(*uint64)(unsafe.Pointer(&buf[0])), nil
}
