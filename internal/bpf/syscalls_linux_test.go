// SPDX-License-Identifier: GPL-2.0-only
//go:build linux

package bpf

import (
	"golang.org/x/sys/unix"
	"testing"
)

func TestNativeSyscallNames(t *testing.T) {
	for _, test := range []struct {
		number uint32
		name   string
	}{
		{unix.SYS_READ, "read"}, {unix.SYS_WRITE, "write"},
		{unix.SYS_CONNECT, "connect"}, {unix.SYS_OPENAT, "openat"},
		{unix.SYS_FUTEX, "futex"},
	} {
		if got := SyscallName(test.number); got != test.name {
			t.Errorf("native syscall %d: got %q, want %q", test.number, got, test.name)
		}
	}
}
