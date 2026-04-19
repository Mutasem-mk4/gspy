// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2024 Mutasem Kharma <mutasem@gspy.dev>

// Package bpf provides the BPF program manager interface and shared types
// for goroutine-to-syscall event tracing. Types in this file correspond
// exactly to the C structs in gspy.bpf.c — layout and alignment must be
// kept in sync at all times.
package bpf

import "context"

// ---------------------------------------------------------------------------
// Event types — must match #define EVENT_* in gspy.bpf.c
// ---------------------------------------------------------------------------
const (
	EventSyscall         uint32 = 0
	EventGoroutineCreate uint32 = 1
	EventGoroutineExit   uint32 = 2
)

// ---------------------------------------------------------------------------
// Goroutine states — must match #define GSTATE_* in gspy.bpf.c
// ---------------------------------------------------------------------------
const (
	GStateCreated uint32 = 0
	GStateRunning uint32 = 1
	GStateSyscall uint32 = 2
	GStateWaiting uint32 = 3
	GStateDead    uint32 = 4
)

// GoroutineMeta matches struct goroutine_meta in gspy.bpf.c.
// sizeof = 24 bytes (8+4+4+8), naturally aligned.
type GoroutineMeta struct {
	GID      uint64
	State    uint32
	Pad      uint32
	FramePtr uint64
}

// SyscallEvent matches struct syscall_event in gspy.bpf.c.
// sizeof = 48 bytes (8+4+4+8+4+4+8+8), naturally aligned.
type SyscallEvent struct {
	Ts        uint64
	Pid       uint32
	Tid       uint32
	Gid       uint64
	SyscallNr uint32
	EventType uint32
	LatencyNs uint64
	FramePC   uint64
}

// Manager defines the interface for BPF program lifecycle management.
// The real implementation (loader.go) uses cilium/ebpf on Linux.
// The mock implementation (mock.go) is used for testing and non-Linux builds.
type Manager interface {
	// LoadAndAttach loads BPF programs and attaches to the target process.
	// pid is the target process PID.
	// binaryPath is the resolved path to the target Go binary.
	// gidOffset is the byte offset of the goid field in runtime.g.
	LoadAndAttach(pid int, binaryPath string, gidOffset uint64) error

	// PollEvents reads events from the BPF ring buffer in a blocking loop.
	// Calls handler for each event. Returns when ctx is cancelled or on error.
	PollEvents(ctx context.Context, handler func(SyscallEvent)) error

	// GetGoroutineMeta reads goroutine metadata from the BPF goroutine_meta_map.
	// Returns nil, false if the goroutine is not tracked.
	GetGoroutineMeta(gid uint64) (*GoroutineMeta, bool)

	// Close detaches all BPF programs, closes maps and ring buffer readers.
	Close() error

	// DebugInfo returns BPF verifier log and map statistics for --debug mode.
	DebugInfo() string
}

// StateString converts a goroutine state constant to a human-readable string.
func StateString(state uint32) string {
	switch state {
	case GStateCreated:
		return "created"
	case GStateRunning:
		return "running"
	case GStateSyscall:
		return "syscall"
	case GStateWaiting:
		return "waiting"
	case GStateDead:
		return "dead"
	default:
		return "unknown"
	}
}

// SyscallNames maps amd64 Linux syscall numbers to human-readable names.
// Reference: arch/x86/entry/syscalls/syscall_64.tbl in the Linux kernel.
var SyscallNames = map[uint32]string{
	0: "read", 1: "write", 2: "open", 3: "close",
	4: "stat", 5: "fstat", 6: "lstat", 7: "poll",
	8: "lseek", 9: "mmap", 10: "mprotect", 11: "munmap",
	12: "brk", 13: "rt_sigaction", 14: "rt_sigprocmask",
	15: "rt_sigreturn", 16: "ioctl", 17: "pread64",
	18: "pwrite64", 19: "readv", 20: "writev",
	21: "access", 22: "pipe", 23: "select",
	24: "sched_yield", 25: "mremap", 26: "msync",
	27: "mincore", 28: "madvise", 29: "shmget",
	30: "shmat", 31: "shmctl", 32: "dup",
	33: "dup2", 34: "pause", 35: "nanosleep",
	36: "getitimer", 37: "alarm", 38: "setitimer",
	39: "getpid", 40: "sendfile", 41: "socket",
	42: "connect", 43: "accept", 44: "sendto",
	45: "recvfrom", 46: "sendmsg", 47: "recvmsg",
	48: "shutdown", 49: "bind", 50: "listen",
	51: "getsockname", 52: "getpeername", 53: "socketpair",
	54: "setsockopt", 55: "getsockopt", 56: "clone",
	57: "fork", 58: "vfork", 59: "execve",
	60: "exit", 61: "wait4", 62: "kill",
	63: "uname", 64: "semget", 65: "semop",
	66: "semctl", 67: "shmdt", 68: "msgget",
	69: "msgsnd", 70: "msgrcv", 71: "msgctl",
	72: "fcntl", 73: "flock", 74: "fsync",
	75: "fdatasync", 76: "truncate", 77: "ftruncate",
	78: "getdents", 79: "getcwd", 80: "chdir",
	81: "fchdir", 82: "rename", 83: "mkdir",
	84: "rmdir", 85: "creat", 86: "link",
	87: "unlink", 88: "symlink", 89: "readlink",
	90: "chmod", 91: "fchmod", 92: "chown",
	93: "fchown", 94: "lchown", 95: "umask",
	96: "gettimeofday", 97: "getrlimit", 98: "getrusage",
	99: "sysinfo", 100: "times", 101: "ptrace",
	102: "getuid", 103: "syslog", 104: "getgid",
	105: "setuid", 106: "setgid", 107: "geteuid",
	108: "getegid", 109: "setpgid", 110: "getppid",
	111: "getpgrp", 112: "setsid", 113: "setreuid",
	114: "setregid", 115: "getgroups", 116: "setgroups",
	117: "setresuid", 118: "getresuid", 119: "setresgid",
	120: "getresgid", 121: "getpgid", 122: "setfsuid",
	123: "setfsgid", 124: "getsid", 125: "capget",
	126: "capset", 127: "rt_sigpending", 128: "rt_sigtimedwait",
	129: "rt_sigqueueinfo", 130: "rt_sigsuspend",
	131: "sigaltstack", 132: "utime", 133: "mknod",
	135: "personality", 136: "ustat", 137: "statfs",
	138: "fstatfs", 139: "sysfs", 140: "getpriority",
	141: "setpriority", 142: "sched_setparam",
	143: "sched_getparam", 144: "sched_setscheduler",
	145: "sched_getscheduler", 146: "sched_get_priority_max",
	147: "sched_get_priority_min", 148: "sched_rr_get_interval",
	149: "mlock", 150: "munlock", 151: "mlockall",
	152: "munlockall", 153: "vhangup", 157: "prctl",
	158: "arch_prctl", 186: "gettid",
	200: "tkill", 202: "futex",
	203: "sched_setaffinity", 204: "sched_getaffinity",
	217: "getdents64", 218: "set_tid_address",
	228: "clock_gettime", 229: "clock_getres",
	230: "clock_nanosleep", 231: "exit_group",
	232: "epoll_wait", 233: "epoll_ctl",
	234: "tgkill", 235: "utimes",
	257: "openat", 258: "mkdirat",
	262: "newfstatat", 263: "unlinkat",
	264: "renameat", 268: "fchmodat",
	269: "faccessat", 270: "pselect6",
	271: "ppoll", 280: "utimensat",
	281: "epoll_pwait", 282: "signalfd",
	283: "timerfd_create", 284: "eventfd",
	285: "fallocate", 286: "timerfd_settime",
	287: "timerfd_gettime", 288: "accept4",
	289: "signalfd4", 290: "eventfd2",
	291: "epoll_create1", 292: "dup3",
	293: "pipe2", 294: "inotify_init1",
	295: "preadv", 296: "pwritev",
	302: "prlimit64", 306: "syncfs",
	318: "getrandom", 319: "memfd_create",
	332: "statx",
}

// SyscallName returns the name for a syscall number, or "syscall_NNN" if unknown.
func SyscallName(nr uint32) string {
	if name, ok := SyscallNames[nr]; ok {
		return name
	}
	return "syscall_" + uitoa(nr)
}

// uitoa converts a uint32 to its decimal string representation.
func uitoa(n uint32) string {
	if n == 0 {
		return "0"
	}
	var buf [10]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	return string(buf[i:])
}

// IOSyscalls is the set of syscall names classified as I/O operations.
var IOSyscalls = map[string]bool{
	"read": true, "write": true, "open": true, "close": true,
	"openat": true, "pread64": true, "pwrite64": true,
	"readv": true, "writev": true, "lseek": true,
	"stat": true, "fstat": true, "lstat": true,
	"fsync": true, "fdatasync": true, "truncate": true,
	"ftruncate": true, "getdents": true, "getdents64": true,
	"rename": true, "renameat": true, "mkdir": true,
	"mkdirat": true, "rmdir": true, "creat": true,
	"link": true, "unlink": true, "unlinkat": true,
	"symlink": true, "readlink": true, "chmod": true,
	"fchmod": true, "fchmodat": true, "chown": true,
	"fchown": true, "statx": true, "newfstatat": true,
	"preadv": true, "pwritev": true, "fallocate": true,
	"syncfs": true,
}

// NetSyscalls is the set of syscall names classified as network operations.
var NetSyscalls = map[string]bool{
	"socket": true, "bind": true, "listen": true,
	"accept": true, "accept4": true, "connect": true,
	"sendto": true, "recvfrom": true, "sendmsg": true,
	"recvmsg": true, "shutdown": true, "getsockname": true,
	"getpeername": true, "socketpair": true,
	"setsockopt": true, "getsockopt": true,
	"epoll_wait": true, "epoll_pwait": true,
	"epoll_ctl": true, "epoll_create1": true,
	"sendfile": true, "poll": true, "ppoll": true,
	"pselect6": true, "select": true,
}

// SchedSyscalls is the set of syscall names classified as scheduling operations.
var SchedSyscalls = map[string]bool{
	"sched_yield": true, "clone": true, "futex": true,
	"nanosleep": true, "clock_nanosleep": true,
	"sched_setaffinity": true, "sched_getaffinity": true,
	"sched_setparam": true, "sched_getparam": true,
	"sched_setscheduler": true, "sched_getscheduler": true,
	"sched_get_priority_max": true, "sched_get_priority_min": true,
	"sched_rr_get_interval": true, "wait4": true,
	"exit": true, "exit_group": true, "pause": true,
}
