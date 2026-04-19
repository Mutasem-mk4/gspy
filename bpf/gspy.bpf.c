// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2024 Mutasem Kharma <mutasem@gspy.dev>

// gspy — eBPF programs for forensic goroutine-to-syscall inspection.
//
// This file implements four BPF programs:
//   1. tp_sys_enter:             tracepoint/raw_syscalls/sys_enter — records syscall entry
//   2. tp_sys_exit:              tracepoint/raw_syscalls/sys_exit  — computes latency, emits event
//   3. uprobe_runtime_execute:   uprobe on runtime.execute         — maps TID→GID
//   4. uprobe_runtime_newproc1:  uprobe on runtime.newproc1        — goroutine creation
//   5. uprobe_runtime_goexit1:   uprobe on runtime.goexit1         — goroutine exit
//
// CO-RE: uses vmlinux.h, BPF_CORE_READ. No linux-headers required at runtime.
// All loops have explicit upper bounds. Target instruction count < 200 per program.

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

// ---------------------------------------------------------------------------
// Constants set at load time from userspace via spec.RewriteConstants
// ---------------------------------------------------------------------------
volatile const __u32 target_pid = 0;
volatile const __u64 gid_offset = 152; // default for Go 1.17–1.23 amd64

// ---------------------------------------------------------------------------
// Event types
// ---------------------------------------------------------------------------
#define EVENT_SYSCALL           0
#define EVENT_GOROUTINE_CREATE  1
#define EVENT_GOROUTINE_EXIT    2

// ---------------------------------------------------------------------------
// Goroutine states (mirror internal/bpf/types.go)
// ---------------------------------------------------------------------------
#define GSTATE_CREATED  0
#define GSTATE_RUNNING  1
#define GSTATE_SYSCALL  2
#define GSTATE_WAITING  3
#define GSTATE_DEAD     4

// ---------------------------------------------------------------------------
// Struct definitions — layouts MUST match Go types in types.go exactly
// ---------------------------------------------------------------------------

// goroutine_meta: per-goroutine metadata stored in BPF hash map.
// sizeof = 24 bytes (8+4+4+8) with natural alignment, no padding issues.
struct goroutine_meta {
	__u64 gid;
	__u32 state;     // GSTATE_*
	__u32 pad;
	__u64 frame_ptr; // SP at last context switch (best-effort)
};

// syscall_event: emitted to ring buffer on each syscall exit.
// sizeof = 48 bytes (8+4+4+8+4+4+8+8) with natural alignment.
struct syscall_event {
	__u64 ts;         // ktime_ns timestamp
	__u32 pid;
	__u32 tid;
	__u64 gid;        // goroutine ID (0 if unmapped)
	__u32 syscall_nr;
	__u32 event_type; // EVENT_*
	__u64 latency_ns; // time blocked in syscall (sys_exit - sys_enter)
	__u64 frame_pc;   // top user-space stack frame PC (0 if unavailable)
};

// Force BTF emission for the syscall_event struct which is only used over ringbuf
const struct syscall_event *__unused_syscall_event __attribute__((unused));

// syscall_enter_info: per-thread scratch for latency calculation.
// sizeof = 24 bytes.
struct syscall_enter_info {
	__u64 ts;
	__u32 syscall_nr;
	__u32 pad;
	__u64 frame_pc;
};

// ---------------------------------------------------------------------------
// BPF Maps — all pre-allocated with explicit max_entries
// ---------------------------------------------------------------------------

// gid_by_tid: maps kernel TID → goroutine ID.
// Updated on every goroutine context switch (runtime.execute).
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 65536);
	__type(key, __u32);   // TID
	__type(value, __u64); // GID
} gid_by_tid SEC(".maps");

// goroutine_meta_map: per-goroutine state and frame pointer.
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 65536);
	__type(key, __u64);                  // GID
	__type(value, struct goroutine_meta);
} goroutine_meta_map SEC(".maps");

// syscall_enter: per-thread scratch for in-flight syscall tracking.
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 65536);
	__type(key, __u32);                     // TID
	__type(value, struct syscall_enter_info);
} syscall_enter SEC(".maps");

// events: ring buffer for all events sent to userspace.
// 16 MB allows ~333K events before wrap (48 bytes each).
struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 16 * 1024 * 1024);
} events SEC(".maps");

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// is_target_process returns true if current task belongs to target PID.
static __always_inline int is_target_process(void)
{
	__u64 pid_tgid = bpf_get_current_pid_tgid();
	__u32 pid = pid_tgid >> 32;
	return pid == target_pid;
}

// get_current_tid returns the kernel thread ID of the current task.
static __always_inline __u32 get_current_tid(void)
{
	return (__u32)bpf_get_current_pid_tgid();
}

// ---------------------------------------------------------------------------
// Program 1: tracepoint/raw_syscalls/sys_enter
// Records syscall entry timestamp, number, and top user-space stack frame.
// ---------------------------------------------------------------------------
SEC("tracepoint/raw_syscalls/sys_enter")
int tp_sys_enter(struct trace_event_raw_sys_enter *ctx)
{
	if (!is_target_process())
		return 0;

	__u32 tid = get_current_tid();

	struct syscall_enter_info info = {};
	info.ts = bpf_ktime_get_ns();
	info.syscall_nr = (__u32)ctx->id;

	// Capture top user-space stack frame for symbol resolution.
	// bpf_get_stack with BPF_F_USER_STACK returns the userspace call chain
	// at syscall entry — this is the goroutine's actual execution context.
	__u64 ustack[4];
	int ret = bpf_get_stack(ctx, ustack, sizeof(ustack), BPF_F_USER_STACK);
	if (ret > 0) {
		info.frame_pc = ustack[0];
	}

	bpf_map_update_elem(&syscall_enter, &tid, &info, BPF_ANY);
	return 0;
}

// ---------------------------------------------------------------------------
// Program 2: tracepoint/raw_syscalls/sys_exit
// Computes latency, looks up GID from gid_by_tid map, emits event to ring buffer.
// ---------------------------------------------------------------------------
SEC("tracepoint/raw_syscalls/sys_exit")
int tp_sys_exit(struct trace_event_raw_sys_exit *ctx)
{
	if (!is_target_process())
		return 0;

	__u32 tid = get_current_tid();

	// Look up the matching sys_enter record
	struct syscall_enter_info *enter = bpf_map_lookup_elem(&syscall_enter, &tid);
	if (!enter)
		return 0;

	__u64 now = bpf_ktime_get_ns();
	__u64 latency = now - enter->ts;
	__u32 syscall_nr = enter->syscall_nr;
	__u64 frame_pc = enter->frame_pc;

	// Look up goroutine ID for this thread
	__u64 *gid_ptr = bpf_map_lookup_elem(&gid_by_tid, &tid);
	__u64 gid = gid_ptr ? *gid_ptr : 0;

	// Reserve space in ring buffer and emit event
	struct syscall_event *evt = bpf_ringbuf_reserve(&events, sizeof(*evt), 0);
	if (!evt) {
		bpf_map_delete_elem(&syscall_enter, &tid);
		return 0;
	}

	evt->ts = now;
	evt->pid = target_pid;
	evt->tid = tid;
	evt->gid = gid;
	evt->syscall_nr = syscall_nr;
	evt->event_type = EVENT_SYSCALL;
	evt->latency_ns = latency;
	evt->frame_pc = frame_pc;

	bpf_ringbuf_submit(evt, 0);

	// Update goroutine metadata state to "in syscall"
	if (gid_ptr) {
		struct goroutine_meta *meta = bpf_map_lookup_elem(
			&goroutine_meta_map, gid_ptr);
		if (meta) {
			meta->state = GSTATE_SYSCALL;
		}
	}

	bpf_map_delete_elem(&syscall_enter, &tid);
	return 0;
}

// ---------------------------------------------------------------------------
// Program 3: uprobe/runtime.execute
// Fires on every goroutine context switch in the Go runtime.
// Reads the goroutine pointer (gp *g) from RAX (Go 1.17+ ABIInternal on amd64),
// then reads goid at gid_offset within the g struct via bpf_probe_read_user.
// Writes (TID → GID) into gid_by_tid and updates goroutine_meta_map.
//
// Go ABI note:
//   Go 1.17+ uses ABIInternal on amd64 where the first integer argument
//   is passed in RAX. runtime.execute(gp *g, inheritTime bool) receives
//   gp in RAX.
//   Reference: https://go.dev/src/cmd/compile/abi-internal.md
// ---------------------------------------------------------------------------
SEC("uprobe/runtime.execute")
int uprobe_runtime_execute(struct pt_regs *ctx)
{
	if (!is_target_process())
		return 0;

	__u32 tid = get_current_tid();

	// Go ABIInternal (1.17+ amd64): first argument (gp *g) is in RAX.
	//
	// We cannot use PT_REGS_PARM1 (which reads rdi for C ABI/arm64 C ABI). Go's
	// internal ABI passes the first argument in rax (amd64) or x0 (arm64). Use
	// BPF_CORE_READ for CO-RE safe access to the registers.
#if defined(__TARGET_ARCH_x86)
	__u64 gp_ptr = BPF_CORE_READ(ctx, ax);
#elif defined(__TARGET_ARCH_arm64)
	__u64 gp_ptr = BPF_CORE_READ(ctx, regs[0]);
#else
	__u64 gp_ptr = 0;
#endif

	if (gp_ptr == 0)
		return 0;

	// Read goid from runtime.g struct at the configured offset.
	// gid_offset is set at load time from userspace after ELF/DWARF detection.
	__u64 gid = 0;
	int ret = bpf_probe_read_user(&gid, sizeof(gid),
				       (void *)(gp_ptr + gid_offset));
	if (ret < 0 || gid == 0)
		return 0;

	// Update TID → GID mapping
	bpf_map_update_elem(&gid_by_tid, &tid, &gid, BPF_ANY);

	// Update goroutine metadata
	struct goroutine_meta meta = {};
	meta.gid = gid;
	meta.state = GSTATE_RUNNING;
	// Store SP from pt_regs as best-effort frame pointer for stack walking.
	// This is the kernel thread's SP at uprobe entry, not the goroutine's
	// user stack, but provides context for process_vm_readv stack walking.
	meta.frame_ptr = BPF_CORE_READ(ctx, sp);

	bpf_map_update_elem(&goroutine_meta_map, &gid, &meta, BPF_ANY);

	return 0;
}

// ---------------------------------------------------------------------------
// Program 4: uprobe/runtime.newproc1
// Fires when a new goroutine is created.
// Emits a goroutine_created event with the parent goroutine's GID.
// The new goroutine's GID will be captured when runtime.execute runs for it.
// ---------------------------------------------------------------------------
SEC("uprobe/runtime.newproc1")
int uprobe_runtime_newproc1(struct pt_regs *ctx)
{
	if (!is_target_process())
		return 0;

	__u32 tid = get_current_tid();

	// Look up current (parent) goroutine ID
	__u64 *gid_ptr = bpf_map_lookup_elem(&gid_by_tid, &tid);
	__u64 parent_gid = gid_ptr ? *gid_ptr : 0;

	struct syscall_event *evt = bpf_ringbuf_reserve(&events, sizeof(*evt), 0);
	if (!evt)
		return 0;

	evt->ts = bpf_ktime_get_ns();
	evt->pid = target_pid;
	evt->tid = tid;
	evt->gid = parent_gid;
	evt->syscall_nr = 0;
	evt->event_type = EVENT_GOROUTINE_CREATE;
	evt->latency_ns = 0;
	evt->frame_pc = 0;

	bpf_ringbuf_submit(evt, 0);

	return 0;
}

// ---------------------------------------------------------------------------
// Program 5: uprobe/runtime.goexit1
// Fires when a goroutine exits. Marks it as dead in goroutine_meta_map
// and emits a goroutine_exit event.
// ---------------------------------------------------------------------------
SEC("uprobe/runtime.goexit1")
int uprobe_runtime_goexit1(struct pt_regs *ctx)
{
	if (!is_target_process())
		return 0;

	__u32 tid = get_current_tid();

	__u64 *gid_ptr = bpf_map_lookup_elem(&gid_by_tid, &tid);
	if (!gid_ptr)
		return 0;

	__u64 gid = *gid_ptr;

	// Mark goroutine as dead
	struct goroutine_meta *meta = bpf_map_lookup_elem(
		&goroutine_meta_map, &gid);
	if (meta) {
		meta->state = GSTATE_DEAD;
	}

	// Emit exit event
	struct syscall_event *evt = bpf_ringbuf_reserve(&events, sizeof(*evt), 0);
	if (!evt)
		return 0;

	evt->ts = bpf_ktime_get_ns();
	evt->pid = target_pid;
	evt->tid = tid;
	evt->gid = gid;
	evt->syscall_nr = 0;
	evt->event_type = EVENT_GOROUTINE_EXIT;
	evt->latency_ns = 0;
	evt->frame_pc = 0;

	bpf_ringbuf_submit(evt, 0);

	return 0;
}

char LICENSE[] SEC("license") = "GPL";
