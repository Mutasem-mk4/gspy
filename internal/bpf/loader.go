// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2024 Mutasem Kharma <mutasem@gspy.dev>

//go:build linux && !testing

// This file implements the real BPF Manager using cilium/ebpf.
// It is only compiled on Linux for non-test builds.
// For testing and non-Linux platforms, see mock.go.

package bpf

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -target bpfel -type goroutine_meta -type syscall_event gspy ../../bpf/gspy.bpf.c -- -I/usr/include -I../../bpf -O2 -g

// realManager is the production BPF Manager implementation.
// It loads eBPF programs from compiled bytecode, attaches them to
// tracepoints and uprobes, and polls events from a ring buffer.
type realManager struct {
	objs     *gspyObjects
	links    []link.Link
	reader   *ringbuf.Reader
	debugLog string
}

// NewManager creates a new BPF manager backed by real eBPF.
func NewManager() Manager {
	return &realManager{}
}

// LoadAndAttach loads BPF programs and attaches to the target process.
//
// Sequence:
//  1. Remove memlock rlimit (required for BPF map allocation)
//  2. Load BPF spec from embedded bytecode
//  3. Rewrite constants (target_pid, gid_offset)
//  4. Load BPF objects with verifier logging enabled
//  5. Attach tracepoints for raw_syscalls/sys_enter and sys_exit
//  6. Attach uprobes for runtime.execute, runtime.newproc1, runtime.goexit1
//  7. Open ring buffer reader
func (m *realManager) LoadAndAttach(pid int, binaryPath string, gidOffset uint64) error {
	// Step 1: Remove memlock rlimit for BPF map memory allocation.
	if err := rlimit.RemoveMemlock(); err != nil {
		return fmt.Errorf("removing memlock rlimit: %w", err)
	}

	// Step 2: Load BPF spec from embedded bytecode.
	spec, err := loadGspy()
	if err != nil {
		return fmt.Errorf("loading BPF spec: %w", err)
	}

	// Step 3: Rewrite constants to target the specific PID and GID offset.
	if err := spec.RewriteConstants(map[string]interface{}{
		"target_pid": uint32(pid),
		"gid_offset": uint64(gidOffset),
	}); err != nil {
		return fmt.Errorf("rewriting BPF constants: %w", err)
	}

	// Step 4: Load BPF objects with verifier logging for --debug.
	var opts ebpf.CollectionOptions
	opts.Programs.LogLevel = ebpf.LogLevelInstruction
	opts.Programs.LogSize = 1 << 20 // 1MB verifier log buffer

	objs := &gspyObjects{}
	if err := spec.LoadAndAssign(objs, &opts); err != nil {
		var ve *ebpf.VerifierError
		if errors.As(err, &ve) {
			m.debugLog = fmt.Sprintf("BPF verifier error:\n%+v", ve)
			return fmt.Errorf("BPF verifier rejected program: %w", err)
		}
		return fmt.Errorf("loading BPF objects: %w", err)
	}
	m.objs = objs

	// Step 5: Attach tracepoints for syscall entry and exit.
	// These are system-wide tracepoints; PID filtering is done in BPF.
	tpEnter, err := link.Tracepoint("raw_syscalls", "sys_enter",
		objs.TpSysEnter, nil)
	if err != nil {
		return fmt.Errorf("attaching sys_enter tracepoint: %w", err)
	}
	m.links = append(m.links, tpEnter)

	tpExit, err := link.Tracepoint("raw_syscalls", "sys_exit",
		objs.TpSysExit, nil)
	if err != nil {
		return fmt.Errorf("attaching sys_exit tracepoint: %w", err)
	}
	m.links = append(m.links, tpExit)

	// Step 6: Attach uprobes to the target Go binary.
	// Uprobes are scoped to the specific PID.
	ex, err := link.OpenExecutable(binaryPath)
	if err != nil {
		return fmt.Errorf("opening executable %s for uprobes: %w",
			binaryPath, err)
	}

	// runtime.execute — fires on every goroutine context switch.
	// This is the critical hook for TID→GID mapping.
	upExecute, err := ex.Uprobe("runtime.execute",
		objs.UprobeRuntimeExecute, &link.UprobeOptions{PID: pid})
	if err != nil {
		return fmt.Errorf("attaching uprobe runtime.execute: %w", err)
	}
	m.links = append(m.links, upExecute)

	// runtime.newproc1 — fires on goroutine creation.
	upNewproc, err := ex.Uprobe("runtime.newproc1",
		objs.UprobeRuntimeNewproc1, &link.UprobeOptions{PID: pid})
	if err != nil {
		return fmt.Errorf("attaching uprobe runtime.newproc1: %w", err)
	}
	m.links = append(m.links, upNewproc)

	// runtime.goexit1 — fires on goroutine exit.
	upGoexit, err := ex.Uprobe("runtime.goexit1",
		objs.UprobeRuntimeGoexit1, &link.UprobeOptions{PID: pid})
	if err != nil {
		return fmt.Errorf("attaching uprobe runtime.goexit1: %w", err)
	}
	m.links = append(m.links, upGoexit)

	// Step 7: Open ring buffer reader for event polling.
	rd, err := ringbuf.NewReader(objs.Events)
	if err != nil {
		return fmt.Errorf("creating ring buffer reader: %w", err)
	}
	m.reader = rd

	return nil
}

// PollEvents reads events from the BPF ring buffer in a blocking loop.
// It decodes each event as a SyscallEvent and calls handler.
// Returns when ctx is cancelled or on unrecoverable error.
func (m *realManager) PollEvents(ctx context.Context, handler func(SyscallEvent)) error {
	errCh := make(chan error, 1)

	// Close the reader when context is cancelled to unblock Read().
	go func() {
		<-ctx.Done()
		if m.reader != nil {
			m.reader.Close()
		}
	}()

	go func() {
		for {
			record, err := m.reader.Read()
			if err != nil {
				if errors.Is(err, ringbuf.ErrClosed) {
					errCh <- nil
					return
				}
				errCh <- fmt.Errorf("reading ring buffer: %w", err)
				return
			}

			var evt SyscallEvent
			if err := binary.Read(
				bytes.NewReader(record.RawSample),
				binary.LittleEndian, &evt,
			); err != nil {
				continue // skip malformed events
			}

			handler(evt)
		}
	}()

	select {
	case <-ctx.Done():
		return ctx.Err()
	case err := <-errCh:
		return err
	}
}

// GetGoroutineMeta reads goroutine metadata from the BPF goroutine_meta_map.
func (m *realManager) GetGoroutineMeta(gid uint64) (*GoroutineMeta, bool) {
	if m.objs == nil {
		return nil, false
	}

	var meta gspyGoroutineMeta
	err := m.objs.GoroutineMetaMap.Lookup(gid, &meta)
	if err != nil {
		return nil, false
	}

	return &GoroutineMeta{
		GID:      meta.Gid,
		State:    meta.State,
		FramePtr: meta.FramePtr,
	}, true
}

// Close detaches all BPF programs and closes resources.
func (m *realManager) Close() error {
	var firstErr error

	for _, l := range m.links {
		if err := l.Close(); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	m.links = nil

	if m.reader != nil {
		if err := m.reader.Close(); err != nil && firstErr == nil {
			firstErr = err
		}
		m.reader = nil
	}

	if m.objs != nil {
		if err := m.objs.Close(); err != nil && firstErr == nil {
			firstErr = err
		}
		m.objs = nil
	}

	return firstErr
}

// DebugInfo returns BPF verifier log and map statistics.
func (m *realManager) DebugInfo() string {
	if m.debugLog != "" {
		return m.debugLog
	}

	if m.objs == nil {
		return "BPF objects not loaded"
	}

	var buf bytes.Buffer
	buf.WriteString("BPF Map Statistics:\n")

	maps := map[string]*ebpf.Map{
		"gid_by_tid":         m.objs.GidByTid,
		"goroutine_meta_map": m.objs.GoroutineMetaMap,
		"syscall_enter":      m.objs.SyscallEnter,
	}

	for name, mp := range maps {
		if mp == nil {
			continue
		}
		info, err := mp.Info()
		if err != nil {
			fmt.Fprintf(&buf, "  %s: error reading info: %v\n", name, err)
			continue
		}
		fmt.Fprintf(&buf, "  %s: type=%s max_entries=%d\n",
			name, info.Type, info.MaxEntries)
	}

	return buf.String()
}
