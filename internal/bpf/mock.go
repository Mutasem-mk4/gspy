// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2024 Mutasem Kharma <mutasem@gspy.dev>

//go:build !linux || testing

// Package bpf mock implementation.
// This file provides a MockManager that implements the Manager interface
// without any real BPF infrastructure. It is used for:
//   - Unit tests on any platform (go test ./... must pass without root/BPF)
//   - Building on non-Linux platforms (development on macOS/Windows)
//
// The MockManager allows tests to inject events and goroutine metadata
// to exercise the TUI, JSON emitter, and attach logic in isolation.
package bpf

import (
	"context"
	"fmt"
	"sync"
)

// MockManager provides a stub BPF implementation for testing.
type MockManager struct {
	mu        sync.RWMutex
	metas     map[uint64]*GoroutineMeta
	eventCh   chan SyscallEvent
	attached  bool
	debugInfo string
	pid       int
	binary    string
	gidOffset uint64
}

// NewManager creates a new MockManager.
// On non-Linux or during testing, this is the Manager constructor.
func NewManager() Manager {
	return NewMockManager()
}

// NewMockManager creates a MockManager with direct access for test setup.
func NewMockManager() *MockManager {
	return &MockManager{
		metas:   make(map[uint64]*GoroutineMeta),
		eventCh: make(chan SyscallEvent, 1024),
	}
}

// LoadAndAttach records the attachment parameters without doing real BPF work.
func (m *MockManager) LoadAndAttach(pid int, binaryPath string, gidOffset uint64) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.attached = true
	m.pid = pid
	m.binary = binaryPath
	m.gidOffset = gidOffset
	return nil
}

// PollEvents delivers injected events to the handler.
// Blocks until ctx is cancelled.
func (m *MockManager) PollEvents(ctx context.Context, handler func(SyscallEvent)) error {
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case evt := <-m.eventCh:
			handler(evt)
		}
	}
}

// GetGoroutineMeta returns metadata for a goroutine if it has been added.
func (m *MockManager) GetGoroutineMeta(gid uint64) (*GoroutineMeta, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	meta, ok := m.metas[gid]
	if !ok {
		return nil, false
	}
	// Return a copy to avoid data races.
	cp := *meta
	return &cp, true
}

// Close marks the manager as detached.
func (m *MockManager) Close() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.attached = false
	return nil
}

// DebugInfo returns the configured debug string.
func (m *MockManager) DebugInfo() string {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if m.debugInfo != "" {
		return m.debugInfo
	}
	return fmt.Sprintf("MockManager: pid=%d binary=%s gidOffset=%d attached=%t",
		m.pid, m.binary, m.gidOffset, m.attached)
}

// --- Test helpers ---

// AddGoroutine adds or updates a goroutine entry for testing.
func (m *MockManager) AddGoroutine(gid uint64, state uint32) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.metas[gid] = &GoroutineMeta{
		GID:   gid,
		State: state,
	}
}

// InjectEvent sends a test event through the mock event channel.
func (m *MockManager) InjectEvent(evt SyscallEvent) {
	m.eventCh <- evt
}

// SetDebugInfo sets the debug info string returned by DebugInfo().
func (m *MockManager) SetDebugInfo(info string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.debugInfo = info
}

// IsAttached returns whether LoadAndAttach has been called.
func (m *MockManager) IsAttached() bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.attached
}
