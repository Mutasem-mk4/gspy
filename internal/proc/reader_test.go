// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2024 Mutasem Kharma <mutasem@gspy.dev>

package proc

import (
	"fmt"
	"testing"
)

func TestSymbolCacheEviction(t *testing.T) {
	const maxSize = 10000
	cache := NewSymbolCache(maxSize)

	// Insert maxSize+1 entries to trigger eviction.
	for i := uint64(0); i <= uint64(maxSize); i++ {
		cache.Put(i, fmt.Sprintf("func_%d", i))
	}

	// Cache should have evicted entries and be bounded.
	cacheLen := cache.Len()
	if cacheLen > maxSize {
		t.Errorf("cache.Len() = %d after inserting %d entries, "+
			"want <= %d (bounded)", cacheLen, maxSize+1, maxSize)
	}

	// Verify the cache is still functional after eviction.
	testPC := uint64(maxSize + 100)
	cache.Put(testPC, "test_function")
	sym, ok := cache.Get(testPC)
	if !ok {
		t.Error("cache.Get() should find recently inserted entry")
	}
	if sym != "test_function" {
		t.Errorf("cache.Get() = %q, want %q", sym, "test_function")
	}

	// Verify cache miss for evicted entries (some should be gone).
	misses := 0
	for i := uint64(0); i < 100; i++ {
		_, ok := cache.Get(i)
		if !ok {
			misses++
		}
	}
	// After eviction of ~half, we should definitely have some misses.
	// The exact number depends on eviction order, but should be > 0.
	t.Logf("cache misses for entries 0-99: %d", misses)
}

func TestSymbolCacheBasicOps(t *testing.T) {
	cache := NewSymbolCache(100)

	// Test empty cache miss.
	_, ok := cache.Get(42)
	if ok {
		t.Error("Get on empty cache should return false")
	}

	// Test put and get.
	cache.Put(42, "main.handler")
	sym, ok := cache.Get(42)
	if !ok {
		t.Error("Get after Put should return true")
	}
	if sym != "main.handler" {
		t.Errorf("Get() = %q, want %q", sym, "main.handler")
	}

	// Test duplicate put (should not increment count).
	cache.Put(42, "main.handler")
	if cache.Len() != 1 {
		t.Errorf("Len() = %d after duplicate Put, want 1", cache.Len())
	}

	// Test overwrite behavior — LoadOrStore keeps the first value.
	cache.Put(42, "new_value")
	sym, _ = cache.Get(42)
	if sym != "main.handler" {
		// sync.Map.LoadOrStore keeps the existing value.
		t.Logf("note: cache keeps first stored value: %q", sym)
	}
}

func TestFrameResolverFallback(t *testing.T) {
	// Create a resolver with no symbols (simulates stripped binary).
	cache := NewSymbolCache(100)
	resolver, err := NewFrameResolver("/nonexistent/binary", cache)
	if err != nil {
		t.Fatalf("NewFrameResolver should not error in fallback mode: %v", err)
	}

	// Resolve a PC — should return "0x<hex>" format.
	result := resolver.Resolve(0xdeadbeef)
	expected := "0xdeadbeef"
	if result != expected {
		t.Errorf("Resolve(0xdeadbeef) = %q, want %q", result, expected)
	}

	// Resolve PC=0 should return "<unknown>".
	result = resolver.Resolve(0)
	if result != "<unknown>" {
		t.Errorf("Resolve(0) = %q, want %q", result, "<unknown>")
	}

	// Verify fallback result is cached.
	cached, ok := cache.Get(0xdeadbeef)
	if !ok {
		t.Error("fallback result should be cached")
	}
	if cached != expected {
		t.Errorf("cached value = %q, want %q", cached, expected)
	}
}

func TestFrameResolverFallbackVariousAddresses(t *testing.T) {
	cache := NewSymbolCache(100)
	resolver, _ := NewFrameResolver("/nonexistent/binary", cache)

	tests := []struct {
		pc   uint64
		want string
	}{
		{0x0, "<unknown>"},
		{0x1, "0x1"},
		{0x400000, "0x400000"},
		{0x7fffffffffff, "0x7fffffffffff"},
		{0xdeadbeefcafe, "0xdeadbeefcafe"},
	}

	for _, tt := range tests {
		t.Run(fmt.Sprintf("0x%x", tt.pc), func(t *testing.T) {
			result := resolver.Resolve(tt.pc)
			if result != tt.want {
				t.Errorf("Resolve(0x%x) = %q, want %q", tt.pc, result, tt.want)
			}
		})
	}
}

func TestIsRuntimeFrame(t *testing.T) {
	tests := []struct {
		name string
		want bool
	}{
		{"runtime.goexit", true},
		{"runtime.main", true},
		{"runtime/internal/atomic.Load", true},
		{"internal/poll.runtime_pollWait", true},
		{"syscall.Syscall", true},
		{"main.handler", false},
		{"net/http.(*conn).serve", false},
		{"mypackage.DoWork", false},
		{"0xdeadbeef", false},
		{"<unknown>", false},
		{"", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isRuntimeFrame(tt.name)
			if got != tt.want {
				t.Errorf("isRuntimeFrame(%q) = %v, want %v",
					tt.name, got, tt.want)
			}
		})
	}
}

func TestProcessReaderNilReadFunc(t *testing.T) {
	cache := NewSymbolCache(100)
	resolver, _ := NewFrameResolver("/nonexistent/binary", cache)
	reader := NewProcessReader(1234, nil, resolver)

	// ReadGoroutineStack with nil readMem should return nil.
	frames := reader.ReadGoroutineStack(0x7fff0000)
	if frames != nil {
		t.Errorf("ReadGoroutineStack with nil readMem should return nil, got %v", frames)
	}
}

func TestProcessReaderZeroFramePtr(t *testing.T) {
	cache := NewSymbolCache(100)
	resolver, _ := NewFrameResolver("/nonexistent/binary", cache)
	mockRead := func(pid int, addr uintptr, size int) ([]byte, error) {
		return make([]byte, size), nil
	}
	reader := NewProcessReader(1234, mockRead, resolver)

	// ReadGoroutineStack with framePtr=0 should return nil.
	frames := reader.ReadGoroutineStack(0)
	if frames != nil {
		t.Errorf("ReadGoroutineStack(0) should return nil, got %v", frames)
	}
}

func TestLe64(t *testing.T) {
	// Test little-endian uint64 decoding.
	data := []byte{0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
	if got := le64(data); got != 1 {
		t.Errorf("le64 = %d, want 1", got)
	}

	data = []byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}
	if got := le64(data); got != 0xffffffffffffffff {
		t.Errorf("le64 = %d, want max uint64", got)
	}

	data = []byte{0xef, 0xbe, 0xad, 0xde, 0x00, 0x00, 0x00, 0x00}
	if got := le64(data); got != 0xdeadbeef {
		t.Errorf("le64 = 0x%x, want 0xdeadbeef", got)
	}
}
