// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2024 Mutasem Kharma <mutasem@gspy.dev>

// Package proc provides process memory reading via process_vm_readv(2),
// Go stack frame walking, and ELF symbol resolution for gspy's
// goroutine-to-syscall attribution.
//
// Key design constraints:
//   - NEVER use ptrace — process_vm_readv only (zero-footprint requirement)
//   - Symbol cache is bounded to 10,000 entries with eviction
//   - All failures are graceful: unresolvable PCs display "0x<hex>"
//   - This package must compile on all platforms; Linux-specific syscalls
//     are guarded by runtime.GOOS checks
package proc

import (
	"debug/elf"
	"fmt"
	"sort"
	"sync"
	"sync/atomic"
)

// ---------------------------------------------------------------------------
// SymbolCache — bounded PC → symbol name cache
// ---------------------------------------------------------------------------

// SymbolCache provides a thread-safe cache mapping program counter values
// to resolved symbol names. The cache is bounded to maxSize entries.
// When capacity is exceeded, the cache is partially evicted (LRU-approximate
// using sync.Map.Range which visits in creation order).
type SymbolCache struct {
	cache   sync.Map
	count   atomic.Int64
	maxSize int64
}

// NewSymbolCache creates a cache bounded to maxSize entries.
func NewSymbolCache(maxSize int) *SymbolCache {
	return &SymbolCache{maxSize: int64(maxSize)}
}

// Get retrieves a cached symbol name for the given PC.
// Returns ("", false) on cache miss.
func (c *SymbolCache) Get(pc uint64) (string, bool) {
	v, ok := c.cache.Load(pc)
	if !ok {
		return "", false
	}
	return v.(string), true
}

// Put stores a PC → symbol mapping. If the cache exceeds maxSize,
// approximately half the entries are evicted to make room.
func (c *SymbolCache) Put(pc uint64, symbol string) {
	if c.count.Load() >= c.maxSize {
		c.evict()
	}
	if _, loaded := c.cache.LoadOrStore(pc, symbol); !loaded {
		c.count.Add(1)
	}
}

// evict removes approximately half the cache entries.
// sync.Map.Range visits entries in an unspecified order, providing
// an approximate LRU effect since older entries tend to be visited first.
func (c *SymbolCache) evict() {
	target := c.maxSize / 2
	evicted := int64(0)
	c.cache.Range(func(key, _ interface{}) bool {
		c.cache.Delete(key)
		evicted++
		return c.count.Add(-1) > target
	})
}

// Len returns the approximate number of entries in the cache.
func (c *SymbolCache) Len() int {
	return int(c.count.Load())
}

// ---------------------------------------------------------------------------
// FrameResolver — ELF symbol → function name resolution
// ---------------------------------------------------------------------------

// elfSymbol is a simplified symbol entry for binary search.
type elfSymbol struct {
	Value uint64
	Size  uint64
	Name  string
}

// FrameResolver resolves program counter values to Go function names
// using the target binary's ELF symbol table. It caches results in a
// SymbolCache for performance.
//
// When symbol resolution fails (stripped binary, invalid PC), the resolver
// returns "0x<hex>" rather than panicking.
type FrameResolver struct {
	symbols []elfSymbol
	cache   *SymbolCache
}

// NewFrameResolver creates a resolver for the given binary.
// If the binary cannot be opened or has no symbols, the resolver
// operates in fallback mode (all PCs resolve to "0x<hex>").
func NewFrameResolver(binaryPath string, cache *SymbolCache) (*FrameResolver, error) {
	r := &FrameResolver{cache: cache}

	f, err := elf.Open(binaryPath)
	if err != nil {
		// Fallback mode: no symbols available.
		return r, nil
	}
	defer f.Close()

	syms, err := f.Symbols()
	if err != nil {
		// Binary has no symbol table (stripped). Fallback mode.
		return r, nil
	}

	// Filter to function symbols (STT_FUNC) and sort by address.
	r.symbols = make([]elfSymbol, 0, len(syms))
	for _, s := range syms {
		if elf.ST_TYPE(s.Info) == elf.STT_FUNC && s.Value > 0 {
			r.symbols = append(r.symbols, elfSymbol{
				Value: s.Value,
				Size:  s.Size,
				Name:  s.Name,
			})
		}
	}

	sort.Slice(r.symbols, func(i, j int) bool {
		return r.symbols[i].Value < r.symbols[j].Value
	})

	return r, nil
}

// Resolve converts a PC to a human-readable function name.
// Uses the symbol cache first, then falls back to ELF symbol table lookup.
// Returns "0x<hex>" if the PC cannot be resolved.
func (r *FrameResolver) Resolve(pc uint64) string {
	if pc == 0 {
		return "<unknown>"
	}

	// Check cache first.
	if r.cache != nil {
		if sym, ok := r.cache.Get(pc); ok {
			return sym
		}
	}

	name := r.lookupSymbol(pc)

	// Cache the result.
	if r.cache != nil {
		r.cache.Put(pc, name)
	}

	return name
}

// lookupSymbol performs a binary search for the function containing the given PC.
// For Go binaries, function symbols have non-zero Size, so we can check
// if pc falls within [symbol.Value, symbol.Value + symbol.Size).
// For symbols with Size=0 (common in Go), we use the next symbol's address
// as the upper bound.
func (r *FrameResolver) lookupSymbol(pc uint64) string {
	if len(r.symbols) == 0 {
		return fmt.Sprintf("0x%x", pc)
	}

	// Binary search: find the last symbol with Value <= pc.
	idx := sort.Search(len(r.symbols), func(i int) bool {
		return r.symbols[i].Value > pc
	})

	if idx == 0 {
		// PC is before the first symbol.
		return fmt.Sprintf("0x%x", pc)
	}

	sym := r.symbols[idx-1]

	// Check if PC is within the symbol's range.
	if sym.Size > 0 {
		if pc < sym.Value+sym.Size {
			return sym.Name
		}
		return fmt.Sprintf("0x%x", pc)
	}

	// Size=0: use the next symbol's address as implicit upper bound.
	if idx < len(r.symbols) {
		nextAddr := r.symbols[idx].Value
		if pc < nextAddr {
			return sym.Name
		}
	} else {
		// Last symbol — assume it contains the PC.
		return sym.Name
	}

	return fmt.Sprintf("0x%x", pc)
}

// ResolveTopUserFrame returns the first non-runtime symbol from a list of PCs.
// Runtime frames (starting with "runtime." or "internal/") are skipped
// to find the user's actual function.
func (r *FrameResolver) ResolveTopUserFrame(pcs []uint64) string {
	for _, pc := range pcs {
		name := r.Resolve(pc)
		if !isRuntimeFrame(name) {
			return name
		}
	}

	// All frames are runtime frames — return the first one.
	if len(pcs) > 0 {
		return r.Resolve(pcs[0])
	}

	return "<unknown>"
}

// isRuntimeFrame returns true if the symbol name belongs to the Go runtime
// or internal packages (not user code).
func isRuntimeFrame(name string) bool {
	if len(name) == 0 || name[0] == '0' { // "0x..." unresolved
		return false
	}
	// Go runtime and internal frames
	prefixes := []string{
		"runtime.", "runtime/internal/",
		"internal/", "syscall.", "golang.org/x/sys/",
	}
	for _, p := range prefixes {
		if len(name) >= len(p) && name[:len(p)] == p {
			return true
		}
	}
	return false
}

// ---------------------------------------------------------------------------
// ProcessReader — process_vm_readv wrapper for stack walking
// ---------------------------------------------------------------------------

// ReadFunc is the function signature for reading target process memory.
// On Linux, this is implemented using process_vm_readv(2).
// For testing, a mock function can be provided.
type ReadFunc func(pid int, addr uintptr, size int) ([]byte, error)

// ProcessReader reads memory from a target process for stack frame walking.
// It uses process_vm_readv(2) on Linux — never ptrace.
//
// READONLY MODE GUARANTEE:
// process_vm_readv(2) is a read-only operation. It cannot modify the target
// process's memory. This is asserted here for --readonly mode compliance.
// The syscall signature is:
//   ssize_t process_vm_readv(pid_t pid,
//     const struct iovec *local_iov, unsigned long liovcnt,
//     const struct iovec *remote_iov, unsigned long riovcnt,
//     unsigned long flags);
// There is no write counterpart used by gspy.
type ProcessReader struct {
	pid      int
	readMem  ReadFunc
	resolver *FrameResolver
}

// NewProcessReader creates a reader for the target process.
// readFn provides the memory reading implementation (real or mock).
func NewProcessReader(pid int, readFn ReadFunc, resolver *FrameResolver) *ProcessReader {
	return &ProcessReader{
		pid:      pid,
		readMem:  readFn,
		resolver: resolver,
	}
}

// ReadGoroutineStack reads the goroutine's stack starting from the given
// frame pointer (SP) and returns resolved stack frames.
//
// Stack walking procedure:
//  1. Read 8 bytes at SP to get the return address (PC)
//  2. Read 8 bytes at SP+8 to get the caller's frame pointer
//  3. Resolve PC to a symbol name
//  4. Repeat with the caller's frame pointer
//
// Maximum depth: 64 frames (prevents infinite loops on corrupted stacks).
func (r *ProcessReader) ReadGoroutineStack(framePtr uint64) []string {
	if r.readMem == nil || framePtr == 0 {
		return nil
	}

	const maxDepth = 64
	const ptrSize = 8 // amd64

	frames := make([]string, 0, 16)
	sp := framePtr

	for i := 0; i < maxDepth; i++ {
		// Read return address at [sp]
		pcBytes, err := r.readMem(r.pid, uintptr(sp), ptrSize)
		if err != nil || len(pcBytes) < ptrSize {
			break
		}
		pc := le64(pcBytes)
		if pc == 0 {
			break
		}

		// Resolve and add frame
		name := r.resolver.Resolve(pc)
		frames = append(frames, name)

		// Read caller's frame pointer at [sp + 8]
		// (Go stack frames on amd64: return addr at [SP], caller SP at [SP+8])
		fpBytes, err := r.readMem(r.pid, uintptr(sp+ptrSize), ptrSize)
		if err != nil || len(fpBytes) < ptrSize {
			break
		}
		nextSP := le64(fpBytes)
		if nextSP == 0 || nextSP <= sp {
			break // stack corruption or end of stack
		}
		sp = nextSP
	}

	return frames
}

// le64 reads a little-endian uint64 from a byte slice.
func le64(b []byte) uint64 {
	return uint64(b[0]) | uint64(b[1])<<8 | uint64(b[2])<<16 |
		uint64(b[3])<<24 | uint64(b[4])<<32 | uint64(b[5])<<40 |
		uint64(b[6])<<48 | uint64(b[7])<<56
}
