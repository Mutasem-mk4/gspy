// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2024 Mutasem Kharma <mutasem@gspy.dev>

// Package ui provides the terminal user interface for gspy using
// bubbletea and lipgloss. This file contains goroutine table state,
// sorting, filtering, and selection logic.
package ui

import (
	"cmp"
	"encoding/json"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/Mutasem-mk4/gspy/internal/bpf"
)

// ---------------------------------------------------------------------------
// Sort and Filter modes
// ---------------------------------------------------------------------------

// SortMode defines how goroutine rows are sorted.
type SortMode int

const (
	SortByCount   SortMode = iota // default: sort by total syscall count
	SortByLatency                 // sort by highest current latency
	SortByGID                     // sort by goroutine ID
)

// SortDirection defines ascending or descending sort order.
type SortDirection int

const (
	SortDesc SortDirection = iota // ▼ descending (default)
	SortAsc                       // ▲ ascending
)

// FilterMode defines which syscall categories to display.
type FilterMode string

const (
	FilterAll   FilterMode = "all"
	FilterIO    FilterMode = "io"
	FilterNet   FilterMode = "net"
	FilterSched FilterMode = "sched"
)

// NextFilter cycles through filter modes: all → io → net → sched → all.
func NextFilter(current FilterMode) FilterMode {
	switch current {
	case FilterAll:
		return FilterIO
	case FilterIO:
		return FilterNet
	case FilterNet:
		return FilterSched
	case FilterSched:
		return FilterAll
	default:
		return FilterAll
	}
}

// ---------------------------------------------------------------------------
// GoroutineRow — one row in the TUI table
// ---------------------------------------------------------------------------

// GoroutineRow represents a single goroutine's state in the TUI.
type GoroutineRow struct {
	GID       uint64 // goroutine ID
	State     string // running | syscall | waiting | dead | created
	Syscall   string // current or last syscall name
	LatencyUS int64  // current syscall latency in microseconds
	Count     int64  // total syscalls since attach
	Frame     string // topmost user-space symbol
	FramePC   uint64 // raw PC of top frame (for cache)
}

// ---------------------------------------------------------------------------
// Table — goroutine table with sort, filter, selection
// ---------------------------------------------------------------------------

// Table manages the goroutine table state including all rows,
// the visible (filtered+sorted) rows, selection cursor, sort mode,
// and filter mode.
const activityWindow = 5 * time.Second

type recentActivity struct {
	row    GoroutineRow
	seenAt time.Time
}

type Table struct {
	activity map[uint64]map[FilterMode]recentActivity
	// AllRows contains every goroutine observed since attach, keyed by GID.
	AllRows map[uint64]*GoroutineRow

	// Rows contains the visible rows after filtering and sorting.
	Rows []*GoroutineRow

	// Selection state
	SelectedIdx int  // index into Rows
	Expanded    bool // true when showing expanded goroutine view

	// Sort state
	Sort    SortMode
	SortDir SortDirection

	// Filter state
	Filter FilterMode

	// Display dimensions
	Width  int
	Height int
}

// NewTable creates a new empty table.
func NewTable() *Table {
	return &Table{
		AllRows:  make(map[uint64]*GoroutineRow),
		activity: make(map[uint64]map[FilterMode]recentActivity),
		Sort:     SortByCount,
		SortDir:  SortDesc,
		Filter:   FilterAll,
		Width:    80,
		Height:   24,
	}
}

// UpdateRow updates or creates a goroutine row from a syscall event.
// Called for every EVENT_SYSCALL event.
func (t *Table) UpdateRow(event GoroutineRow, observedAt time.Time) {
	previous := t.AllRows[event.GID]
	if previous != nil {
		event.Count = previous.Count
		if event.State == "" {
			event.State = previous.State
		}
	}
	event.Count++
	t.AllRows[event.GID] = &event
	t.recordActivity(event, observedAt)
}

func (t *Table) recordActivity(event GoroutineRow, observedAt time.Time) {
	categories := t.activity[event.GID]
	if categories == nil {
		categories = make(map[FilterMode]recentActivity)
		t.activity[event.GID] = categories
	}
	for _, category := range []FilterMode{FilterIO, FilterNet, FilterSched} {
		if matchesCategory(category, event.Syscall) {
			categories[category] = recentActivity{row: event, seenAt: observedAt}
		}
	}
}

// SetState updates a goroutine's state (e.g., from BPF goroutine_meta).
func (t *Table) SetState(gid uint64, state string) {
	row, ok := t.AllRows[gid]
	if !ok {
		row = &GoroutineRow{GID: gid, State: state}
		t.AllRows[gid] = row
		return
	}
	row.State = state
}

// MarkDead marks a goroutine as dead.
func (t *Table) MarkDead(gid uint64) {
	if row, ok := t.AllRows[gid]; ok {
		row.State = "dead"
	}
}

// Refresh rebuilds the visible Rows by applying filter and sort.
func (t *Table) Refresh(now time.Time) {
	selected := t.SelectedRow()
	t.Rows = t.Rows[:0]

	for _, row := range t.AllRows {
		if visible := t.filteredRow(row, now); visible != nil {
			t.Rows = append(t.Rows, visible)
		}
	}

	t.sortRows()
	if selected != nil {
		for index, row := range t.Rows {
			if row.GID == selected.GID {
				t.SelectedIdx = index
				break
			}
		}
	}

	// Clamp selection index.
	if t.SelectedIdx >= len(t.Rows) {
		t.SelectedIdx = len(t.Rows) - 1
	}
	if t.SelectedIdx < 0 {
		t.SelectedIdx = 0
	}
}

// A category view retains its last matching event independently of later syscalls.
func (t *Table) filteredRow(row *GoroutineRow, now time.Time) *GoroutineRow {
	if t.Filter == FilterAll || t.Filter == "" {
		return row
	}
	activity, ok := t.activity[row.GID][t.Filter]
	if !ok || now.Sub(activity.seenAt) >= activityWindow {
		return nil
	}
	visible := activity.row
	visible.Count = row.Count
	visible.State = row.State
	return &visible
}

func matchesCategory(category FilterMode, syscall string) bool {
	switch category {
	case FilterIO:
		return bpf.IOSyscalls[syscall]
	case FilterNet:
		return bpf.NetSyscalls[syscall]
	case FilterSched:
		return bpf.SchedSyscalls[syscall]
	}
	return false
}

func (t *Table) sortRows() {
	sort.Slice(t.Rows, func(i, j int) bool {
		left, right := t.Rows[i], t.Rows[j]
		order := cmp.Compare(left.Count, right.Count)
		switch t.Sort {
		case SortByLatency:
			order = cmp.Compare(left.LatencyUS, right.LatencyUS)
		case SortByGID:
			order = cmp.Compare(left.GID, right.GID)
		}
		if order == 0 {
			return left.GID < right.GID
		}
		if t.SortDir == SortDesc {
			return order > 0
		}
		return order < 0
	})
}

// ToggleSort cycles through sort modes and toggles direction.
func (t *Table) ToggleSort() {
	switch t.Sort {
	case SortByCount:
		t.Sort = SortByLatency
	case SortByLatency:
		t.Sort = SortByGID
	case SortByGID:
		t.Sort = SortByCount
	}
	// Reset to descending on mode change.
	t.SortDir = SortDesc
}

// ToggleSortDirection toggles between ascending and descending.
func (t *Table) ToggleSortDirection() {
	if t.SortDir == SortDesc {
		t.SortDir = SortAsc
	} else {
		t.SortDir = SortDesc
	}
}

// CycleFilter cycles to the next filter mode.
func (t *Table) CycleFilter() {
	t.Filter = NextFilter(t.Filter)
}

// MoveUp moves the selection cursor up.
func (t *Table) MoveUp() {
	if t.SelectedIdx > 0 {
		t.SelectedIdx--
	}
}

// MoveDown moves the selection cursor down.
func (t *Table) MoveDown() {
	if t.SelectedIdx < len(t.Rows)-1 {
		t.SelectedIdx++
	}
}

// SelectedRow returns the currently selected row, or nil if empty.
func (t *Table) SelectedRow() *GoroutineRow {
	if t.SelectedIdx >= 0 && t.SelectedIdx < len(t.Rows) {
		return t.Rows[t.SelectedIdx]
	}
	return nil
}

// GoroutineCount returns the total number of known goroutines.
func (t *Table) GoroutineCount() int {
	count := len(t.AllRows)
	if _, unknown := t.AllRows[0]; unknown {
		count--
	}
	return count
}

// VisibleCount returns the number of visible (filtered) rows.
func (t *Table) VisibleCount() int {
	return len(t.Rows)
}

// SortColumnName returns the name and indicator for the current sort column.
func (t *Table) SortColumnName() (string, string) {
	var name string
	switch t.Sort {
	case SortByCount:
		name = "COUNT"
	case SortByLatency:
		name = "LATENCY"
	case SortByGID:
		name = "GID"
	}

	indicator := "▼"
	if t.SortDir == SortAsc {
		indicator = "▲"
	}

	return name, indicator
}

// Resize updates the display dimensions.
func (t *Table) Resize(width, height int) {
	if width > 0 {
		t.Width = width
	}
	if height > 0 {
		t.Height = height
	}
}

// MaxVisibleRows returns the number of rows that can be displayed
// given the current terminal height (accounting for header + footer).
func (t *Table) MaxVisibleRows() int {
	// 2 header lines + 1 column header + 1 footer line = 4 chrome lines
	rows := t.Height - 4
	if rows < 1 {
		rows = 1
	}
	return rows
}

// VisibleSlice returns the slice of rows currently visible in the viewport.
func (t *Table) VisibleSlice() []*GoroutineRow {
	max := t.MaxVisibleRows()
	if len(t.Rows) <= max {
		return t.Rows
	}

	// Scroll to keep selection visible.
	start := 0
	if t.SelectedIdx >= max {
		start = t.SelectedIdx - max + 1
	}
	end := start + max
	if end > len(t.Rows) {
		end = len(t.Rows)
		start = end - max
		if start < 0 {
			start = 0
		}
	}

	return t.Rows[start:end]
}

// FilterString returns a display string for the current filter mode.
func (t *Table) FilterString() string {
	return strings.ToLower(string(t.Filter))
}

// SaveSnapshot exports the entire current table state to a JSON file.
func (t *Table) SaveSnapshot(filename string) error {
	f, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer f.Close()

	encoder := json.NewEncoder(f)
	encoder.SetIndent("", "  ")
	err = encoder.Encode(t.AllRows)
	if err != nil {
		_ = f.Close()
		return err
	}
	return f.Close()
}
