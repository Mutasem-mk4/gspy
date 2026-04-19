// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2024 Mutasem Kharma <mutasem@gspy.dev>

package ui

import (
	"testing"

	tea "github.com/charmbracelet/bubbletea"
)

// makeTestRows creates N goroutine rows with varied data for testing.
func makeTestRows(n int) []*GoroutineRow {
	syscalls := []string{"write", "read", "epoll_wait", "futex", "connect"}
	states := []string{"running", "syscall", "waiting", "dead", "created"}

	rows := make([]*GoroutineRow, n)
	for i := 0; i < n; i++ {
		rows[i] = &GoroutineRow{
			GID:       uint64(i + 1),
			State:     states[i%len(states)],
			Syscall:   syscalls[i%len(syscalls)],
			LatencyUS: int64((i + 1) * 1000), // 1ms, 2ms, 3ms, ...
			Count:     int64((n - i) * 100),   // descending counts
			Frame:     "net/http.(*conn).serve",
		}
	}
	return rows
}

func TestSortByLatency(t *testing.T) {
	table := NewTable()

	// Add 5 goroutines with different latencies.
	rows := makeTestRows(5)
	for _, r := range rows {
		table.AllRows[r.GID] = r
	}

	// Set sort to latency descending.
	table.Sort = SortByLatency
	table.SortDir = SortDesc
	table.Refresh()

	if len(table.Rows) != 5 {
		t.Fatalf("expected 5 visible rows, got %d", len(table.Rows))
	}

	// Verify descending order by latency.
	for i := 1; i < len(table.Rows); i++ {
		if table.Rows[i].LatencyUS > table.Rows[i-1].LatencyUS {
			t.Errorf("row %d latency (%d) > row %d latency (%d) — not sorted descending",
				i, table.Rows[i].LatencyUS, i-1, table.Rows[i-1].LatencyUS)
		}
	}

	// Test ascending sort.
	table.SortDir = SortAsc
	table.Refresh()

	for i := 1; i < len(table.Rows); i++ {
		if table.Rows[i].LatencyUS < table.Rows[i-1].LatencyUS {
			t.Errorf("row %d latency (%d) < row %d latency (%d) — not sorted ascending",
				i, table.Rows[i].LatencyUS, i-1, table.Rows[i-1].LatencyUS)
		}
	}
}

func TestSortByCount(t *testing.T) {
	table := NewTable()

	rows := makeTestRows(5)
	for _, r := range rows {
		table.AllRows[r.GID] = r
	}

	table.Sort = SortByCount
	table.SortDir = SortDesc
	table.Refresh()

	if len(table.Rows) != 5 {
		t.Fatalf("expected 5 visible rows, got %d", len(table.Rows))
	}

	// Verify descending order by count.
	for i := 1; i < len(table.Rows); i++ {
		if table.Rows[i].Count > table.Rows[i-1].Count {
			t.Errorf("row %d count (%d) > row %d count (%d) — not sorted descending",
				i, table.Rows[i].Count, i-1, table.Rows[i-1].Count)
		}
	}
}

func TestFilterIO(t *testing.T) {
	table := NewTable()

	// Add rows with IO and non-IO syscalls.
	table.AllRows[1] = &GoroutineRow{GID: 1, Syscall: "read", Count: 10}
	table.AllRows[2] = &GoroutineRow{GID: 2, Syscall: "write", Count: 20}
	table.AllRows[3] = &GoroutineRow{GID: 3, Syscall: "futex", Count: 30}
	table.AllRows[4] = &GoroutineRow{GID: 4, Syscall: "connect", Count: 40}
	table.AllRows[5] = &GoroutineRow{GID: 5, Syscall: "openat", Count: 50}

	table.Filter = FilterIO
	table.Refresh()

	// Only IO syscalls should be visible: read, write, openat.
	if len(table.Rows) != 3 {
		t.Errorf("FilterIO: got %d rows, want 3 (read, write, openat)",
			len(table.Rows))
	}

	for _, row := range table.Rows {
		switch row.Syscall {
		case "read", "write", "openat":
			// expected
		default:
			t.Errorf("FilterIO: unexpected syscall %q in results", row.Syscall)
		}
	}
}

func TestFilterNet(t *testing.T) {
	table := NewTable()

	table.AllRows[1] = &GoroutineRow{GID: 1, Syscall: "read", Count: 10}
	table.AllRows[2] = &GoroutineRow{GID: 2, Syscall: "connect", Count: 20}
	table.AllRows[3] = &GoroutineRow{GID: 3, Syscall: "socket", Count: 30}
	table.AllRows[4] = &GoroutineRow{GID: 4, Syscall: "futex", Count: 40}
	table.AllRows[5] = &GoroutineRow{GID: 5, Syscall: "accept4", Count: 50}

	table.Filter = FilterNet
	table.Refresh()

	// Only net syscalls should be visible: connect, socket, accept4.
	if len(table.Rows) != 3 {
		t.Errorf("FilterNet: got %d rows, want 3 (connect, socket, accept4)",
			len(table.Rows))
	}

	for _, row := range table.Rows {
		switch row.Syscall {
		case "connect", "socket", "accept4":
			// expected
		default:
			t.Errorf("FilterNet: unexpected syscall %q in results", row.Syscall)
		}
	}
}

func TestFilterSched(t *testing.T) {
	table := NewTable()

	table.AllRows[1] = &GoroutineRow{GID: 1, Syscall: "read", Count: 10}
	table.AllRows[2] = &GoroutineRow{GID: 2, Syscall: "futex", Count: 20}
	table.AllRows[3] = &GoroutineRow{GID: 3, Syscall: "sched_yield", Count: 30}
	table.AllRows[4] = &GoroutineRow{GID: 4, Syscall: "nanosleep", Count: 40}
	table.AllRows[5] = &GoroutineRow{GID: 5, Syscall: "connect", Count: 50}

	table.Filter = FilterSched
	table.Refresh()

	// Only sched syscalls: futex, sched_yield, nanosleep.
	if len(table.Rows) != 3 {
		t.Errorf("FilterSched: got %d rows, want 3 (futex, sched_yield, nanosleep)",
			len(table.Rows))
	}
}

func TestTableResize(t *testing.T) {
	// Verify that sending a WindowSizeMsg does not panic.
	model := NewModel(Config{
		PID:       1234,
		Binary:    "/usr/bin/test",
		GoVersion: "go1.21.5",
	})

	// Initialize.
	model.Init()

	// Send resize.
	newModel, _ := model.Update(tea.WindowSizeMsg{Width: 40, Height: 80})
	if newModel == nil {
		t.Fatal("Update(WindowSizeMsg) returned nil model")
	}

	m, ok := newModel.(*Model)
	if !ok {
		t.Fatal("Update should return *Model")
	}

	if m.width != 40 || m.height != 80 {
		t.Errorf("after resize: width=%d height=%d, want 40x80",
			m.width, m.height)
	}

	// Verify View() doesn't panic at small size.
	view := m.View()
	if view == "" {
		t.Error("View() should return non-empty string")
	}

	// Test very small resize.
	newModel, _ = m.Update(tea.WindowSizeMsg{Width: 10, Height: 5})
	m = newModel.(*Model)
	view = m.View()
	if view == "" {
		t.Error("View() should return non-empty string at 10x5")
	}
}

func TestNextFilter(t *testing.T) {
	tests := []struct {
		input FilterMode
		want  FilterMode
	}{
		{FilterAll, FilterIO},
		{FilterIO, FilterNet},
		{FilterNet, FilterSched},
		{FilterSched, FilterAll},
	}

	for _, tt := range tests {
		t.Run(string(tt.input), func(t *testing.T) {
			got := NextFilter(tt.input)
			if got != tt.want {
				t.Errorf("NextFilter(%s) = %s, want %s", tt.input, got, tt.want)
			}
		})
	}
}

func TestTableToggleSort(t *testing.T) {
	table := NewTable()

	if table.Sort != SortByCount {
		t.Errorf("initial sort = %d, want SortByCount", table.Sort)
	}

	table.ToggleSort()
	if table.Sort != SortByLatency {
		t.Errorf("after first toggle: sort = %d, want SortByLatency", table.Sort)
	}

	table.ToggleSort()
	if table.Sort != SortByGID {
		t.Errorf("after second toggle: sort = %d, want SortByGID", table.Sort)
	}

	table.ToggleSort()
	if table.Sort != SortByCount {
		t.Errorf("after third toggle: sort = %d, want SortByCount", table.Sort)
	}
}

func TestTableSelection(t *testing.T) {
	table := NewTable()

	rows := makeTestRows(5)
	for _, r := range rows {
		table.AllRows[r.GID] = r
	}
	table.Refresh()

	// Initial selection.
	if table.SelectedIdx != 0 {
		t.Errorf("initial SelectedIdx = %d, want 0", table.SelectedIdx)
	}

	// Move down.
	table.MoveDown()
	if table.SelectedIdx != 1 {
		t.Errorf("after MoveDown: SelectedIdx = %d, want 1", table.SelectedIdx)
	}

	// Move up.
	table.MoveUp()
	if table.SelectedIdx != 0 {
		t.Errorf("after MoveUp: SelectedIdx = %d, want 0", table.SelectedIdx)
	}

	// Move up at top (should clamp).
	table.MoveUp()
	if table.SelectedIdx != 0 {
		t.Errorf("MoveUp at top: SelectedIdx = %d, want 0", table.SelectedIdx)
	}

	// Move to bottom.
	for i := 0; i < 10; i++ {
		table.MoveDown()
	}
	if table.SelectedIdx != len(table.Rows)-1 {
		t.Errorf("at bottom: SelectedIdx = %d, want %d",
			table.SelectedIdx, len(table.Rows)-1)
	}
}

func TestSortColumnName(t *testing.T) {
	table := NewTable()

	name, ind := table.SortColumnName()
	if name != "COUNT" {
		t.Errorf("default sort column = %q, want COUNT", name)
	}
	if ind != "▼" {
		t.Errorf("default indicator = %q, want ▼", ind)
	}

	table.SortDir = SortAsc
	_, ind = table.SortColumnName()
	if ind != "▲" {
		t.Errorf("ascending indicator = %q, want ▲", ind)
	}
}

func TestFormatLatency(t *testing.T) {
	tests := []struct {
		us   int64
		want string
	}{
		{0, "-"},
		{-1, "-"},
		{500, "500µs"},
		{999, "999µs"},
		{1000, "1.0ms"},
		{4200, "4.2ms"},
		{100000, "100.0ms"},
		{1000000, "1.0s"},
		{1500000, "1.5s"},
	}

	for _, tt := range tests {
		t.Run(tt.want, func(t *testing.T) {
			got := formatLatency(tt.us)
			if got != tt.want {
				t.Errorf("formatLatency(%d) = %q, want %q", tt.us, got, tt.want)
			}
		})
	}
}

func TestTruncate(t *testing.T) {
	tests := []struct {
		s      string
		maxLen int
		want   string
	}{
		{"hello", 10, "hello"},
		{"hello", 5, "hello"},
		{"hello world", 5, "hell…"},
		{"hello", 1, "…"},
		{"hello", 0, ""},
		{"", 5, ""},
	}

	for _, tt := range tests {
		got := truncate(tt.s, tt.maxLen)
		if got != tt.want {
			t.Errorf("truncate(%q, %d) = %q, want %q",
				tt.s, tt.maxLen, got, tt.want)
		}
	}
}
