package ui

import (
	"strings"
	"testing"
	"time"

	"github.com/Mutasem-mk4/gspy/internal/bpf"
)

// The recorded Linux journey showed that a later futex hid genuine network activity.
func TestCategoryActivitySurvivesLaterSyscallsAndExpires(t *testing.T) {
	start := time.Unix(100, 0)
	for _, scenario := range []struct {
		filter  FilterMode
		syscall string
	}{
		{FilterNet, "connect"}, {FilterIO, "write"}, {FilterSched, "futex"},
	} {
		t.Run(string(scenario.filter), func(t *testing.T) {
			table := NewTable()
			table.Filter = scenario.filter
			table.UpdateRow(GoroutineRow{GID: 7, Syscall: scenario.syscall, Frame: "main.work", LatencyUS: 12}, start)
			table.UpdateRow(GoroutineRow{GID: 7, Syscall: "getpid", Frame: "runtime.other", LatencyUS: 99}, start.Add(time.Second))
			table.Refresh(start.Add(5*time.Second - time.Nanosecond))
			if len(table.Rows) != 1 {
				t.Fatal("matching activity disappeared after an unrelated syscall")
			}
			row := table.Rows[0]
			if row.Syscall != scenario.syscall || row.Frame != "main.work" || row.LatencyUS != 12 || row.Count != 2 {
				t.Fatalf("category view mixed event fields: %+v", row)
			}
			table.Refresh(start.Add(5 * time.Second))
			if len(table.Rows) != 0 {
				t.Fatal("expired activity remained visible")
			}
			table.Filter = FilterAll
			table.Refresh(start.Add(5 * time.Second))
			if len(table.Rows) != 1 || table.Rows[0].Syscall != "getpid" {
				t.Fatal("category expiration lost the unfiltered latest event")
			}
		})
	}
}

func TestSelectionStaysOnGoroutineWhenCountsChange(t *testing.T) {
	now := time.Now()
	table := NewTable()
	table.UpdateRow(GoroutineRow{GID: 1, Syscall: "connect"}, now)
	table.UpdateRow(GoroutineRow{GID: 2, Syscall: "connect"}, now)
	table.Refresh(now)
	table.MoveDown()
	table.UpdateRow(GoroutineRow{GID: 2, Syscall: "connect"}, now)
	table.Refresh(now)
	if table.SelectedRow().GID != 2 {
		t.Fatal("refresh moved selection to a different goroutine")
	}
}

func TestCapturedFrameUsesResolvedSymbolInTableAndDetails(t *testing.T) {
	model := NewModel(Config{Filter: FilterAll, ResolveFrame: func(uint64) string { return "main.work" }})
	model.Update(SyscallEventMsg(bpf.SyscallEvent{GID: 7, FramePC: 0x1000, EventType: bpf.EventSyscall}))
	model.Update(TickMsg(time.Now()))
	if !strings.Contains(model.View(), "main.work") {
		t.Fatal("resolved frame missing from table")
	}
	model.table.Expanded = true
	view := model.View()
	if !strings.Contains(view, "main.work") || !strings.Contains(view, "not a full stack") {
		t.Fatal("details omit the frame or imply a complete stack")
	}
}

func TestUnattributedEventsAreNotCountedAsKnownGoroutines(t *testing.T) {
	table := NewTable()
	table.UpdateRow(GoroutineRow{GID: 0, Syscall: "futex"}, time.Now())
	table.UpdateRow(GoroutineRow{GID: 3, Syscall: "write"}, time.Now())
	if table.GoroutineCount() != 1 || !strings.Contains(RenderRow(table.AllRows[0], 100, false), "?") {
		t.Fatal("unattributed event group presented as a known goroutine")
	}
}
