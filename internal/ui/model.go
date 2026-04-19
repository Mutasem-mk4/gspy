// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2024 Mutasem Kharma <mutasem@gspy.dev>

package ui

import (
	"fmt"
	"strings"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/mutasemkharma/gspy/internal/bpf"
)

// ---------------------------------------------------------------------------
// Messages — all tea.Msg types used by the TUI
// ---------------------------------------------------------------------------

// SyscallEventMsg wraps a BPF syscall event for the TUI update loop.
type SyscallEventMsg bpf.SyscallEvent

// TickMsg triggers a 1Hz TUI refresh.
type TickMsg time.Time

// PulseMsg triggers a 500ms heartbeat pulse animation.
type PulseMsg time.Time

// JsonSnapshotMsg triggers a state dump to disk.
type JsonSnapshotMsg struct{ Filename string }

// FlashMsg shows a temporary message in the footer.
type FlashMsg string

// ProcessExitedMsg indicates the target process has exited.
type ProcessExitedMsg struct{}

// ErrorMsg carries a fatal error to the TUI.
type ErrorMsg struct{ Err error }

// clearFlashMsg clears the flash message after the timeout.
type clearFlashMsg struct{}

// ---------------------------------------------------------------------------
// Model — bubbletea Model implementation
// ---------------------------------------------------------------------------

// Config holds runtime configuration passed to the TUI model.
type Config struct {
	PID       int
	Binary    string
	GoVersion string
	Readonly  bool
	SHA256    string
	Filter    FilterMode
	SortMode  SortMode
}

// Model is the bubbletea Model for gspy's TUI.
// It manages the goroutine table, display state, and event processing.
type Model struct {
	// Configuration (immutable after init)
	config Config

	// Table state
	table *Table

	// Window dimensions
	width  int
	height int

	// Timing
	startTime time.Time
	lastTick  time.Time
	pulse     bool // toggles every 500ms

	// UI Feedback
	flash string // temporary message in footer

	recentSyscalls map[uint64][]SyscallRecord
	showHelp       bool
	processExited  bool

	// State
	quitting bool
	err      error
}

// NewModel creates a new TUI model with the given configuration.
func NewModel(cfg Config) *Model {
	t := NewTable()
	t.Filter = cfg.Filter
	if cfg.SortMode == SortByLatency {
		t.Sort = SortByLatency
	}

	return &Model{
		config:         cfg,
		table:          t,
		width:          80,
		height:         24,
		startTime:      time.Now(),
		lastTick:       time.Now(),
		pulse:          true,
		recentSyscalls: make(map[uint64][]SyscallRecord),
	}
}

// Init initializes the model and starts the tickers.
func (m *Model) Init() tea.Cmd {
	return tea.Batch(
		tickCmd(),
		pulseCmd(),
		tea.ClearScreen,
	)
}

// tickCmd returns a tea.Cmd that fires a TickMsg every second.
func tickCmd() tea.Cmd {
	return tea.Tick(time.Second, func(t time.Time) tea.Msg {
		return TickMsg(t)
	})
}

// pulseCmd returns a tea.Cmd that fires every 500ms for animation.
func pulseCmd() tea.Cmd {
	return tea.Tick(500*time.Millisecond, func(t time.Time) tea.Msg {
		return PulseMsg(t)
	})
}

// Update handles all incoming messages and updates the model state.
func (m *Model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {

	case tea.KeyMsg:
		return m.handleKey(msg)

	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height
		m.table.Resize(msg.Width, msg.Height)
		return m, nil

	case SyscallEventMsg:
		m.handleSyscallEvent(bpf.SyscallEvent(msg))
		return m, nil

	case TickMsg:
		m.lastTick = time.Time(msg)
		m.table.Refresh()
		return m, tickCmd()

	case PulseMsg:
		m.pulse = !m.pulse
		return m, pulseCmd()

	case FlashMsg:
		m.flash = string(msg)
		return m, tea.Tick(3*time.Second, func(t time.Time) tea.Msg {
			return clearFlashMsg{}
		})

	case clearFlashMsg:
		m.flash = ""
		return m, nil

	case JsonSnapshotMsg:
		// The actual file I/O is handled by the main loop listening for this msg
		// if we were in a complex architecture, but here we can just do it or
		// let the tea.Program handle it. We'll send it up to main.
		return m, nil

	case ProcessExitedMsg:
		m.processExited = true
		return m, nil

	case ErrorMsg:
		m.err = msg.Err
		if !m.processExited {
			m.quitting = true
			return m, tea.Quit
		}
		return m, nil

	default:
		return m, nil
	}
}

// handleKey processes key press events.
func (m *Model) handleKey(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	// If help or expanded view is open, most keys return to table.
	if m.showHelp || m.table.Expanded {
		switch msg.String() {
		case "esc", "q", "?", "backspace":
			m.showHelp = false
			m.table.Expanded = false
			return m, nil
		}
		return m, nil
	}

	switch msg.String() {
	case "q", "ctrl+c":
		m.quitting = true
		return m, tea.Quit

	case "up", "k":
		m.table.MoveUp()
		return m, nil

	case "down", "j":
		m.table.MoveDown()
		return m, nil

	case "enter":
		if m.table.SelectedRow() != nil {
			m.table.Expanded = true
		}
		return m, nil

	case "f":
		m.table.CycleFilter()
		m.table.Refresh()
		return m, nil

	case "s":
		m.table.ToggleSort()
		m.table.Refresh()
		return m, nil

	case "S":
		m.table.ToggleSortDirection()
		m.table.Refresh()
		return m, nil

	case "ctrl+j":
		filename := fmt.Sprintf("gspy_dump_%d_%d.json",
			m.config.PID, time.Now().Unix())
		err := m.table.SaveSnapshot(filename)
		if err != nil {
			m.flash = fmt.Sprintf("Error: %v", err)
		} else {
			m.flash = fmt.Sprintf("Snapshot saved: %s", filename)
		}
		return m, tea.Tick(3*time.Second, func(t time.Time) tea.Msg {
			return clearFlashMsg{}
		})

	case "?":
		m.showHelp = true
		return m, nil
	}

	return m, nil
}

// handleSyscallEvent processes a BPF syscall event.
func (m *Model) handleSyscallEvent(evt bpf.SyscallEvent) {
	switch evt.EventType {
	case bpf.EventSyscall:
		syscallName := bpf.SyscallName(evt.SyscallNr)
		latencyUS := int64(evt.LatencyNs / 1000)
		frame := fmt.Sprintf("0x%x", evt.FramePC)
		// Note: frame resolution happens in the caller that feeds events.
		// The model receives pre-resolved frame names when available.

		m.table.UpdateRow(
			evt.Gid,
			syscallName,
			latencyUS,
			frame,
			evt.FramePC,
			"syscall",
		)

		// Record for expanded view (last 20 syscalls per goroutine).
		record := SyscallRecord{
			Syscall:   syscallName,
			LatencyUS: latencyUS,
			Frame:     frame,
			Timestamp: evt.Ts,
		}
		history := m.recentSyscalls[evt.Gid]
		if len(history) >= 20 {
			history = history[1:]
		}
		m.recentSyscalls[evt.Gid] = append(history, record)

	case bpf.EventGoroutineCreate:
		m.table.SetState(evt.Gid, "created")

	case bpf.EventGoroutineExit:
		m.table.MarkDead(evt.Gid)
	}
}

// View renders the current UI state.
func (m *Model) View() string {
	if m.quitting {
		if m.err != nil {
			return fmt.Sprintf("Error: %v\n", m.err)
		}
		return fmt.Sprintf("process %d exited, detaching\n", m.config.PID)
	}

	// Overlay screens.
	if m.showHelp {
		return lipgloss.Place(m.width, m.height, lipgloss.Center, lipgloss.Center,
			RenderHelp(m.width, m.height))
	}
	if m.table.Expanded {
		return m.renderExpanded()
	}

	return m.renderTable()
}

// renderTable renders the main goroutine table view.
func (m *Model) renderTable() string {
	var b strings.Builder

	// Header bar
	uptime := formatUptime(time.Since(m.startTime))
	header := RenderHeader(m.width, m.config.PID, m.config.Binary,
		m.config.GoVersion, m.table.GoroutineCount(), uptime,
		m.table.Filter, m.config.Readonly, m.config.SHA256, m.pulse)
	b.WriteString(header)
	b.WriteString("\n")

	// Column headers with sort indicator
	sortCol, sortInd := m.table.SortColumnName()
	colHeaders := RenderColumnHeaders(m.width, sortCol, sortInd)
	b.WriteString(colHeaders)
	b.WriteString("\n")

	// Table rows
	visibleRows := m.table.VisibleSlice()
	rowsRendered := 0
	maxRows := m.table.MaxVisibleRows()

	if len(visibleRows) == 0 {
		b.WriteString(RenderEmptyState(m.width, maxRows))
		rowsRendered = maxRows
	}

	for _, row := range visibleRows {
		if rowsRendered >= maxRows {
			break
		}
		// Check if this row is the selected row by pointer.
		selected := (row == m.table.SelectedRow())

		b.WriteString(RenderRow(row, m.width, selected))
		b.WriteString("\n")
		rowsRendered++
	}

	// Pad remaining rows
	for rowsRendered < maxRows {
		b.WriteString(strings.Repeat(" ", m.width))
		b.WriteString("\n")
		rowsRendered++
	}

	// Footer
	footer := m.flash
	if footer == "" {
		footer = " q:quit  cr:expand  f:filter  s:sort  ŝ:order  ^j:dump  ?:help"
	}
	b.WriteString(RenderFooter(m.width, footer, m.processExited))

	return b.String()
}

// renderExpanded renders the expanded goroutine detail view.
func (m *Model) renderExpanded() string {
	row := m.table.SelectedRow()
	if row == nil {
		m.table.Expanded = false
		return m.renderTable()
	}

	history := m.recentSyscalls[row.GID]

	// Stack frames would come from process_vm_readv — use placeholder.
	var stackFrames []string
	if row.Frame != "" && row.Frame != "<unknown>" {
		stackFrames = []string{row.Frame}
	}

	return RenderExpanded(row, m.width, m.height, stackFrames, history)
}

// formatUptime formats a duration to a concise string like "2m30s".
func formatUptime(d time.Duration) string {
	if d < time.Minute {
		return fmt.Sprintf("%ds", int(d.Seconds()))
	}
	if d < time.Hour {
		return fmt.Sprintf("%dm%ds",
			int(d.Minutes()), int(d.Seconds())%60)
	}
	return fmt.Sprintf("%dh%dm",
		int(d.Hours()), int(d.Minutes())%60)
}

// GetTable returns the table for external access (testing).
func (m *Model) GetTable() *Table {
	return m.table
}
