// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2024 Mutasem Kharma <mutasem@gspy.dev>

package ui

import (
	"fmt"
	"strings"

	"github.com/charmbracelet/lipgloss"
)

// ---------------------------------------------------------------------------
// Styles — High-fidelity TrueColor (24-bit) theme
// ---------------------------------------------------------------------------

var (
	// Palette
	colTeal   = lipgloss.Color("#00FFD1") // Active accent
	colGold   = lipgloss.Color("#FFB800") // Warnings/Syscall
	colRed    = lipgloss.Color("#FF0055") // High latency/Panic
	colDim    = lipgloss.Color("#5C6370") // Faint/Dead
	colGreen  = lipgloss.Color("#A6E22E") // Running
	colPurple = lipgloss.Color("#BD93F9") // Selection accent

	// headerStyle: bold reverse for the header bar with Teal accent.
	headerStyle = lipgloss.NewStyle().
			Bold(true).
			Background(colTeal).
			Foreground(lipgloss.Color("#000000"))

	// footerStyle: dim text for the footer help bar.
	footerStyle = lipgloss.NewStyle().
			Foreground(colDim)

	// selectedStyle: vibrant selection bar.
	selectedStyle = lipgloss.NewStyle().
			Background(colPurple).
			Foreground(lipgloss.Color("#000000")).
			Bold(true)

	// columnHeaderStyle: bold underlines for column headers.
	columnHeaderStyle = lipgloss.NewStyle().
				Bold(true).
				Foreground(colTeal).
				Underline(true)

	// redStyle: high alert for latency > 100ms.
	redStyle = lipgloss.NewStyle().
			Foreground(colRed).
			Bold(true)

	// yellowStyle: gold for "syscall" state.
	yellowStyle = lipgloss.NewStyle().
			Foreground(colGold)

	// dimStyle: faint text for "dead" state.
	dimStyle = lipgloss.NewStyle().
			Foreground(colDim)

	// greenStyle: vibrant green for "running" state.
	greenStyle = lipgloss.NewStyle().
			Foreground(colGreen)

	// expandedTitleStyle: bold for expanded view title.
	expandedTitleStyle = lipgloss.NewStyle().
				Bold(true).
				Foreground(colTeal).
				Background(lipgloss.Color("#24283B")).
				Padding(0, 1)

	// expandedBorderStyle: for the expanded view overlay border.
	expandedBorderStyle = lipgloss.NewStyle().
				Border(lipgloss.ThickBorder()).
				BorderForeground(colTeal).
				Padding(0, 1)

	// liveIndicatorStyle: pulsating teal/dim dot.
	liveIndicatorStyle = lipgloss.NewStyle().
				Bold(true)
)

// ---------------------------------------------------------------------------
// Column widths — designed for 80-column minimum
// ---------------------------------------------------------------------------
//
// Layout:  GID(8) STATE(8) SYSCALL(14) LATENCY(10) COUNT(8) FRAME(remaining)
//          8 + 8 + 14 + 10 + 8 + 2(min) + 5(separators) = 55 minimum
//          At 80 cols: FRAME gets ~25 chars

const (
	colGID     = 8
	colState   = 8
	colSyscall = 14
	colLatency = 10
	colCount   = 8
	colSep     = 1 // space between columns
)

// ---------------------------------------------------------------------------
// Render functions
// ---------------------------------------------------------------------------

// RenderHeader renders the top header bar.
// Left:  "gspy  pid:<PID>  binary:<name>  go:<version>"
// Right: "goroutines:<N>  attached:<duration>  ● LIVE"
func RenderHeader(width int, pid int, binary string, goVersion string,
	goroutines int, uptime string, filter FilterMode,
	readonly bool, sha256 string, pulse bool) string {

	left := fmt.Sprintf(" GSPY [%d]  %s  %s",
		pid, truncate(binary, 25), goVersion)

	indicator := liveIndicatorStyle.Foreground(colDim).Render("●")
	if pulse {
		indicator = liveIndicatorStyle.Foreground(colGreen).Render("●")
	}

	right := fmt.Sprintf("G:%d  %s  %s LIVE ",
		goroutines, uptime, indicator)

	// Add filter indicator
	if filter != FilterAll {
		left += fmt.Sprintf("   %s", filter)
	}

	// Add readonly indicator
	if readonly {
		shaShort := sha256
		if len(shaShort) > 12 {
			shaShort = shaShort[:12]
		}
		left += fmt.Sprintf("  [FORENSIC:%s]", shaShort)
	}

	// Pad to fill width
	pad := width - lipgloss.Width(left) - lipgloss.Width(right)
	if pad < 0 {
		pad = 0
	}

	line := left + strings.Repeat(" ", pad) + right

	return headerStyle.Width(width).Render(line)
}

// RenderEmptyState renders a placeholder when the table is empty.
func RenderEmptyState(width, height int) string {
	msg := " Scanning for active goroutines... \n (Check if the process is a Go binary) "
	styled := columnHeaderStyle.Padding(1, 2).Render(msg)

	lines := strings.Split(styled, "\n")
	var b strings.Builder
	// Center vertically
	for i := 0; i < (height/2)-2; i++ {
		_, _ = b.WriteString("\n")
	}
	for _, l := range lines {
		pad := (width - lipgloss.Width(l)) / 2
		if pad < 0 {
			pad = 0
		}
		_, _ = b.WriteString(strings.Repeat(" ", pad) + l + "\n")
	}
	return b.String()
}

// RenderColumnHeaders renders the column header row with sort indicator.
func RenderColumnHeaders(width int, sortCol string, sortIndicator string) string {
	frameWidth := width - colGID - colState - colSyscall - colLatency -
		colCount - 5*colSep
	if frameWidth < 2 {
		frameWidth = 2
	}

	gid := padRight("GID", colGID)
	state := padRight("STATE", colState)
	syscall := padRight("SYSCALL", colSyscall)
	latency := padRight("LATENCY", colLatency)
	count := padRight("COUNT", colCount)
	frame := padRight("FRAME", frameWidth)

	// Add sort indicator to the appropriate column.
	switch sortCol {
	case "GID":
		gid = padRight("GID"+sortIndicator, colGID)
	case "COUNT":
		count = padRight("COUNT"+sortIndicator, colCount)
	case "LATENCY":
		latency = padRight("LATENCY"+sortIndicator, colLatency)
	}

	line := gid + " " + state + " " + syscall + " " + latency + " " +
		count + " " + frame

	return columnHeaderStyle.Render(line)
}

// RenderRow renders a single goroutine row.
func RenderRow(row *GoroutineRow, width int, selected bool) string {
	frameWidth := width - colGID - colState - colSyscall - colLatency -
		colCount - 5*colSep
	if frameWidth < 2 {
		frameWidth = 2
	}

	gid := padRight(fmt.Sprintf("%d", row.GID), colGID)
	state := renderState(row.State, colState)
	syscall := padRight(truncate(row.Syscall, colSyscall), colSyscall)
	latency := renderLatency(row.LatencyUS, colLatency)
	count := padRight(fmt.Sprintf("%d", row.Count), colCount)
	frame := padRight(truncate(row.Frame, frameWidth), frameWidth)

	line := gid + " " + state + " " + syscall + " " + latency + " " +
		count + " " + frame

	if selected {
		return selectedStyle.Render(line)
	}

	// Dim entire row if goroutine is dead.
	if row.State == "dead" {
		return dimStyle.Render(line)
	}

	return line
}

// RenderFooter renders the bottom help bar.
func RenderFooter(width int, text string, processExited bool) string {
	if processExited {
		text = " 󱇰 PROCESS EXITED. Final trace snapshot. Press Q to exit. "
		return headerStyle.Background(colRed).Width(width).Render(text)
	}
	if len(text) > width {
		text = text[:width]
	}
	return footerStyle.Width(width).Render(text)
}

// RenderHelp renders the help overlay.
func RenderHelp(width, height int) string {
	var b strings.Builder
	_, _ = b.WriteString(expandedTitleStyle.Render(" gspy Keybindings "))
	_, _ = b.WriteString("\n\n")

	keys := [][]string{
		{"q / ctrl+c", "Quit gspy"},
		{"j / k", "Navigate table"},
		{"enter", "Expand goroutine history"},
		{"esc / q", "Close expanded view / help"},
		{"f", "Cycle filter (IO/Net/Sched/All)"},
		{"s", "Toggle Sort (Count/Latency)"},
		{"S", "Toggle Sort Order (Asc/Desc)"},
		{"ctrl+j", "Save JSON snapshot to disk"},
		{"?", "Show/Hide this help screen"},
	}

	for _, k := range keys {
		_, _ = b.WriteString(fmt.Sprintf("  %-12s  %s\n", k[0], k[1]))
	}

	_, _ = b.WriteString("\n")
	_, _ = b.WriteString(dimStyle.Render(" Press any key to close "))

	content := b.String()
	if width > 40 && height > 15 {
		return expandedBorderStyle.Padding(1, 4).Render(content)
	}
	return content
}

// RenderExpanded renders the full-screen expanded goroutine view.
// Top half: full user-space stack trace.
// Bottom half: last 20 syscalls with timestamps and latency.
func RenderExpanded(row *GoroutineRow, width, height int,
	stackFrames []string, recentSyscalls []SyscallRecord) string {

	var b strings.Builder

	// Title
	title := fmt.Sprintf("Goroutine %d — %s", row.GID, row.State)
	_, _ = b.WriteString(expandedTitleStyle.Render(title))
	_, _ = b.WriteString("\n\n")

	// Top half: stack trace
	_, _ = b.WriteString(columnHeaderStyle.Render("Stack Trace:"))
	_, _ = b.WriteString("\n")

	if len(stackFrames) == 0 {
		_, _ = b.WriteString(dimStyle.Render("  (no stack frames available)"))
		_, _ = b.WriteString("\n")
	} else {
		maxFrames := (height - 8) / 2
		if maxFrames < 4 {
			maxFrames = 4
		}
		for i, frame := range stackFrames {
			if i >= maxFrames {
				_, _ = b.WriteString(dimStyle.Render(
					fmt.Sprintf("  ... %d more frames", len(stackFrames)-i)))
				_, _ = b.WriteString("\n")
				break
			}
			prefix := "  "
			if i == 0 {
				prefix = "→ "
			}
			line := fmt.Sprintf("%s#%d %s", prefix, i, frame)
			if len(line) > width-2 {
				line = line[:width-5] + "..."
			}
			_, _ = b.WriteString(line)
			_, _ = b.WriteString("\n")
		}
	}

	_, _ = b.WriteString("\n")

	// Bottom half: recent syscalls
	_, _ = b.WriteString(columnHeaderStyle.Render("Recent Syscalls:"))
	_, _ = b.WriteString("\n")

	header := fmt.Sprintf("  %-14s %-12s %s", "SYSCALL", "LATENCY", "FRAME")
	_, _ = b.WriteString(dimStyle.Render(header))
	_, _ = b.WriteString("\n")

	if len(recentSyscalls) == 0 {
		_, _ = b.WriteString(dimStyle.Render("  (no syscalls recorded)"))
		_, _ = b.WriteString("\n")
	} else {
		maxSyscalls := (height - 8) / 2
		if maxSyscalls < 4 {
			maxSyscalls = 4
		}
		if maxSyscalls > 20 {
			maxSyscalls = 20
		}
		start := len(recentSyscalls) - maxSyscalls
		if start < 0 {
			start = 0
		}
		for _, sc := range recentSyscalls[start:] {
			latStr := formatLatency(sc.LatencyUS)
			line := fmt.Sprintf("  %-14s %-12s %s",
				truncate(sc.Syscall, 14),
				latStr,
				truncate(sc.Frame, width-32))
			if len(line) > width-2 {
				line = line[:width-5] + "..."
			}

			if sc.LatencyUS > 100000 { // > 100ms
				_, _ = b.WriteString(redStyle.Render(line))
			} else {
				_, _ = b.WriteString(line)
			}
			_, _ = b.WriteString("\n")
		}
	}

	_, _ = b.WriteString("\n")
	_, _ = b.WriteString(dimStyle.Render("  ESC to return"))

	content := b.String()

	// Wrap in border if space allows.
	if width > 10 && height > 10 {
		return expandedBorderStyle.Width(width - 4).Render(content)
	}
	return content
}

// SyscallRecord is a single syscall in the expanded view's history.
type SyscallRecord struct {
	Syscall   string
	LatencyUS int64
	Frame     string
	Timestamp uint64
}

// ---------------------------------------------------------------------------
// Formatting helpers
// ---------------------------------------------------------------------------

// renderState renders the goroutine state with appropriate ANSI color.
func renderState(state string, width int) string {
	padded := padRight(state, width)
	switch state {
	case "running":
		return greenStyle.Render(padded)
	case "syscall":
		return yellowStyle.Render(padded)
	case "dead":
		return dimStyle.Render(padded)
	default:
		return padded
	}
}

// renderLatency renders latency with red color if > 100ms.
func renderLatency(latencyUS int64, width int) string {
	str := formatLatency(latencyUS)
	padded := padRight(str, width)
	if latencyUS > 100000 { // > 100ms
		return redStyle.Render(padded)
	}
	return padded
}

// formatLatency formats a microsecond latency value to human-readable form.
func formatLatency(us int64) string {
	if us <= 0 {
		return "-"
	}
	if us < 1000 {
		return fmt.Sprintf("%dµs", us)
	}
	if us < 1000000 {
		return fmt.Sprintf("%.1fms", float64(us)/1000.0)
	}
	return fmt.Sprintf("%.1fs", float64(us)/1000000.0)
}

func truncate(s string, maxLen int) string {
	if maxLen <= 0 {
		return ""
	}
	if len(s) <= maxLen {
		return s
	}

	// Smart truncation for Go symbols: github.com/foo/bar.Function -> …bar.Function
	// Only apply if we have enough space to make it look decent.
	if maxLen > 10 && strings.Contains(s, ".") {
		parts := strings.Split(s, "/")
		if len(parts) > 1 {
			short := "…" + parts[len(parts)-1]
			if len(short) <= maxLen {
				return short
			}
		}
	}

	// Default fallback: truncate at start and append ellipse.
	return s[:maxLen-1] + "…"
}

// padRight pads a string to the given width with spaces.
func padRight(s string, width int) string {
	if len(s) >= width {
		return s[:width]
	}
	return s + strings.Repeat(" ", width-len(s))
}
