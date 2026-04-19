// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2024 Mutasem Kharma <mutasem@gspy.dev>

// gspy — forensic goroutine-to-syscall inspector for live Go processes.
//
// Usage:
//
//	gspy <pid>                  Attach, show live goroutine→syscall TUI
//	gspy <pid> --top            Sort by syscall frequency (default)
//	gspy <pid> --latency        Sort by highest current syscall latency
//	gspy <pid> --filter <mode>  Filter: io | net | sched | all (default: all)
//	gspy <pid> --readonly       Forensic mode: zero writes, log SHA-256
//	gspy <pid> --json           Emit newline-delimited JSON to stdout
//	gspy <pid> --debug          Show BPF verifier log and map stats
//	gspy --version              Show version block
//	gspy --help                 Show usage
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/mutasemkharma/gspy/internal/attach"
	"github.com/mutasemkharma/gspy/internal/bpf"
	"github.com/mutasemkharma/gspy/internal/proc"
	"github.com/mutasemkharma/gspy/internal/ui"
)

// Build-time variables set via -ldflags.
var (
	Version        = "0.1.0"
	BuildGoVersion = "unknown"
)

// Exit codes.
const (
	exitOK           = 0
	exitFatal        = 1
	exitKernelOld    = 2
	exitInterrupted  = 130
)

func main() {
	// Recover from unexpected panics — log and exit cleanly.
	defer func() {
		if r := recover(); r != nil {
			fmt.Fprintf(os.Stderr, "gspy: fatal panic: %v\n", r)
			os.Exit(exitFatal)
		}
	}()

	os.Exit(run())
}

func run() int {
	// ── Flag parsing ────────────────────────────────────────────
	var (
		flagTop      = flag.Bool("top", false, "Sort by syscall count (default)")
		flagLatency  = flag.Bool("latency", false, "Sort by highest syscall latency")
		flagFilter   = flag.String("filter", "all", "Filter: io | net | sched | all")
		flagReadonly = flag.Bool("readonly", false, "Forensic mode: zero writes, log SHA-256")
		flagJSON     = flag.Bool("json", false, "Emit newline-delimited JSON to stdout")
		flagDebug    = flag.Bool("debug", false, "Show BPF verifier log and map stats")
		flagVersion  = flag.Bool("version", false, "Show version information")
	)

	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, `gspy — forensic goroutine-to-syscall inspector for live Go processes

USAGE:
  gspy <pid>                  Attach, show live goroutine→syscall TUI
  gspy <pid> --top            Sort by syscall frequency (default)
  gspy <pid> --latency        Sort by highest current syscall latency
  gspy <pid> --filter <mode>  Filter: io | net | sched | all (default: all)
  gspy <pid> --readonly       Forensic mode: zero writes, log SHA-256
  gspy <pid> --json           Emit newline-delimited JSON to stdout
  gspy <pid> --debug          Show BPF verifier log and map stats
  gspy --version              Show version block
  gspy --help                 Show usage

OPTIONS:
`)
		flag.PrintDefaults()
		fmt.Fprintf(os.Stderr, `
CAPABILITIES:
  Requires CAP_BPF + CAP_PERFMON (or CAP_SYS_ADMIN). Run as root, or grant:
    sudo setcap cap_bpf,cap_perfmon+ep $(which gspy)

KERNEL:
  Requires Linux >= 5.8 (BPF ring buffer support).

SUPPORTED GO VERSIONS:
  %s
`, attach.SupportedGoVersionRange())
	}

	flag.Parse()

	// ── Version output ──────────────────────────────────────────
	if *flagVersion {
		printVersion()
		return exitOK
	}

	// ── PID argument ────────────────────────────────────────────
	args := flag.Args()
	if len(args) < 1 {
		fmt.Fprintf(os.Stderr, "gspy: missing required argument: <pid>\n")
		fmt.Fprintf(os.Stderr, "Usage: gspy <pid> [options]\n")
		fmt.Fprintf(os.Stderr, "Run 'gspy --help' for full usage.\n")
		return exitFatal
	}

	pid, err := strconv.Atoi(args[0])
	if err != nil {
		fmt.Fprintf(os.Stderr, "gspy: invalid PID %q: %v\n", args[0], err)
		return exitFatal
	}

	// ── Validate filter ─────────────────────────────────────────
	filter := ui.FilterMode(strings.ToLower(*flagFilter))
	switch filter {
	case ui.FilterAll, ui.FilterIO, ui.FilterNet, ui.FilterSched:
		// valid
	default:
		fmt.Fprintf(os.Stderr, "gspy: invalid filter %q (use: all, io, net, sched)\n",
			*flagFilter)
		return exitFatal
	}

	// ── Determine sort mode ─────────────────────────────────────
	sortMode := ui.SortByCount
	if *flagLatency {
		sortMode = ui.SortByLatency
	}
	_ = flagTop // --top is the default

	// ── Step 1: Validate PID ────────────────────────────────────
	if err := attach.ValidatePID(pid); err != nil {
		fmt.Fprintf(os.Stderr, "gspy: %v\n", err)
		return exitFatal
	}

	// ── Step 2: Resolve binary path ─────────────────────────────
	binaryPath, err := attach.ResolveBinaryPath(pid)
	if err != nil {
		fmt.Fprintf(os.Stderr, "gspy: %v\n", err)
		return exitFatal
	}

	// ── Step 3: Enumerate threads ───────────────────────────────
	tids, err := attach.EnumerateTIDs(pid)
	if err != nil {
		fmt.Fprintf(os.Stderr, "gspy: warning: %v\n", err)
		// Non-fatal: continue without thread enumeration.
	}
	_ = tids // used for informational purposes

	// ── Step 4: Detect Go version and GID offset ────────────────
	goVersion, err := attach.DetectGoVersion(binaryPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "gspy: warning: could not detect Go version: %v\n", err)
		fmt.Fprintf(os.Stderr, "gspy: assuming default goid offset %d\n",
			attach.DefaultGIDOffset)
		goVersion = "unknown"
	}

	gidOffset, warning := attach.GetGIDOffset(binaryPath, goVersion)
	if warning != "" {
		fmt.Fprintf(os.Stderr, "gspy: %s\n", warning)
	}

	// ── Step 5: Readonly mode — SHA-256 ─────────────────────────
	var sha256Hash string
	if *flagReadonly {
		sha256Hash, err = attach.ComputeSHA256(binaryPath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "gspy: warning: SHA-256 computation failed: %v\n", err)
		} else {
			fmt.Fprintf(os.Stderr, "READONLY MODE: no writes to target process memory\n")
			fmt.Fprintf(os.Stderr, "SHA-256(%s): %s\n", binaryPath, sha256Hash)
		}
	}

	// ── Step 6: Check capabilities ──────────────────────────────
	if err := attach.CheckCapabilities(); err != nil {
		fmt.Fprintf(os.Stderr, "gspy: %v\n", err)
		return exitFatal
	}

	// ── Step 7: Check kernel version ────────────────────────────
	if err := attach.CheckKernelVersion(); err != nil {
		fmt.Fprintf(os.Stderr, "gspy: %v\n", err)
		return exitKernelOld
	}

	// ── Step 8: Check perf_event_paranoid ────────────────────────
	paranoid, err := attach.CheckPerfEventParanoid()
	if err != nil {
		fmt.Fprintf(os.Stderr, "gspy: warning: could not read perf_event_paranoid: %v\n", err)
	} else if paranoid > 2 {
		fmt.Fprintf(os.Stderr,
			"gspy: warning: perf_event_paranoid=%d (> 2), BPF may fail. "+
				"Consider: sudo sysctl kernel.perf_event_paranoid=2\n", paranoid)
	}

	// ── Step 9: Load BPF programs ───────────────────────────────
	mgr := bpf.NewManager()
	if err := mgr.LoadAndAttach(pid, binaryPath, gidOffset); err != nil {
		fmt.Fprintf(os.Stderr, "gspy: BPF load/attach failed: %v\n", err)
		if *flagDebug {
			fmt.Fprintf(os.Stderr, "\n%s\n", mgr.DebugInfo())
		}
		return exitFatal
	}
	defer mgr.Close()

	if *flagDebug {
		fmt.Fprintf(os.Stderr, "%s\n", mgr.DebugInfo())
	}

	// ── Step 10: Set up symbol resolution ───────────────────────
	cache := proc.NewSymbolCache(10000)
	resolver, err := proc.NewFrameResolver(binaryPath, cache)
	if err != nil {
		fmt.Fprintf(os.Stderr, "gspy: warning: symbol resolution limited: %v\n", err)
	}

	// ── Step 11: Set up signal handling and context ──────────────
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		<-sigCh
		cancel()
	}()

	// ── Step 12: Monitor target process liveness ────────────────
	go func() {
		ticker := time.NewTicker(500 * time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				if !attach.CheckProcessAlive(pid) {
					fmt.Fprintf(os.Stderr, "process %d exited, detaching\n", pid)
					cancel()
					return
				}
			}
		}
	}()

	// ── Step 13: Run in JSON or TUI mode ────────────────────────
	if *flagJSON {
		return runJSON(ctx, mgr, resolver, pid, *flagReadonly)
	}

	return runTUI(ctx, cancel, mgr, resolver, pid, binaryPath, goVersion,
		sha256Hash, *flagReadonly, filter, sortMode)
}

// runJSON runs the JSON output mode.
// Emits one JSON object per line per syscall event. No TUI.
func runJSON(ctx context.Context, mgr bpf.Manager,
	resolver *proc.FrameResolver, pid int, readonly bool) int {

	enc := json.NewEncoder(os.Stdout)

	exitCode := exitOK
	err := mgr.PollEvents(ctx, func(evt bpf.SyscallEvent) {
		if evt.EventType != bpf.EventSyscall {
			return
		}

		frame := resolver.Resolve(evt.FramePC)
		if resolver != nil {
			frame = resolver.Resolve(evt.FramePC)
		}

		obj := struct {
			Ts        float64 `json:"ts"`
			PID       int     `json:"pid"`
			GID       uint64  `json:"gid"`
			TID       uint32  `json:"tid"`
			State     string  `json:"state"`
			Syscall   string  `json:"syscall"`
			LatencyUS int64   `json:"latency_us"`
			Count     int64   `json:"count"`
			Frame     string  `json:"frame"`
			Readonly  bool    `json:"readonly,omitempty"`
		}{
			Ts:        float64(evt.Ts) / 1e9,
			PID:       pid,
			GID:       evt.Gid,
			TID:       evt.Tid,
			State:     "syscall",
			Syscall:   bpf.SyscallName(evt.SyscallNr),
			LatencyUS: int64(evt.LatencyNs / 1000),
			Frame:     frame,
		}

		if readonly {
			obj.Readonly = true
		}

		if err := enc.Encode(obj); err != nil {
			// stdout closed (pipe broken), exit gracefully.
			return
		}
	})

	if err != nil && ctx.Err() == nil {
		fmt.Fprintf(os.Stderr, "gspy: polling error: %v\n", err)
		exitCode = exitFatal
	}

	// Check if we were interrupted by SIGINT.
	if ctx.Err() != nil {
		exitCode = exitInterrupted
	}

	return exitCode
}

// runTUI runs the interactive TUI mode.
func runTUI(ctx context.Context, cancel context.CancelFunc,
	mgr bpf.Manager, resolver *proc.FrameResolver,
	pid int, binaryPath string, goVersion string,
	sha256 string, readonly bool,
	filter ui.FilterMode, sortMode ui.SortMode) int {

	// Create TUI model.
	cfg := ui.Config{
		PID:       pid,
		Binary:    binaryPath,
		GoVersion: goVersion,
		Readonly:  readonly,
		SHA256:    sha256,
		Filter:    filter,
		SortMode:  sortMode,
	}
	model := ui.NewModel(cfg)

	// Create bubbletea program.
	p := tea.NewProgram(model,
		tea.WithAltScreen(),
		tea.WithMouseCellMotion(),
	)

	// Start BPF event polling goroutine.
	// Events are sent to the TUI as SyscallEventMsg.
	go func() {
		defer func() {
			if r := recover(); r != nil {
				fmt.Fprintf(os.Stderr, "gspy: event poller panic: %v\n", r)
				p.Send(ui.ErrorMsg{Err: fmt.Errorf("event poller panic: %v", r)})
			}
		}()

		err := mgr.PollEvents(ctx, func(evt bpf.SyscallEvent) {
			// Resolve frame symbol before sending to TUI.
			if evt.FramePC != 0 && resolver != nil {
				// We can't modify the evt struct to store the resolved name,
				// so the TUI model will resolve it via FramePC.
				// For efficiency, pre-populate the cache.
				resolver.Resolve(evt.FramePC)
			}
			p.Send(ui.SyscallEventMsg(evt))
		})

		if err != nil && ctx.Err() == nil {
			p.Send(ui.ErrorMsg{Err: err})
		}
	}()

	// Start process liveness monitor for TUI notification.
	go func() {
		ticker := time.NewTicker(500 * time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				if !attach.CheckProcessAlive(pid) {
					p.Send(ui.ProcessExitedMsg{})
					cancel()
					return
				}
			}
		}
	}()

	// Run TUI.
	finalModel, err := p.Run()
	if err != nil {
		fmt.Fprintf(os.Stderr, "gspy: TUI error: %v\n", err)
		return exitFatal
	}

	// Check final state.
	if m, ok := finalModel.(*ui.Model); ok {
		_ = m // could inspect for exit reason
	}

	// If context was cancelled by SIGINT, return 130.
	if ctx.Err() != nil {
		return exitInterrupted
	}

	return exitOK
}

// printVersion displays version information.
func printVersion() {
	fmt.Printf("gspy %s\n", Version)
	fmt.Printf("  license:          GPL-2.0-only\n")
	fmt.Printf("  built with:       %s %s/%s\n",
		BuildGoVersion, runtime.GOOS, runtime.GOARCH)
	fmt.Printf("  ebpf backend:     cilium/ebpf v0.14.0\n")
	fmt.Printf("  kernel required:  >= 5.8 (BPF ring buffer)\n")
	fmt.Printf("  go runtimes:      %s\n", attach.SupportedGoVersionRange())
	fmt.Printf("  capabilities:     CAP_BPF + CAP_PERFMON  (or CAP_SYS_ADMIN)\n")
}
