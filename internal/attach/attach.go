// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2024 Mutasem Kharma <mutasem@gspy.dev>

// Package attach handles process validation, capability checking,
// kernel version verification, and the overall attachment sequence
// for gspy's eBPF-based tracing.
package attach

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
)

// ProcPath is the path to the proc filesystem.
// Override in tests to use a mock /proc directory.
var ProcPath = "/proc"

// ProcessInfo holds resolved information about the target process.
type ProcessInfo struct {
	PID        int
	BinaryPath string
	GoVersion  string
	GIDOffset  uint64
}

// ValidatePID checks that the given PID refers to a running process.
// Returns an error for invalid PIDs (<=0) or nonexistent processes.
func ValidatePID(pid int) error {
	if pid <= 0 {
		return fmt.Errorf("invalid PID %d: must be a positive integer", pid)
	}

	procDir := filepath.Join(ProcPath, strconv.Itoa(pid))
	fi, err := os.Stat(procDir)
	if err != nil {
		if os.IsNotExist(err) {
			return fmt.Errorf("process %d not found: no such process", pid)
		}
		return fmt.Errorf("checking process %d: %w", pid, err)
	}
	if !fi.IsDir() {
		return fmt.Errorf("process %d not found: %s is not a directory",
			pid, procDir)
	}

	return nil
}

// ResolveBinaryPath reads /proc/<pid>/exe to find the target binary path.
func ResolveBinaryPath(pid int) (string, error) {
	exeLink := filepath.Join(ProcPath, strconv.Itoa(pid), "exe")
	target, err := os.Readlink(exeLink)
	if err != nil {
		return "", fmt.Errorf("reading /proc/%d/exe: %w", pid, err)
	}
	// Check that the resolved path actually exists.
	if _, err := os.Stat(target); err != nil {
		return "", fmt.Errorf("target binary %s: %w", target, err)
	}
	return target, nil
}

// EnumerateTIDs returns all thread IDs for the given process by reading
// /proc/<pid>/task/.
func EnumerateTIDs(pid int) ([]int, error) {
	taskDir := filepath.Join(ProcPath, strconv.Itoa(pid), "task")
	entries, err := os.ReadDir(taskDir)
	if err != nil {
		return nil, fmt.Errorf("reading /proc/%d/task: %w", pid, err)
	}

	tids := make([]int, 0, len(entries))
	for _, e := range entries {
		tid, err := strconv.Atoi(e.Name())
		if err != nil {
			continue // skip non-numeric entries
		}
		tids = append(tids, tid)
	}

	if len(tids) == 0 {
		return nil, fmt.Errorf("no threads found for process %d", pid)
	}

	return tids, nil
}

// CAP_BPF is Linux capability bit 39. Added in Linux 5.8.
const capBPF = 39

// CAP_PERFMON is Linux capability bit 38. Added in Linux 5.8.
const capPERFMON = 38

// CAP_SYS_ADMIN is Linux capability bit 21.
const capSYS_ADMIN = 21

// CheckCapabilities verifies that the current process has the required
// capabilities for BPF operations.
//
// Required: (CAP_BPF + CAP_PERFMON) OR CAP_SYS_ADMIN.
//
// Reads CapEff from /proc/self/status and checks the capability bitfield.
// On non-Linux platforms or if /proc is unavailable, returns a descriptive error.
func CheckCapabilities() error {
	if runtime.GOOS != "linux" {
		return fmt.Errorf("gspy requires Linux (current OS: %s)", runtime.GOOS)
	}

	statusPath := filepath.Join(ProcPath, "self", "status")
	capEff, err := readCapEff(statusPath)
	if err != nil {
		return fmt.Errorf("reading capabilities: %w", err)
	}

	hasBPF := (capEff & (1 << capBPF)) != 0
	hasPerfmon := (capEff & (1 << capPERFMON)) != 0
	hasSysAdmin := (capEff & (1 << capSYS_ADMIN)) != 0

	if (hasBPF && hasPerfmon) || hasSysAdmin {
		return nil
	}

	return fmt.Errorf(
		"insufficient privileges to attach eBPF probes.\n" +
			"gspy requires CAP_BPF and CAP_PERFMON (Linux 5.8+).\n\n" +
			"FIX: Run as root (sudo) or grant capabilities:\n" +
			"  sudo setcap cap_bpf,cap_perfmon+ep $(which gspy)")
}

// readCapEff reads the CapEff line from the given /proc/self/status path
// and returns it as a uint64 bitmask.
func readCapEff(statusPath string) (uint64, error) {
	f, err := os.Open(statusPath)
	if err != nil {
		return 0, fmt.Errorf("opening %s: %w", statusPath, err)
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		if !strings.HasPrefix(line, "CapEff:") {
			continue
		}

		// Line format: "CapEff:\t000001ffffffffff"
		fields := strings.Fields(line)
		if len(fields) < 2 {
			return 0, fmt.Errorf("malformed CapEff line: %q", line)
		}

		val, err := strconv.ParseUint(fields[1], 16, 64)
		if err != nil {
			return 0, fmt.Errorf("parsing CapEff value %q: %w",
				fields[1], err)
		}
		return val, nil
	}

	if err := scanner.Err(); err != nil {
		return 0, fmt.Errorf("reading %s: %w", statusPath, err)
	}

	return 0, fmt.Errorf("CapEff not found in %s", statusPath)
}

// CheckKernelVersion verifies that the running kernel is >= 5.8.
// BPF ring buffer support was added in Linux 5.8.
func CheckKernelVersion() error {
	if runtime.GOOS != "linux" {
		return fmt.Errorf("gspy requires Linux (current OS: %s)", runtime.GOOS)
	}

	major, minor, err := readKernelVersion()
	if err != nil {
		return fmt.Errorf("reading kernel version: %w", err)
	}

	if major < 5 || (major == 5 && minor < 8) {
		return fmt.Errorf(
			"unsupported kernel version %d.%d.\n\n"+
				"gspy requires Linux >= 5.8 for BPF ring buffer support.\n"+
				"Please upgrade your kernel or check if BPF is enabled (CONFIG_BPF=y).", major, minor)
	}

	return nil
}

// readKernelVersion reads /proc/version and extracts the major.minor version.
func readKernelVersion() (int, int, error) {
	versionPath := filepath.Join(ProcPath, "version")
	data, err := os.ReadFile(versionPath)
	if err != nil {
		return 0, 0, fmt.Errorf("reading %s: %w", versionPath, err)
	}

	// Format: "Linux version 5.15.0-91-generic (...)""
	fields := strings.Fields(string(data))
	if len(fields) < 3 {
		return 0, 0, fmt.Errorf("unexpected /proc/version format: %q",
			string(data))
	}

	version := fields[2]
	parts := strings.SplitN(version, ".", 3)
	if len(parts) < 2 {
		return 0, 0, fmt.Errorf("cannot parse kernel version %q", version)
	}

	major, err := strconv.Atoi(parts[0])
	if err != nil {
		return 0, 0, fmt.Errorf("parsing major version %q: %w", parts[0], err)
	}

	// Minor may contain non-numeric suffix (e.g. "15" from "5.15.0-91")
	minorStr := parts[1]
	// Strip any trailing non-digit characters
	for i, c := range minorStr {
		if c < '0' || c > '9' {
			minorStr = minorStr[:i]
			break
		}
	}

	minor, err := strconv.Atoi(minorStr)
	if err != nil {
		return 0, 0, fmt.Errorf("parsing minor version %q: %w", parts[1], err)
	}

	return major, minor, nil
}

// CheckPerfEventParanoid reads /proc/sys/kernel/perf_event_paranoid and
// warns if the value is > 2.
func CheckPerfEventParanoid() (int, error) {
	path := filepath.Join(ProcPath, "sys", "kernel", "perf_event_paranoid")
	data, err := os.ReadFile(path)
	if err != nil {
		return 0, fmt.Errorf("reading %s: %w", path, err)
	}

	val, err := strconv.Atoi(strings.TrimSpace(string(data)))
	if err != nil {
		return 0, fmt.Errorf("parsing perf_event_paranoid: %w", err)
	}

	return val, nil
}

// CheckProcessAlive verifies that the target process is still running.
func CheckProcessAlive(pid int) bool {
	procDir := filepath.Join(ProcPath, strconv.Itoa(pid))
	_, err := os.Stat(procDir)
	return err == nil
}
