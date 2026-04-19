# gspy Submission Metadata (v0.1.0)

This document contains the standardized metadata for submitting `gspy` to security distributions.

## 🏺 General Metadata
- **Project Name**: gspy
- **Tagline**: Forensic goroutine-to-syscall inspector for live Go processes.
- **Repository**: https://github.com/mutasem_mk4/gspy
- **License**: GPL-2.0-only
- **Version**: 0.1.0
- **Supported OS**: Linux (Kernel 5.8+)
- **Architecture**: amd64 (verified)

---

## 🦎 Kali Linux (ITP / New Tool Request)
**Platform**: [bugs.kali.org](https://bugs.kali.org/)
**Category**: New Tool Requests

### Description for Bug Report:
`gspy` is a forensic tool designed to inspect the execution state of live Go processes without using `ptrace` or binary instrumentation. It uses eBPF (uprobes and tracepoints) to map Goroutine IDs to active kernel syscalls and user-space stack frames in real-time.

**Why it belongs in Kali:**
It bridges the gap between high-level Go runtime state and kernel-level syscall activity, providing a zero-footprint way to investigate compromised or suspicious Go binaries (Malware, C2 agents, etc.) during live forensics.

**Technical Details:**
- **Language**: Go/C (eBPF)
- **Source**: https://github.com/mutasem_mk4/gspy/archive/v0.1.0.tar.gz
- **Dependencies**: `clang`, `llvm`, `libbpf`, `libelf`
- **Installation**: `make build` (static binary)

---

## 🏴 BlackArch Linux (PKGBUILD PR)
**Platform**: [GitHub - BlackArch](https://github.com/BlackArch/blackarch)
**Categories**: `forensic`, `debugger`

### PR Description:
Add `gspy`: a forensic Goroutine-to-Syscall inspector.
`gspy` allows investigators to see exactly what syscalls every goroutine is making in a target process without affecting its memory or file hash.

**PKGBUILD Location**: `packaging/PKGBUILD` (in gspy repo)

---

## 🦜 Parrot OS (New Tool Request)
**Platform**: [GitLab - ParrotSec](https://gitlab.com/parrotsec)
**Template**: `new_tool`

### Submission Details:
- **Tool Name**: gspy
- **Purpose**: Live Go process forensic inspection.
- **Packaging**: Ready (contains `debian/` directory).
- **Stability**: High (zero-footprint, read-only memory access via `process_vm_readv`).
- **Standard Use case**: Inspecting Go malware or analyzing performance bottlenecks in real-time.
