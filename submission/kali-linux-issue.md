### Tool Overview
**gspy** is a highly specialized eBPF-driven forensic tool designed to solve the "goroutine-blindness" inherent in traditional tracing tools (`strace`, `ptrace`). It attaches to live Go processes using eBPF uprobes and kernel tracepoints, mapping running goroutines to real-time syscalls and user-space stack frames without binary modification or `ptrace()` pauses.

### Why Kali Linux Needs gspy
Currently, Kali lacks a dedicated tool for analyzing Go-based malware, rootkits, and C2 frameworks at the runtime level. As Golang becomes the standard for modern offensive tooling (e.g., Sliver, Merlin), gspy provides a critical advantage for reverse engineers and malware analysts, granting unprecedented observability into compiled Go binaries.

### Key Technical Advantages
- **Zero Observer Effect:** Uses `process_vm_readv` and eBPF. Completely bypasses the `ptrace` attachment halt, ensuring target process performance is strictly unaffected.
- **Forensic Integrity:** Includes a `--readonly` mode with cryptographic (SHA-256) footprinting of the process memory map, strictly enforcing a 0-write operational guarantee.
- **Architecture Compatibility:** CO-RE (Compile Once – Run Everywhere) compliant. Fully native compilation for both `x86_64` (AMD64) and `AArch64` (ARM64) systems.
- **Go ABI Tracking:** Natively understands the internal Go scheduler and tracks the internal Application Binary Interface (ABI) of the Go compiler (v1.21 - v1.24+).

### Packaging Status
- **Repository:** https://github.com/Mutasem-mk4/gspy
- **License:** GPL-2.0-only (SPDX compliant)
- **Packaging:** Complete `debian/` directory included (control, rules, DEP-5 copyright, changelog).
- **Documentation:** Full `man` pages and TUI-driven help.
- **Quality Metrics:** Go Report Card A+, Full CI/CD coverage, Security Scorecard 10/10.

### Additional Metadata
- **Category:** Forensics / Reverse Engineering
- **Language:** Go + eBPF C
- **Dependencies:** Linux kernel >= 5.8, CAP_BPF + CAP_PERFMON
- **Build:** `make generate && make build`
- **Test:** `make test` (uses mock BPF, no root required)

I am the maintainer of this tool and am happy to assist with any further packaging requirements or maintain the Debian package directly.