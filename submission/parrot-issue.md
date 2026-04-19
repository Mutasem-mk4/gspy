## New tool request: gspy — forensic goroutine-to-syscall inspector for live Go processes

**Repository:** https://github.com/Mutasem-mk4/gspy
**Version:** 0.2.0
**License:** GPL-2.0-only
**Category:** Forensics / Reverse Engineering

### What it does

gspy attaches to a running Go process by PID using eBPF uprobes and kernel tracepoints, reads goroutine IDs via `process_vm_readv(2)` (zero ptrace, zero binary modification), and displays a live TUI mapping goroutine ID → syscall → user-space stack frame.

### Why it belongs in Parrot

- Fills a gap: no existing tool provides goroutine-level syscall attribution for Go processes
- Read-only inspection model aligns with forensic best practices
- `--readonly` mode with SHA-256 preserves chain of custody
- JSON output integrates with existing IR workflows

### Technical requirements

- Linux kernel >= 5.8
- CAP_BPF + CAP_PERFMON (or root)
- amd64 (arm64 experimental)

### Packaging

Complete `debian/` directory is in the upstream repo:

```
debian/control
debian/rules
debian/copyright (DEP-5)
debian/changelog
debian/source/format (3.0 quilt)
```

Build: `make generate && make build`
Test: `make test` (no root required, mock BPF)
CI: https://github.com/Mutasem-mk4/gspy/actions ✅

### Checklist

- [x] GPL-2.0-only license (eBPF kernel interaction mandates GPL)
- [x] Complete Debian packaging in upstream repo
- [x] Man page: `man/gspy.1`
- [x] CI green
- [x] `dpkg-buildpackage -us -uc` produces valid `.deb`
- [x] No equivalent tool in Parrot OS
