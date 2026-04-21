# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- **Official BlackArch Linux Support**: gspy is now an official package in the BlackArch repository.
- **Verified arm64 Support**: Goroutine ID (`goid`) offsets for Go 1.17–1.24 verified on `aarch64`.
- Architecture-specific ABI offset tables (internal/attach/elf.go).

### Fixed
- Fixed Go 1.23 and 1.24 GID offsets (changed from 152 to 160 due to `syscallbp` addition).
- Potential nil pointer dereferences in BPF event polling and TUI update loops.

### Planned
- Codecov integration for test coverage badge automation.

## [0.2.0] - 2026-04-20

### Changed
- **Breaking**: Migrated to cilium/ebpf v0.21.0 API.
  - Variable initialization now uses `Variables.Set` loop instead of direct field assignment.
  - Log buffer configuration uses `LogSizeStart` instead of deprecated `LogSize`.
- Updated bpf2go from v0.14.0 to v0.17.1.
- Upgraded golangci-lint to v1.64.2 for Go 1.24 compatibility.
- Fixed `go.mod` module path to `github.com/Mutasem-mk4/gspy` (was lowercase with underscore).
- Updated all internal import paths to match corrected module path.
- GitHub Actions updated to Node.js 24-compatible action versions.

### Added
- Go 1.24 ABI support for goroutine ID extraction (`runtime.g` struct offset table).
- pkg.go.dev reference badge in README.
- Go Report Card badge in README.
- OpenSSF Scorecard badge in README.
- CI build status badge in README.
- CHANGELOG.md following Keep a Changelog format.
- CONTRIBUTING.md with build, test, and submission guidance.
- BlackArch-compliant PKGBUILD with SPDX `GPL-2.0-only` license identifier.
- Makefile `uninstall` target for clean removal.
- Test coverage reporting in CI (`go tool cover -func`).

### Fixed
- `debian/copyright` Source URL typo (underscore → hyphen).
- `debian/control` Section changed from `utils` to `admin`.
- `debian/source/format` changed from `3.0 (native)` to `3.0 (quilt)`.
- Man page version header updated to 0.2.0.
- Removed redundant `debian/compat` (debhelper-compat in Build-Depends).

## [0.1.1] - 2026-04-19

### Changed
- Hardened CI pipeline for distribution acceptance audits.
- Version string now uses `git describe --tags --always --dirty` in CI builds.
- Binary verification step no longer silences failures (`|| true` removed).
- TUI flash messages refactored with timed auto-clear (3-second timeout).

### Added
- Real-process BPF integration tests in CI (launches Go test target, attaches gspy).
- SPDX-License-Identifier headers on all `.go` and `.c` source files.
- Gzipped man page (`man/gspy.1.gz`) included in GitHub release artifacts.
- PKGBUILD relocated to `packaging/blackarch/` for BlackArch submission.

### Fixed
- Debian build policy compliance: removed all network access during `override_dh_auto_build`.
- CI lint job now generates BPF bindings before running golangci-lint (was failing on missing types).

## [0.1.0] - 2024-12-01

### Added
- **Initial release** of gspy — forensic goroutine-to-syscall inspector.
- eBPF uprobe on `runtime.execute` for goroutine scheduler tracing.
- `raw_syscalls/sys_enter` and `raw_syscalls/sys_exit` tracepoints for syscall interception.
- Goroutine ID extraction via `process_vm_readv(2)` — zero ptrace, zero binary modification.
- TID-to-GID BPF hash map for real-time goroutine-to-thread attribution.
- BPF ring buffer (16 MB) with 100ms poll interval.
- Live terminal UI (bubbletea) with 1 Hz refresh, sort, filter, and expanded goroutine view.
- Sort modes: `--top` (syscall frequency), `--latency` (highest current latency).
- Filter modes: `--filter io|net|sched|all` for targeted inspection.
- `--readonly` forensic mode: zero writes to target process memory, SHA-256 binary hash logged.
- `--json` mode: newline-delimited JSON output for SIEM/jq pipeline integration.
- `--debug` mode: BPF verifier log and map statistics.
- ELF symbol table resolution for user-space stack frames (no DWARF required for basic operation).
- CO-RE BPF programs with BTF support for kernel portability.
- Man page (`man/gspy.1`) with full option documentation.
- Complete `debian/` packaging directory for Kali Linux and Parrot OS.
- Makefile with `generate`, `build`, `build-only`, `install`, `test`, `lint`, `man` targets.
- GPL-2.0-only license (mandatory for eBPF kernel interaction).

### Known Limitations
- arm64: goroutine ID offsets unverified — IDs may be incorrect on `aarch64`.
- Go generics: inlined generic functions may produce incorrect stack frame resolution.
- Stripped binaries without DWARF: partial frame resolution (hex addresses only).
- Linux kernel < 5.8: not supported (BPF ring buffer required).
- cgroupv1 namespaces: not supported.
- Measured overhead: < 2% CPU at 10K syscalls/sec on a 4-core machine.

[Unreleased]: https://github.com/Mutasem-mk4/gspy/compare/v0.2.0...HEAD
[0.2.0]: https://github.com/Mutasem-mk4/gspy/compare/v0.1.1...v0.2.0
[0.1.1]: https://github.com/Mutasem-mk4/gspy/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/Mutasem-mk4/gspy/releases/tag/v0.1.0
