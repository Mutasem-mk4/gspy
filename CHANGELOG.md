# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.2.0] - 2026-04-20

### Changed
- Migrated to cilium/ebpf v0.21.0 API (`Variables.Set` loop, `LogSizeStart`).
- Fixed `go.mod` module path to match GitHub repository URL.
- Updated bpf2go from v0.14.0 to v0.17.1.
- Upgraded golangci-lint to v1.64.2 for Go 1.24 compatibility.

### Added
- Go 1.24 ABI support for goroutine ID extraction.
- pkg.go.dev and Go Report Card badges in README.
- CI build status badge in README.
- CHANGELOG.md following Keep a Changelog format.
- BlackArch-compliant PKGBUILD with SPDX license identifier.

### Fixed
- `debian/copyright` Source URL typo (underscore → hyphen).
- `debian/control` Section changed from `utils` to `admin`.
- `debian/source/format` changed from `3.0 (native)` to `3.0 (quilt)`.
- Man page version header updated to 0.2.0.
- All internal import paths corrected to match module path.

## [0.1.1] - 2026-04-19

### Changed
- Hardened for security distribution acceptance (Kali, BlackArch, Parrot).
- Fixed version string reporting in CI to use `git describe`.
- Hardened binary verification in CI (removed silenced tests).
- Refactored TUI flash messages with timed auto-clear (3s).

### Added
- Real-process BPF integration tests in CI.
- SPDX-License-Identifier tags on all source files.
- Relocated and modernized PKGBUILD for BlackArch compatibility.
- Gzipped man page in release artifacts.

### Fixed
- Complied with Debian build policy (removed internet access during build).

## [0.1.0] - 2024-12-01

### Added
- Initial release.
- eBPF-based forensic goroutine-to-syscall inspector for live Go processes.
- Supports Go 1.17–1.23 on amd64.
- Requires Linux kernel >= 5.8 with BPF ring buffer support.
- TUI mode with 1 Hz refresh, sort, filter, and expanded goroutine view.
- JSON output mode for pipeline processing.
- Forensic `--readonly` mode with SHA-256 binary verification.
- Man page and complete documentation.

[0.2.0]: https://github.com/Mutasem-mk4/gspy/compare/v0.1.1...v0.2.0
[0.1.1]: https://github.com/Mutasem-mk4/gspy/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/Mutasem-mk4/gspy/releases/tag/v0.1.0
