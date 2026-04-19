# Contributing to gspy

Thank you for your interest in contributing to gspy. This is a forensic security tool — correctness, reliability, and audit trail integrity are non-negotiable.

## Building from Source

### Prerequisites

| Tool | Minimum Version | Purpose |
|------|----------------|---------|
| Go | 1.21 | Compiler |
| clang | 14 | BPF C compilation via bpf2go |
| llvm | 14 | `llvm-strip` for BPF object stripping |
| libbpf-dev | — | BPF CO-RE headers |
| libelf-dev | — | ELF parsing for symbol resolution |
| bpftool | — | Optional: generate `vmlinux.h` from running kernel |

### Build Steps

```bash
# Install bpf2go (only needed once)
go install github.com/cilium/ebpf/cmd/bpf2go@v0.17.1

# Generate BPF bytecode from C source
make generate

# Build the gspy binary
make build

# Install to system paths (optional)
sudo make install
```

The `make generate` step compiles `bpf/gspy.bpf.c` into Go-embedded BPF bytecode via `bpf2go`. This requires `clang` and `llvm-strip` in your PATH.

### Makefile Targets

| Target | Description |
|--------|-------------|
| `generate` | Compile BPF C → Go + `.o` bytecode |
| `build` | Generate + build the binary |
| `build-only` | Build without regenerating BPF (for CI) |
| `test` | Run all tests with race detector |
| `lint` | Run golangci-lint |
| `install` | Install to `/usr/bin` and man page |
| `uninstall` | Remove installed files |
| `clean` | Remove build artifacts |
| `man` | Compress man page for distribution |

## Running Tests

```bash
make test
```

Tests use a **mock BPF layer** — no root, no kernel BPF, and no running target process is required. The test suite verifies:
- ABI offset tables for Go 1.21–1.24
- Syscall name resolution
- TUI rendering and state transitions
- JSON output serialization
- `--readonly` mode SHA-256 verification logic

You should never need `sudo` to run the test suite.

## Code Style

All Go code must pass `golangci-lint` with the project's `.golangci.yml` configuration:

```bash
make lint
```

Additional style requirements:
- Run `gofmt` on all `.go` files (enforced by CI).
- Every `.go` and `.c` file must begin with an SPDX header:
  ```
  // SPDX-License-Identifier: GPL-2.0-only
  ```
- Commit messages follow [Conventional Commits](https://www.conventionalcommits.org/): `feat:`, `fix:`, `docs:`, `chore:`, `test:`, `ci:`.

## Submitting a Bug Report

Open a [GitHub Issue](https://github.com/Mutasem-mk4/gspy/issues/new) and include:

1. **gspy version**: output of `gspy --version`
2. **Kernel version**: output of `uname -r`
3. **Go version of the target process** (if known): this affects `runtime.g` struct offsets
4. **Exact command line** you ran
5. **Expected vs. actual behavior**
6. **`--debug` output** if applicable (includes BPF verifier log)

For security vulnerabilities, see [SECURITY.md](SECURITY.md) — do not open a public issue.

## Submitting a Pull Request

1. Fork the repository and create a feature branch from `master`.
2. Make your changes with clear, atomic commits.
3. Ensure `make test` and `make lint` pass locally.
4. If you modified BPF C code, verify `make generate` succeeds with clang >= 14.
5. If you added a new Go version to the ABI table, add the corresponding test case in `internal/attach/`.
6. Open a PR against `master` with a clear description of what and why.

All PRs must pass CI (lint, test, ABI matrix, build, integration) before merge.

## BPF Licensing Note

**All BPF C code must be GPL-2.0-only.** This is not a project policy choice — it is a hard requirement of the Linux kernel's BPF subsystem. The kernel will refuse to load BPF programs that are not GPL-licensed. Every `.c` file in `bpf/` must carry the SPDX header, and the `LICENSE` section in the BPF ELF must resolve to GPL.

If you contribute BPF C code, you are agreeing to license it under GPL-2.0-only.

## Research Opportunities

### arm64 Goroutine ID Offsets

gspy's goroutine ID extraction depends on the byte offset of the `goid` field within Go's `runtime.g` struct. These offsets are verified on `amd64` for Go 1.21–1.24, but **unverified on `aarch64`**.

If you have access to arm64 Linux hardware with kernel >= 5.8:
1. Build a Go binary for each supported version
2. Use `go tool compile -S` or `dlv` to verify the `runtime.g` struct layout
3. Note the byte offset of the `goid` field
4. Submit a PR adding the verified offsets to the ABI table in `internal/attach/abi.go`

This is a high-impact contribution that would unlock verified arm64 support.

## Code of Conduct

This project enforces a [Code of Conduct](CODE_OF_CONDUCT.md). Be respectful and professional in all interactions.
