# Contributing to gspy

Thank you for your interest in contributing to gspy! As a forensic tool, maintaining reliability and security is paramount.

## Development Environment

1. Install Go 1.21+.
2. Install clang >= 14, llvm, and libbpf-dev for eBPF compilation.
3. Run make generate to build BPF bytecode.
4. Run make test to execute tests with mock BPF (no root required).
5. Run make lint using golangci-lint to ensure code quality.

## Submitting Pull Requests

* Ensure all tests pass.
* If adding new BPF logic, ensure it works cleanly on minimum kernel 5.8.
* Keep commit messages conventional (e.g., eat:, ix:, docs:).

## Code of Conduct

This project enforces a [Code of Conduct](CODE_OF_CONDUCT.md). Please be respectful and professional in all interactions.
