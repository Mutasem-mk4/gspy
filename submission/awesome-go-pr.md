# awesome-go PR Preparation — gspy

> **Do NOT submit until September 2026.** awesome-go requires repositories to be at least 5 months old. gspy was created ~April 2026, so the earliest eligible date is **September 20, 2026**.

## Exact entry to add

Add this line to the `## Security` section of awesome-go's README.md, alphabetically after `gost-crypto`:

```markdown
- [gspy](https://github.com/Mutasem-mk4/gspy) - Forensic goroutine-to-syscall inspector for live Go processes using eBPF.
```

## PR Title

```
Add gspy to Security section
```

## PR Body

```markdown
**gspy** — Forensic goroutine-to-syscall inspector for live Go processes using eBPF.

**Repository:** https://github.com/Mutasem-mk4/gspy
**Category:** Security

### What it does

gspy attaches to a running Go process by PID using eBPF uprobes (`runtime.execute`) and kernel tracepoints (`raw_syscalls`), reads goroutine IDs via `process_vm_readv(2)` (zero ptrace, zero binary modification), and maps goroutine ID → syscall → user-space stack frame in real time.

### Why it belongs in awesome-go

- **Unique**: No other Go library provides goroutine-level syscall attribution
- **Security-focused**: Forensic `--readonly` mode with SHA-256 chain-of-custody verification
- **Production-quality**: CI with lint, test, ABI matrix (Go 1.21–1.24), integration tests
- **Well-documented**: Man page, CHANGELOG, CONTRIBUTING, SECURITY.md
- **Properly licensed**: GPL-2.0-only (required for eBPF kernel interaction)

### Checklist (from CONTRIBUTING.md)

- [x] Added the project to the correct category (`Security`) in alphabetical order
- [x] Project is open source
- [x] Project has a README with clear documentation
- [x] Project has tests (`make test`)
- [x] Project has CI (GitHub Actions — all green)
- [x] Project is actively maintained
- [x] Project is useful to the Go community
- [x] Project does not duplicate an existing entry
- [x] Project has a proper Go module path (`github.com/Mutasem-mk4/gspy`)
- [x] Project is indexed on pkg.go.dev
```

## Pre-submission checklist

Before submitting this PR in September 2026, verify:

- [ ] Repository is at least 5 months old (check `gh api repos/Mutasem-mk4/gspy --jq .created_at`)
- [ ] Test coverage >= 80% (check CI logs for `go tool cover -func` output)
- [ ] pkg.go.dev page is live: https://pkg.go.dev/github.com/Mutasem-mk4/gspy
- [ ] Go Report Card grade is A+: https://goreportcard.com/report/github.com/Mutasem-mk4/gspy
- [ ] CI is green: https://github.com/Mutasem-mk4/gspy/actions
- [ ] No open critical issues
- [ ] README badges are all resolving correctly
- [ ] The awesome-go `## Security` section format hasn't changed (re-check before submitting)
- [ ] awesome-go's CONTRIBUTING.md requirements haven't changed
