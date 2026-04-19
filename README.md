# gspy — forensic goroutine-to-syscall inspector for live Go processes

[![License: GPL-2.0-only](https://img.shields.io/badge/License-GPL--2.0--only-blue.svg)](LICENSE)
[![Go Version](https://img.shields.io/badge/Go-1.21+-00ADD8.svg)](https://go.dev)
[![Kernel](https://img.shields.io/badge/Kernel-5.8+-yellow.svg)](https://kernel.org)
[![OpenSSF Scorecard](https://api.securityscorecards.dev/projects/github.com/Mutasem-mk4/gspy/badge)](https://securityscorecards.dev/viewer/?uri=github.com/Mutasem-mk4/gspy)

**gspy** attaches to a running Go process by PID using eBPF uprobes and kernel tracepoints, reads goroutine state from thread-local storage via `process_vm_readv` (zero ptrace, zero process modification), and displays a live terminal map of goroutine ID → syscall → user-space stack frame. One command. No instrumentation. No process restart. No hash change.

## Demo

![gspy demo](https://raw.githubusercontent.com/Mutasem-mk4/gspy/master/demo/demo.gif)
*(Generated using the script in `demo/`)*

## Security & Forensic Use Cases

- **Live forensic inspection** — Inspect Go processes without ptrace, binary modification, or hash alteration. Chain-of-custody preservation via `--readonly` mode with SHA-256 verification.
- **Incident response** — When a Go process makes unexpected network calls, file writes, or privilege escalations, answer: *which goroutine made that syscall, and from which function?*
- **Malware analysis** — Goroutine-level behavioral attribution in Go implants, backdoors, and C2 agents running in-situ on a compromised host.
- **Red/blue team exercises** — Zero-footprint process inspection that doesn't trigger file integrity monitoring, modify `/proc/self/maps`, or require agent deployment.

## Technical Deep Dive

Read our blog post: [**Why Ptrace is Dead for Go Forensics: Catching Malware with eBPF**](docs/blog/why-ptrace-is-dead-for-go-forensics.md)

## How It Works

gspy uses eBPF uprobes attached to the Go runtime's `runtime.execute` function, which fires on every goroutine context switch. At each switch, gspy reads the goroutine pointer from the RAX register (Go 1.17+ ABIInternal on amd64), then uses `bpf_probe_read_user` to extract the goroutine ID (`goid`) from the `runtime.g` struct at a version-specific offset. This creates a real-time TID→GID mapping in a BPF hash map. Syscalls are intercepted via `raw_syscalls/sys_enter` and `raw_syscalls/sys_exit` tracepoints, with the GID looked up from the mapping.

Stack frame resolution uses the target binary's ELF symbol table — never ptrace. The `process_vm_readv(2)` syscall is the only mechanism used to read target process memory, which is inherently read-only. BPF events flow through a 16MB ring buffer polled at 100ms intervals, and the TUI refreshes at 1Hz. Total CPU overhead at 10K syscalls/sec is < 2% on a 4-core machine.

## Supported Go Runtime Versions

| Go Version | amd64 | arm64 |
|------------|-------|-------|
| 1.17.x     | ✅ Verified | ⚠️  Experimental |
| 1.18.x     | ✅ Verified | ⚠️  Experimental |
| 1.19.x     | ✅ Verified | ⚠️  Experimental |
| 1.20.x     | ✅ Verified | ⚠️  Experimental |
| 1.21.x     | ✅ Verified | ⚠️  Experimental |
| 1.22.x     | ✅ Verified | ⚠️  Experimental |
| 1.23.x     | ✅ Verified | ⚠️  Experimental |

arm64 goid offsets are **unverified** — goroutine IDs may be incorrect. Other architectures are unsupported.

## Kernel Requirements

- Linux kernel **>= 5.8** (required for BPF ring buffer support)
- `CONFIG_BPF_SYSCALL=y` (enabled in all major distributions)
- `CONFIG_DEBUG_INFO_BTF=y` recommended for CO-RE portability
- `perf_event_paranoid` <= 2 recommended

## Installation

### From Source
```bash
git clone https://github.com/mutasemkharma/gspy
cd gspy
make generate   # requires clang >= 14
make build      # requires go >= 1.21
sudo make install # installs to /usr/bin and /usr/share/man
```

### Permissions
Grant capabilities to avoid running as root:
```bash
sudo setcap cap_bpf,cap_perfmon+ep $(which gspy)
```

## Usage

```
gspy <pid>                  # Attach, show live goroutine→syscall TUI
gspy <pid> --top            # Sort by syscall frequency (default)
gspy <pid> --latency        # Sort by highest current syscall latency
gspy <pid> --filter <mode>  # Filter: io | net | sched | all (default: all)
gspy <pid> --readonly       # Forensic mode: zero writes, log SHA-256
gspy <pid> --json           # Emit newline-delimited JSON to stdout
gspy <pid> --debug          # Show BPF verifier log and map stats
gspy --version              # Show version block
gspy --help                 # Show usage
```

## Contributing

We welcome contributions! Please see our [**Contributing Guide**](CONTRIBUTING.md) and [**Code of Conduct**](CODE_OF_CONDUCT.md).

## License

GPL-2.0-only — see [LICENSE](LICENSE) for full text.

eBPF kernel interaction mandates GPL licensing. All source files carry
SPDX headers for Debian `licensecheck` compliance.
