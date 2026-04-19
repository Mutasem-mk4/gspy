# gspy — forensic goroutine-to-syscall inspector for live Go processes

[![License: GPL-2.0-only](https://img.shields.io/badge/License-GPL--2.0--only-blue.svg)](LICENSE)
[![Go Version](https://img.shields.io/badge/Go-1.21+-00ADD8.svg)](https://go.dev)
[![Kernel](https://img.shields.io/badge/Kernel-5.8+-yellow.svg)](https://kernel.org)

**gspy** attaches to a running Go process by PID using eBPF uprobes and kernel tracepoints, reads goroutine state from thread-local storage via `process_vm_readv` (zero ptrace, zero process modification), and displays a live terminal map of goroutine ID → syscall → user-space stack frame. One command. No instrumentation. No process restart. No hash change.

## Security Use Cases

- **Live forensic inspection** — Inspect Go processes without ptrace, binary modification, or hash alteration. Chain-of-custody preservation via `--readonly` mode with SHA-256 verification.
- **Incident response** — When a Go process makes unexpected network calls, file writes, or privilege escalations, answer: *which goroutine made that syscall, and from which function?*
- **Malware analysis** — Goroutine-level behavioral attribution in Go implants, backdoors, and C2 agents running in-situ on a compromised host.
- **Red/blue team exercises** — Zero-footprint process inspection that doesn't trigger file integrity monitoring, modify `/proc/self/maps`, or require agent deployment.

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

## Build from Source

```bash
git clone https://github.com/mutasemkharma/gspy
cd gspy
make generate   # requires clang >= 14
make build      # requires go >= 1.21
```

## Install

```bash
make install    # installs to /usr/bin and /usr/share/man
```

Or grant capabilities to avoid running as root:

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

### Example: TUI Output

```
 gspy  pid:1234  binary:/usr/bin/myapp  go:go1.21.5     goroutines:47  attached:2m30s
 GID▼     STATE    SYSCALL        LATENCY    COUNT    FRAME
 42       syscall  write          4.2ms      891      net/http.(*conn).serve
 17       running  epoll_wait     12.1ms     2340     net.(*netFD).Read
 88       syscall  futex          102.3ms    45       sync.(*Mutex).Lock
 3        waiting  nanosleep      1.5s       12       time.Sleep
 91       dead     -              -          7        main.worker

 q:quit  enter:expand  f:filter  s:sort  r:readonly  j:json-dump  ?:help
```

### Example: JSON Pipeline

```bash
# Find goroutines making network calls with latency > 1ms
sudo gspy 1234 --json --filter net | jq 'select(.latency_us > 1000)'

# Log all syscalls to file for later analysis
sudo gspy 1234 --json --readonly > /evidence/gspy_$(date +%s).jsonl

# Real-time alert on unexpected file writes
sudo gspy 1234 --json --filter io | jq -r 'select(.syscall == "write") | .frame'
```

### Example: Forensic Mode

```bash
$ sudo gspy 1234 --readonly --filter net
READONLY MODE: no writes to target process memory
SHA-256(/usr/bin/suspicious): a3b4c5d6e7f8...
# TUI shows [READONLY sha256:a3b4c5d6e7f8] in header
```

## Known Limitations

- **arm64 GID offsets unverified** — Goroutine IDs on arm64 may be incorrect. Provide binaries with DWARF debug info for accurate offsets.
- **Go generics** — Inlined generic functions may produce incorrect frame resolution in the symbol table.
- **ASLR + stripped binaries** — Processes without DWARF info and with ASLR enabled may have partial frame resolution (hex addresses instead of function names).
- **cgroupv1 namespaces** — Unsupported. Container-based targets using cgroupv1 may not work correctly.
- **Kernel < 5.8** — Not supported. gspy exits immediately with exit code 2 and a clear error message.
- **Non-Go processes** — gspy is specifically designed for Go processes. Attaching to non-Go processes will fail during Go version detection.

## Architecture

```
┌─────────────────────────────────────────────────────┐
│                    User Space                        │
│                                                     │
│  ┌─────────┐   ┌──────────┐   ┌─────────────────┐ │
│  │ cmd/gspy│──▸│ attach   │──▸│ proc/reader     │ │
│  │  main   │   │ PID/ELF  │   │ symbol resolve  │ │
│  └────┬────┘   └──────────┘   └─────────────────┘ │
│       │                                            │
│  ┌────▼─────────────────────────────────────────┐  │
│  │   ui/model.go (bubbletea)                     │  │
│  │   ┌──────────┐  ┌──────────┐  ┌──────────┐  │  │
│  │   │ view.go  │  │ table.go │  │ model.go │  │  │
│  │   └──────────┘  └──────────┘  └──────────┘  │  │
│  └────▲─────────────────────────────────────────┘  │
│       │ SyscallEventMsg                            │
│  ┌────┴────┐                                       │
│  │ bpf/    │   ring buffer poll (100ms)            │
│  │loader.go│◂─────────────────────────────────┐    │
│  └─────────┘                                  │    │
├───────────────────────────────────────────────┤    │
│                    Kernel Space               │    │
│                                               │    │
│  ┌────────────────────────────────────────┐   │    │
│  │  gspy.bpf.c (CO-RE, cilium/ebpf)      │   │    │
│  │                                        │   │    │
│  │  ┌─────────────┐  ┌─────────────────┐ │   │    │
│  │  │ tracepoints │  │ uprobes         │ │   │    │
│  │  │ sys_enter   │  │ runtime.execute │ │   │    │
│  │  │ sys_exit    │  │ runtime.newproc1│ │   │    │
│  │  └──────┬──────┘  │ runtime.goexit1 │ │   │    │
│  │         │         └────────┬────────┘ │   │    │
│  │         ▼                  ▼          │   │    │
│  │  ┌──────────────────────────────────┐ │   │    │
│  │  │         BPF Maps                 │ │   │    │
│  │  │ gid_by_tid  goroutine_meta_map   │ │   │    │
│  │  │ syscall_enter  events (ringbuf)──┼─┼───┘    │
│  │  └──────────────────────────────────┘ │        │
│  └────────────────────────────────────────┘        │
└─────────────────────────────────────────────────────┘
```

## License

GPL-2.0-only — see [LICENSE](LICENSE) for full text.

eBPF kernel interaction mandates GPL licensing. All source files carry
SPDX headers for Debian `licensecheck` compliance.
