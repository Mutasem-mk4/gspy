# gspy Pull Request Templates for Awesome Lists

This document contains the exact markdown and PR descriptions needed to submit `gspy` to the top security "Awesome" lists.

---

## 🦾 Target 1: Awesome Linux Security
**Repository**: [sbilly/awesome-security](https://github.com/sbilly/awesome-security)  
**Category**: `## Endpoint` -> `### Forensics`

### Markdown to Insert (Alphabetical):
```markdown
* [gspy](https://github.com/Mutasem-mk4/gspy) - Forensic goroutine-to-syscall inspector for live Go processes using eBPF.
```

### PR Metadata:
- **Title**: Add gspy - Forensic goroutine-to-syscall inspector
- **Description**:
Hi! I'd like to add `gspy` to the Forensics section. It's a specialized tool for inspecting live Go processes using eBPF uprobes and tracepoints to bridge the gap between user-space goroutines and kernel-level syscalls. It operates with a zero-footprint (no ptrace/no binary modification).

---

## 🧪 Target 2: Awesome Malware Analysis
**Repository**: [rshipp/awesome-malware-analysis](https://github.com/rshipp/awesome-malware-analysis)  
**Category**: `## Debugging and Reverse Engineering`

### Markdown to Insert (Alphabetical):
```markdown
* [gspy](https://github.com/Mutasem-mk4/gspy) - Forensic eBPF-driven goroutine-to-syscall inspector for live Golang malware analysis.
```

### PR Metadata:
- **Title**: Add gspy for live Golang malware analysis
- **Description**:
Added `gspy` to the Debugging and Reverse Engineering section. `gspy` allows analysts to trace syscalls made by specific goroutines in live Go binaries without affecting process performance or memory integrity (utilizing eBPF and `process_vm_readv`). Great for analyzing Go-based backdoors and C2 agents.

---

## 🔍 Target 3: Awesome Forensics
**Repository**: [cugu/awesome-forensics](https://github.com/cugu/awesome-forensics)  
**Category**: `### Live Forensics`

### Markdown to Insert (Alphabetical):
```markdown
- [gspy](https://github.com/Mutasem-mk4/gspy) - Forensic goroutine-to-syscall inspector for live Go processes using eBPF.
```

### PR Metadata:
- **Title**: Add gspy to Live Forensics
- **Description**:
I'm submitting `gspy`, a tool for live forensic inspection of Go processes. It helps responders map which internal goroutines are triggering specific system calls in real-time using eBPF, facilitating rapid incident response for high-concurrency Go applications.
