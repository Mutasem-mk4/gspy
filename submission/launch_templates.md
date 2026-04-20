# 🚀 Gspy Official Launch Submission Package

Use these finalized, "Platinum-grade" templates for the April 21st viral launch. 

## 1. Hacker News ("Show HN")
**Time:** 15:00 UTC (April 21)
**Title:** Show HN: gspy – Map raw Linux syscalls back to specific Goroutines with eBPF

### 💬 First Comment (Copy & Paste)
Hey HN, I'm the author of gspy.

Tracing Go binaries on Linux during incident response is notoriously difficult. If you run `strace`, you see a firehose of syscalls, but because Go has its own M:N scheduler, you can't easily tell which logical goroutine triggered which syscall. They all look like they're coming from the same few OS threads.

`gspy` solves this attribution problem using eBPF uprobes. It hooks into the Go runtime's scheduler (`runtime.execute`). Every time a goroutine context switches, `gspy` records the mapping of Thread ID (TID) to Goroutine ID (GID) in a BPF map. When a syscall occurs, we perform a real-time lookup to attribute the kernel event back to the specific Go logic that triggered it.

**Key Technical Highlights:**
*   **Zero-Pause Observability:** Unlike `ptrace`, it never stops the process. No `SIGSTOP`, no `T-state` detection for malware to find.
*   **No Memory Scribing:** We use `process_vm_readv` (and BPF helpers) to read the Go stack and TLS mapping without writing a single byte to the target memory.
*   **TUI-First:** Built a fast, low-dependency terminal interface for real-time triage.

**The Hardest Part:**
The hardest part about building this was handling Go's non-standard calling convention (ABIInternal). Unlike C, Go passes many arguments in registers in a way that eBPF's standard `PT_REGS_PARM` macros don't always catch correctly, especially across the transition from Go 1.17 to 1.21. I had to implement some custom offset-mapping logic in the BPF C code to ensure we were reading the GID from the correct register/stack slot across different Go versions.

Would love to hear your thoughts on the eBPF implementation or the Go runtime hacking involved!

---

## 2. Reddit (The "Lesson-First" Strategy)
**Subreddits:** `r/golang`, `r/netsec`

**Title:** I spent 3 months deep-diving into the Go Runtime Scheduler to build an eBPF tracer. Here is what I learned about Goroutine attribution.

**Body Template:**
Hey everyone, 

I've been obsessed with how the Go scheduler handles context switching and how that impacts forensic observability. I realized that traditional Linux tracers are effectively "blind" to Go's logical flow because they stop at the Thread level.

I built **gspy** (github.com/Mutasem-mk4/gspy) to solve this. It's a zero-overhead eBPF tracer that maps raw syscalls directly to their initiating Goroutines in real-time.

**Key things I learned during development:**
1. How `runtime.g` structures differ across Go 1.17+ versions.
2. The nuances of reading Thread Local Storage (TLS) from inside a BPF program.
3. Why `ptrace` is increasingly detectable by modern malware and why eBPF is the future of forensic-grade stealth.

Check out the TUI and the source here: https://github.com/Mutasem-mk4/gspy

---

## 3. X (Twitter)
**Draft (Copy & Paste):**
Reversing Go malware on Linux just got much easier. 🧪

Today I'm open-sourcing `gspy` — a zero-overhead eBPF tracer that maps raw kernel syscalls directly to their initiating Goroutines in real-time. No ptrace, no restarts.

🔗 https://github.com/Mutasem-mk4/gspy 

Tagging: @lizrice @brendangregg @golang @ciliumproject 

#eBPF #golang #infosec #DFIR
