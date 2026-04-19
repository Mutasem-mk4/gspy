# Why Ptrace is Dead for Go Forensics: Catching Malware with eBPF

*Live incident response on Go applications presents a unique set of challenges. This is the story of how and why we built gspy, a zero-footprint live Go forensic tool.*

The nightmare scenario is real: you have a suspicious Go binary running on a production Linux server. It might be a rogue process, it might be a C2 implant, or it might just be a legitimate application with a rogue goroutine leaking data. You can't kill it without losing the state, and you can't restart it to attach a profiler. You need to know exactly what it's doing right now.

## The Problem with strace and Go

If you attach strace, you'll see a firehose of system calls. You might even see a connect or write that looks suspicious. But Go uses an M:N scheduler. System calls are executed by OS threads (M), but the actual logic runs inside lightweight goroutines (G). strace only sees the thread IDs. It cannot tell you which goroutine made the call, nor can it easily tell you the exact Go function frame that triggered it without complex stack unwinding.

Furthermore, ptrace stops the process. For malware analysis, anti-debugging tricks can detect ptrace and alter the process behavior. For chain-of-custody in digital forensics, stopping processes and altering memory is highly undesirable.

## Enter eBPF: The Magic Behind gspy

gspy solves this by abandoning ptrace entirely. Instead, it relies on the Linux kernel's eBPF capabilities.

### 1. Hooking the Scheduler
We place a uprobe on runtime.execute in the Go runtime. This is the function responsible for scheduling a goroutine onto an OS thread. Every time it fires, we know exactly which goroutine is about to run.

### 2. Reading the Goroutine ID
Using the ABIInternal calling convention (Go 1.17+), we can read the runtime.g pointer directly from the RAX register. We then use bpf_probe_read_user to safely extract the goid at a known offset.

### 3. Intercepting Syscalls
We attach to the raw_syscalls/sys_enter and sys_exit tracepoints. Because our eBPF map already knows which goid is running on the current thread, we simply map the syscall to the goroutine in real-time.

## Read-Only Memory with process_vm_readv

To resolve stack frames (function names) without ptrace, gspy parses the target binary's ELF symbol table and uses process_vm_readv(2) to read the target's memory. This system call is strictly read-only and leaves zero footprint. 

The result? A live, top-like view of every goroutine mapping directly to the syscalls it's executing and the Go function it originated from, with total CPU overhead under 2%.

Try it out at [github.com/Mutasem-mk4/gspy](https://github.com/Mutasem-mk4/gspy).
