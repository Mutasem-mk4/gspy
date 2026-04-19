# gspy Launch Playbook

To ensure `gspy` reaches the maximum audiencce in the security and developer communities, follow this coordinated launch strategy.

## 1. Hacker News ("Show HN")

**Title:** Show HN: gspy – zero-overhead goroutine-to-syscall tracer using eBPF
**URL/Text:** Link to the GitHub repository directly. Add a top-level comment immediately after posting to provide context.

**Top-Level Comment Copy:**
> Hey HN, I'm the author of gspy.
>
> When doing incident response on Linux systems, tracing Go malware (like Cobalt Strike variants, custom C2s, or ransomware) is notoriously difficult. Standard tools like `strace` or `sysdig` show you raw syscalls, but because Go utilizes an M:N scheduler, thousands of goroutines multiplex over a few OS threads. A raw strace log is almost impossible to attribute to a specific logical goroutine.
>
> `gspy` elegantly solves this. It attaches via eBPF uprobes directly to the Go runtime's scheduler (`runtime.execute`). Every time a goroutine context switches, `gspy` maps the active OS Thread ID to the Goroutine ID. When a syscall fires, we immediately know *which specific goroutine* made it.
>
> **Best part:** It uses `process_vm_readv` to read thread-local storage securely. It does 0 writes to the target memory, never modifies the binary, and never triggers an `execve` restart. You can attach to a production process completely invisibly.
>
> Would love to hear feedback from SREs and security engineers!

---

## 2. Reddit (`r/netsec` & `r/golang`)

**Title (r/netsec):** Live Forensics on Go Malware: Mapping Goroutines to Syscalls with eBPF
**Title (r/golang):** I built an eBPF process tracer that maps raw syscalls back to specific Goroutines for debugging.

**Body:**
*Use a similar copy to the HN post, but embed the `demo.gif` URL at the very top so mobile users see the TUI in action immediately.*

---

## 3. GitHub "Awesome list" submission

Open a PR to `avelino/awesome-go` under the **Security** or **Debugging** categories.

**PR Subject:** Add gspy to Security
**PR Body:**
```markdown
* **Security**
  * [gspy](https://github.com/Mutasem-mk4/gspy) - Forensic goroutine-to-syscall inspector using eBPF for live profiling and incident response.
```

---

## 4. X / Twitter (Infosec Community)

**Draft Tweet:**
> Reversing Go malware on Linux just got much easier.
>
> Today I'm open-sourcing `gspy` — a zero-overhead eBPF tracer that maps raw kernel syscalls directly to their initiating Goroutines in real-time. No ptrace, no restarts.
>
> 🔗 https://github.com/Mutasem-mk4/gspy #eBPF #golang #infosec
> [Attach demo.gif]
