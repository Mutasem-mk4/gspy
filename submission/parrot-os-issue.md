### Proposal
I would like to propose the inclusion of **gspy** into the Parrot OS repository. gspy is an advanced eBPF-driven Digital Forensics and Incident Response (DFIR) tool for analyzing live Golang binaries.

### Value Proposition for Parrot OS
Parrot OS is known for its focus on developer-friendly security tools. gspy aligns perfectly with this by providing deep visibility into the Go runtime—something currently impossible with standard tools like `strace` or `gdb` due to Go's internal scheduler. By adding gspy, Parrot OS will provide reverse engineers and SOC analysts with unparalleled capabilities against modern Go-based malware (e.g., Sliver, Merlin, various rootkits).

### Technical Highlights
- **eBPF-Driven Zero Footprint:** Completely bypasses the `ptrace` attachment halt, ensuring target process performance is strictly unaffected and avoiding standard anti-debugging checks.
- **Goroutine-to-Syscall Mapping:** Maps concurrent Go logic to OS-level kernel calls and userspace stack frames in real-time.
- **Symbol Resolution:** Dynamically resolves userspace symbols from ELF tables without requiring external DWARF.
- **Compliance:** Built-in forensic mode (`--readonly`) for incident responders. Guarantees a cryptographic (SHA-256) footprint of the process memory map alongside a strictly enforced 0-write operational guarantee.

### Readiness
- **License:** GPL-2.0-only (SPDX compliant)
- **Upstream:** https://github.com/Mutasem-mk4/gspy
- **Packaging:** Debian-compliant `debian/` directory is maintained upstream.
- **Stability:** Passing all CI/CD benchmarks on Kernel 5.8+ (x86_64 and AArch64).

I am the maintainer of this tool and am happy to assist with any further packaging requirements or submit a Merge Request with the `debian/` structure upon approval.