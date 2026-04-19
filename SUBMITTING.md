# Distribution Submission Guide

This document provides exact steps for submitting gspy to Kali Linux, Parrot OS, and BlackArch Linux.

---

## BlackArch Linux

BlackArch is the easiest starting point. Submission is a single pull request.

### Prerequisites
- Working PKGBUILD (included at `./PKGBUILD`)
- Green CI/CD build (GitHub Actions passing)
- The tool must be categorized properly

### Steps

1. **Fork the BlackArch repository:**
   ```bash
   gh repo fork BlackArch/blackarch --clone
   cd blackarch
   ```

2. **Add gspy to the package list:**
   ```bash
   # Copy the PKGBUILD to the correct category
   mkdir -p packages/gspy
   cp /path/to/gspy/PKGBUILD packages/gspy/PKGBUILD
   ```

3. **Verify the PKGBUILD builds:**
   ```bash
   cd packages/gspy
   makepkg -si    # builds and installs locally
   ```

4. **Submit pull request:**
   ```bash
   git add packages/gspy/PKGBUILD
   git commit -m "add gspy: forensic goroutine-to-syscall inspector"
   git push origin master
   gh pr create --title "add gspy: forensic goroutine-to-syscall inspector" \
     --body "Adds gspy, an eBPF-based forensic tool for inspecting Go processes.

   - Maps goroutine IDs to kernel syscalls in real-time
   - Uses uprobes + tracepoints (no ptrace)
   - Forensic --readonly mode with SHA-256 verification
   - GO_VERSION: 1.17-1.23 amd64
   - KERNEL: >= 5.8

   Upstream: https://github.com/Mutasem-mk4/gspy
   License: GPL-2.0-only
   Categories: forensic, debugger"
   ```

5. **Wait for review.** BlackArch maintainers typically review within 1-2 weeks.

---

## Kali Linux

Kali uses Debian packages. Submission requires filing a bug report with the Kali Bug Tracker.

### Prerequisites
- Complete `debian/` directory (included)
- Passing builds via `dpkg-buildpackage`
- Man page installed to the correct path

### Steps

1. **Create a Kali bug tracker account:**
   - Go to: https://bugs.kali.org/
   - Register and log in

2. **File a new tool request:**
   - Project: "Kali Linux"
   - Category: "New Tool Requests"
   - Summary: "gspy — forensic goroutine-to-syscall inspector for Go processes"
   - Description:
     ```
     Tool name: gspy
     Tool URL: https://github.com/Mutasem-mk4/gspy
     Tool description: eBPF-based forensic tool that attaches to live Go processes
     and maps goroutine IDs to kernel syscalls. Uses uprobes and tracepoints
     (no ptrace, no binary modification). Supports forensic --readonly mode
     with SHA-256 binary verification.

     Category: Forensics / Reverse Engineering
     License: GPL-2.0-only
     Language: Go + eBPF C
     Dependencies: Linux kernel >= 5.8, CAP_BPF + CAP_PERFMON

     Packaging: Complete debian/ directory included:
       - debian/control
       - debian/rules
       - debian/copyright (DEP-5)
       - debian/changelog

     Build: make generate && make build
     Test: make test (no root required, uses mock BPF)
     ```

3. **Wait for triage.** Kali reviews tool requests based on:
   - Uniqueness (gspy has no equivalent — this is good)
   - Active maintenance (commit history matters)
   - Working packaging (our debian/ directory)

---

## Parrot OS

Parrot follows Debian packaging standards and accepts tools through their GitLab.

### Steps

1. **Visit Parrot packaging guidelines:**
   - https://docs.parrotlinux.org/developers/packaging/

2. **Open an issue on the Parrot GitLab:**
   - https://gitlab.com/parrotlinux/project/issues
   - Title: "New tool request: gspy — forensic Go process inspector"
   - Include the same description as the Kali submission

3. **They may ask you to submit a merge request** with the debian/ directory.

---

## Pre-Submission Checklist

Before submitting to ANY distribution:

- [ ] GitHub Actions CI is green (all jobs pass)
- [ ] `make test` passes on a real Linux machine
- [ ] `make generate` produces valid BPF bytecode
- [ ] `sudo ./bin/gspy <pid>` works on a real Go process
- [ ] `man gspy` renders correctly  
- [ ] `gspy --version` shows correct version info
- [ ] `dpkg-buildpackage -us -uc` builds a .deb successfully
- [ ] `makepkg -si` builds from PKGBUILD successfully
- [ ] Repository has at least 3-5 commits showing active development
- [ ] README has clear build instructions
- [ ] LICENSE file is GPL-2.0-only (verified by licensecheck)
