# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| 0.1.x   | ✅ Current |

## Reporting Vulnerabilities

gspy is a security tool that runs with elevated kernel privileges (CAP_BPF, CAP_PERFMON). We take security seriously.

If you discover a vulnerability, please report it responsibly:

1. **DO NOT** open a public GitHub issue
2. Email: mutasem@gspy.dev
3. Include:
   - Description of the vulnerability
   - Steps to reproduce
   - Impact assessment
   - Kernel version and Go version tested

We will acknowledge receipt within 48 hours and provide a fix timeline within 7 days.

## Threat Model

gspy requires elevated privileges by design. The following are **not** considered vulnerabilities:

- Requiring CAP_BPF or CAP_SYS_ADMIN to operate
- Ability to read memory from processes the user already has access to
- Information disclosure about a process the user owns

The following **are** considered vulnerabilities:

- Memory corruption in the BPF layer that could cause kernel panic
- Privilege escalation beyond the intended capability set
- Writing to or modifying the target process (violating readonly guarantee)
- Information leakage about processes the user does NOT have access to
