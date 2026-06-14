# SYSCAGE Threat Model

---

## Scope

SYSCAGE is a **behavioral syscall confinement tool**. It reduces the kernel attack surface by restricting which system calls a process can make. This limits what an attacker can do after gaining code execution inside a confined process.

## What SYSCAGE Protects Against

| Threat | Mitigation |
|---|---|
| Shellcode execution | Blocked if shellcode uses syscalls not in the process's profile |
| Fileless malware (mmap/mprotect) | Unusual `mmap`/`mprotect` calls are denied |
| Reverse shell (`socket`/`connect`/`execve`) | Network and process-creation syscalls blocked unless observed |
| Kernel exploit via syscall | Reduces number of reachable syscall entry points |
| Data exfiltration via `write` | If `write` was not in the observed profile, it's blocked |
| Privilege escalation via `setuid`/`setgid` | These syscalls must appear in the trace or they're denied |

## What SYSCAGE Does NOT Protect Against

| Threat | Reason |
|---|---|
| Memory corruption within allowed syscalls | seccomp filters syscalls, not data |
| Side-channel attacks | seccomp has no side-channel visibility |
| Kernel exploits via existing syscalls | An allowed syscall with a kernel bug is still exploitable |
| Direct physical access | Out of scope |
| Network-level attacks | Out of scope |

## Assumptions

- The tracing phase captures representative behavior of the process
- The process is not already compromised during tracing (if it is, the profile will include malicious syscalls)
- The kernel is trusted (seccomp relies on the kernel it restricts)

## Attack Scenarios

### Scenario 1: Code injection via buffer overflow

1. Attacker gains control of process A
2. Injects shellcode that calls `execve("/bin/sh", ...)`
3. **SYSCAGE:** `execve` is not in A's profile → SIGSYS → process killed

### Scenario 2: Fileless malware via RWX memory

1. Attacker uses `mmap` with RWX to inject code
2. If `mmap` was not observed during profiling, it is blocked
3. **SYSCAGE:** Even if `mmap` is allowed, the specific combination of `mprotect` to set X on writable memory may not be in the profile

### Scenario 3: Reverse shell from a web server

1. Web server is exploited
2. Attacker calls `socket`, `connect`, `dup2`, `execve`
3. **SYSCAGE:** None of these are in a typical web server's profile → all blocked

## Known Limitations

- **Tracing completeness:** A profile is only as good as the trace. If a legitimate code path was not exercised during tracing, it will be blocked in production.
- **Static profiles:** SYSCAGE generates static seccomp filters. Dynamic behavior changes require re-profiling.
- **32-bit vs 64-bit:** The current implementation targets x86_64. 32-bit syscalls (ia32 on x86_64) are not handled.
