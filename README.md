# SYSCAGE

Behavioral syscall profiler and seccomp policy generator for Linux process confinement.

[![Platform-Linux](https://img.shields.io/badge/Platform-Linux-1793D1?style=flat-square&logo=linux&logoColor=white)](https://kernel.org) [![Language-C11](https://img.shields.io/badge/Language-C11-A8B9CC?style=flat-square&logo=c&logoColor=white)](https://gcc.gnu.org/) [![License-MIT](https://img.shields.io/badge/License-MIT-EE0000?style=flat-square&logo=license&logoColor=white)](LICENSE) [![Status](https://img.shields.io/badge/Status-Active-006400?style=flat-square)](#-roadmap) [![Tested-on](https://img.shields.io/badge/Tested%20on-Arch%20Linux-1793D1?style=flat-square&logo=arch-linux)](https://archlinux.org) [![Domain](https://img.shields.io/badge/Domain-Process%20Confinement-8A2BE2?style=flat-square)](#-threat-model)

---

## Etymology & Origin

The name **SYSCAGE** is a portmanteau of **Sys**call and **Cage** — a cage for system calls. It encapsulates the tool's purpose: confining a process to only the system calls it needs, blocking everything else.

Where LinSpec checks if protections are active and K-Scanner detects violations, SYSCAGE shifts from detection to **active restriction**. It learns what a process needs at runtime, then builds a seccomp-bpf filter that enforces that behavior.

---

## Overview

SYSCAGE is a three-phase tool that observes, generates, and enforces syscall-level policies on Linux processes.

**Core Pipeline:**

1. **Learn** — `syscage learn` — Running PID or command → `.trace` file
2. **Generate** — `syscage gen` — `.trace` file → `.syscage` profile
3. **Enforce** — `syscage enforce` / `syscage watch` — `.syscage` profile → seccomp-bpf filter via `prctl(2)`

---

## Features

- **Behavioral syscall profiling** — traces a process and records every syscall it makes
- **Automatic seccomp generation** — converts traced behavior into a ready-to-use seccomp-bpf filter
- **Ptrace-based tracing (zero deps)** — works on any Linux system without external libraries
- **eBPF tracing (optional)** — lower overhead when libbpf is available (`--ebpf`)
- **Critical syscall injection** — automatically includes essential syscalls (read, write, exit, etc.)
- **Multiple enforcement modes** — attach to running process, spawn new process, or watch with violation monitoring
- **C header export** — generate embeddable seccomp filter code (`--header`)
- **Subcommand CLI** — follows the `git`/`docker` pattern (`learn`, `gen`, `enforce`, `watch`)
- **Text-based profiles** — human-readable, diffable, and version-controllable
- **Pure C11** — minimal dependencies (system headers + libc)

---

## Example Output

```text
┌─ SYSCAGE ──────────────────┐
│ Kernel Policy Fence        │
│ Syscall Profiling/Seccomp  │
└────────────────────────────┘

[INF] 14:30:01  Tracing PID 1234 for 30 seconds...
[INF] 14:30:31  Traced 14203 syscalls in 30.0s
[INF] 14:30:31  Trace complete: 14203 syscalls observed, 21 unique.
[INF] 14:30:31  Trace saved to nginx.trace

[INF] 14:30:32  Profile saved to nginx.trace.syscage

  Profile Summary
  ──────────────────────────────
  Rules:        37
  Observations: 14203
  Source PID:   1234
  Duration:     30.0s
  Default:      KILL

  NR     SYSCALL
  ─────────────────
  0      read
  1      write
  2      open
  3      close
  4      stat
  5      fstat
  9      mmap
  10     mprotect
  11     munmap
  12     brk
  ... and 27 more

[INF] 14:30:33  Spawned PID 1298 under seccomp profile.
[INF] 14:30:33  Watching PID 1298 under seccomp profile.
```

---

## How It Works

SYSCAGE reads syscall data from the kernel through two backends:

- **Ptrace (default):** Uses `PTRACE_SYSCALL` to intercept every syscall entry, reads `orig_rax` from `struct user_regs_struct`, and records the syscall number.
- **eBPF (optional):** Uses `raw_tracepoint/sys_enter` for lower-overhead syscall capture.

The pipeline flow:

```
 PID or command
      │
      ▼
 ┌──────────┐   ┌────────────┐   ┌──────────────┐
 │  TRACER  │──>│ PROFILER   │──>│  ENFORCER    │
 │ ptrace/  │   │ generates  │   │ applies via  │
 │ eBPF     │   │ .syscage   │   │ prctl +      │
 │          │   │ profile    │   │ seccomp(2)   │
 └──────────┘   └────────────┘   └──────────────┘
      │               │                │
      ▼               ▼                ▼
   .trace        .syscage         process with
  (raw data)    (text rules)     seccomp filter
```

### Profile Generation

1. All syscalls observed above the frequency threshold are added to the allowlist
2. Critical syscalls (read, write, exit, getpid, etc.) are automatically injected
3. The profile is sorted by syscall number for readability
4. The default action for unknown syscalls is **KILL**

### Enforcement

The enforcer builds a seccomp-bpf filter (the same BPF used by `tcpdump`) and applies it via:

```
prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)   // prevent filter bypass
prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog)  // apply filter
```

---

## Build and Run

```bash
# 1. Clone the repository
git clone https://github.com/jeffersoncesarantunes/SYSCAGE.git
cd SYSCAGE

# 2. Compile
make clean && make
```

### 3. Profile a process (learn phase)

Trace every syscall a process makes. The **recommended way** (works on any Linux) is to **launch a command** under trace. You can also attach to a running process if your kernel allows it.

```bash
# Recommended: launch and trace a command (works everywhere)
sudo ./bin/syscage learn -d 5 -o ls.trace -- /bin/ls -la /tmp

# Optional: trace an already running process (by PID or name)
sudo ./bin/syscage learn -d 15 -o nginx.trace 1234
sudo ./bin/syscage learn -d 15 -o nginx.trace $(pidof nginx)
```

> **What each part means:**
> - `-d 5` — trace for 5 seconds
> - `-o ls.trace` — save results to file `ls.trace`
> - `-- /bin/ls -la /tmp` — the `--` separates SYSCAGE options from the command to launch
> - `1234` — PID of a running process to trace
> - `$(pidof nginx)` — resolves "nginx" to its PID automatically
>
> **Note:** Attaching to a running process requires `ptrace_scope = 0`. Most Linux distros (including Arch) default to `1`, which only allows tracing child processes. This is why Option A/B may fail with "Operation not permitted" — launch the command under trace instead (Option C, which always works).

### 4. Generate a seccomp profile (gen phase)

Convert the raw trace into a human-readable policy file:

```bash
sudo ./bin/syscage gen ls.trace
```

This creates `ls.trace.syscage` — a text file listing every allowed syscall.

You can also generate a C header for embedding into other programs:

```bash
sudo ./bin/syscage gen --header ls.trace
```

### 5. Enforce the profile (enforce / watch phase)

Apply the policy to a process. Use `enforce` to spawn a command silently, or `watch` to see its output and exit status:

```bash
# watch shows the command's output and waits for it to finish (recommended)
sudo ./bin/syscage watch -p ls.trace.syscage -- /bin/ls /tmp

# enforce spawns and returns immediately (for scripts/production)
sudo ./bin/syscage enforce -p ls.trace.syscage -e -- /bin/ls /tmp
```

> **What each part means:**
> - `-p ls.trace.syscage` — which profile to apply
> - `-e` — spawn a new process (instead of attaching to a running one)
> - `-- /bin/ls /tmp` — command to confine under the profile
> - `watch` — same as enforce, but **shows output** and logs if a blocked syscall is attempted

### Complete working example: `ls`

```bash
sudo ./bin/syscage learn -d 5 -o ls.trace -- /bin/ls -la /tmp
sudo ./bin/syscage gen ls.trace
sudo ./bin/syscage watch -p ls.trace.syscage -- /bin/ls /tmp
```

That's it. Three commands and you've confined `ls` to only the syscalls it used during profiling. If it runs the same as without SYSCAGE, the profile is complete.

---

## Operational Integrity

SYSCAGE is designed for safe profiling and enforcement:

- **Read-only during learning:** The ptracer never modifies the target's memory or execution
- **No kernel modification:** All profiling uses standard ptrace/seccomp APIs
- **Self-contained profiles:** Profiles are plain text — no binary state
- **Graceful fallback:** If ptrace fails, no changes are made to the system
- **Seccomp is process-scoped:** A restricted process cannot affect other processes
- **NO_NEW_PRIVS enforced:** Prevents filter bypass via `setuid` binaries

---

## Repository Structure

```
SYSCAGE/
├── docs/
│   ├── ARCHITECTURE.md                    System design and module boundaries
│   ├── OPERATION_MODEL.md                 Usage workflow and execution modes
│   ├── THREAT_MODEL.md                    Security scope and attack scenarios
│   └── BPF_REFERENCE.md                   Seccomp-BPF filter internals

├── include/
│   ├── syscage.h                          Main header and configuration
│   ├── tracer.h                           Tracer API
│   ├── profiler.h                         Profiler and profile API
│   └── enforcer.h                         Enforcer and seccomp API

├── src/
│   ├── main.c                             CLI entry point (subcommand dispatch)
│   ├── common.c                           Utilities (logging, file I/O, PID resolution)
│   ├── tracer.c                           Ptrace/eBPF tracer backend
│   ├── profiler.c                         Profile generation and I/O
│   └── enforcer.c                         Seccomp filter building and enforcement

├── tests/
│   └── test_profiler.c                    Unit tests for profiler and I/O

├── examples/
│   └── profiles/                          Example profiles

├── .clang-format

├── .gitignore

├── LICENSE

├── Makefile

└── README.md
```

---

## Tech Stack

- **Language:** C (C11)
- **Kernel Interface:** ptrace(2), prctl(2), seccomp(2)
- **Optional Backend:** eBPF (`raw_tracepoint/sys_enter`)
- **Filter Format:** seccomp-bpf (`struct sock_fprog` / `struct sock_filter`)
- **Build Tool:** GNU Make
- **Target Platforms:** Linux Kernel 5.x, 6.x (x86_64)

---

## Roadmap

- [x] Ptrace-based syscall tracer (no deps)
- [x] Trace file I/O (save/load .trace)
- [x] Profile generation from trace data
- [x] Text profile format (.syscage)
- [x] C header export for embedding
- [x] Seccomp filter building
- [x] Process spawn under filter (`enforce -e`)
- [x] Watch mode with violation monitoring
- [ ] eBPF backend (libbpf)
- [ ] Running process attach (ptrace seccomp injection)
- [ ] Profile merging (combine multiple traces)
- [ ] JSON profile export
- [ ] Systemd integration (generator mode)
- [ ] Container-aware profiling (Docker/k8s)
- [ ] Remote profiling over SSH

---

## Documentation

[![Docs-Architecture](https://img.shields.io/badge/Architecture-Design-00599C?style=flat-square&logo=linux&logoColor=white)](docs/ARCHITECTURE.md) [![Docs-Operation](https://img.shields.io/badge/Operation-Model-006400?style=flat-square&logo=gnu-bash&logoColor=white)](docs/OPERATION_MODEL.md) [![Docs-ThreatModel](https://img.shields.io/badge/Threat-Model-CC0000?style=flat-square&logo=target&logoColor=white)](docs/THREAT_MODEL.md) [![Docs-BPF](https://img.shields.io/badge/BPF-Reference-444444?style=flat-square&logo=linux&logoColor=white)](docs/BPF_REFERENCE.md)

---

## License

[![License-MIT](https://img.shields.io/badge/License-MIT-BD93F9?style=flat-square&logo=opensourceinitiative&logoColor=white)](LICENSE)

*This project is licensed under the MIT License.*


