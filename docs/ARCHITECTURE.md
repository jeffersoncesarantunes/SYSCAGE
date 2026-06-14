# SYSCAGE Architecture

SYSCAGE is organized as a three-phase pipeline, where each phase produces an artifact consumed by the next.

```
 LEARN ──> GEN ──> ENFORCE/WATCH
 trace     profile  seccomp filter
  │         │         │
  ▼         ▼         ▼
 .trace    .syscage   kernel
```

---

## Phase 1: LEARN (Tracer)

The tracer attaches to a process via **ptrace** (fallback) or **eBPF** (optional) and records every system call the process makes.

**Two backends:**

- **Ptrace (default, no deps):** Uses `PTRACE_SEIZE`/`PTRACE_SYSCALL` to intercept each syscall entry, reads `orig_rax` from `struct user_regs_struct`, and records the syscall number and frequency.
- **eBPF (optional, needs libbpf):** Attaches `raw_tracepoint/sys_enter` to capture syscalls with minimal overhead. Enabled via `--ebpf`.

**Output:** A `.trace` file containing syscall numbers and their observed frequencies.

---

## Phase 2: GEN (Profiler)

The profiler reads a `.trace` file and generates a seccomp profile (`.syscage`) by:

1. Whitelisting all observed syscalls that meet the minimum frequency threshold
2. Injecting critical syscalls (read, write, exit, etc.) that every process needs
3. Sorting by syscall number

**Profile format:** Text-based, one syscall per line with action flag (`A`=ALLOW, `K`=KILL). Human-readable and version-controllable.

**Optional:** C header output (`-H`) that generates a ready-to-compile `sock_fprog` structure.

---

## Phase 3: ENFORCE (Enforcer)

The enforcer compiles a `.syscage` profile into a seccomp BPF filter and applies it to a process.

**Three modes:**

| Mode | Description |
|---|---|
| `attach` | Injects filter into a running process (experimental, requires ptrace) |
| `exec` | Forks a child, applies filter via `prctl(PR_SET_SECCOMP)`, then execs |
| `watch` | Same as exec but monitors for SIGSYS violations |

---

## Data Flow

```
             ┌──────────┐
  pid/cmd ──>│  TRACER  │──> .trace
             └──────────┘
                  │
                  ▼
             ┌──────────┐
   .trace ──>│ PROFILER │──> .syscage (text profile)
             └──────────┘        .h (C header)
                  │
                  ▼
             ┌───────────┐
  .syscage ─>│ ENFORCER  │──> seccomp(2) filter applied to process
             └───────────┘
```

---

## Module Boundaries

```
┌─────────────────────────────────────────────────────┐
│                      CLI (main.c)                    │
│  learn / gen / enforce / watch subcommand dispatch  │
├─────────────────────────────────────────────────────┤
│     src/tracer.c       src/profiler.c  src/enforcer.c│
│  ptrace/eBPF backend  rule generation  seccomp apply│
├─────────────────────────────────────────────────────┤
│                    include/                           │
│          syscage.h / tracer.h / profiler.h / enforcer.h
├─────────────────────────────────────────────────────┤
│                  docs/                                │
│   ARCHITECTURE / OPERATION_MODEL / THREAT_MODEL / BPF
└─────────────────────────────────────────────────────┘
```

---

## Design Decisions

- **Ptrace as default backend:** Zero external dependencies. Every Linux system has ptrace. eBPF is a compile-time option.
- **Text-based profiles:** Human readable, diffable, and version-controllable. No binary format lock-in.
- **Subcommand CLI:** Follows the `git`/`docker` pattern for discoverability and composition (as opposed to K-Scanner's flag-heavy approach).
- **Critical syscall injection:** ensures the generated filter never blocks essential process operations even if the trace was incomplete.
- **NO_NEW_PRIVS before SECCOMP:** Required by the kernel to prevent filter bypass via privilege escalation.
