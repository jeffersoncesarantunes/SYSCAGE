# SYSCAGE Operation Model

---

## Workflow

SYSCAGE operates in three distinct phases. Each phase builds on the previous one.

### Basic workflow

```
syscage learn -d 30 -o nginx.trace $(pidof nginx)
syscage gen -o nginx.syscage nginx.trace
syscage watch -p nginx.syscage -- /usr/sbin/nginx
```

### One-liner for quick profiling

```
syscage learn -d 10 -o ls.trace -- /bin/ls -la && \
syscage gen ls.trace && \
syscage enforce -p ls.trace.syscage -e -- /bin/ls -la
```

---

## Execution Modes

### syscage learn

Captures syscalls from a target and writes a `.trace` file.

```
# Attach to a running process by PID
syscage learn -d 30 -o nginx.trace 1234

# Attach by process name
syscage learn -d 10 -o sshd.trace $(pidof sshd)

# Execute a command under trace
syscage learn -d 5 -o ls.trace -- /bin/ls -laR /

# Trace for 60 seconds with eBPF backend
syscage learn -d 60 -e -o firefox.trace $(pidof firefox)
```

**Important:** The trace duration should cover the process's typical behavior. A web server needs at least 30 seconds of requests. A short-lived command (like `ls`) only needs a few seconds.

### syscage gen

Converts a `.trace` file into a seccomp policy profile.

```
# Basic generation
syscage gen nginx.trace

# Specify output file
syscage gen -o custom.syscage nginx.trace

# Also emit a C header for embedding
syscage gen --header nginx.trace

# Only include syscalls observed 5+ times
syscage gen -f 5 nginx.trace
```

### syscage enforce

Applies a profile to a process.

```
# Attach to a running process (experimental)
syscage enforce -p nginx.syscage 1234

# Spawn a new process under the profile
syscage enforce -p ls.syscage -e -- /bin/ls -la
```

### syscage watch

Spawns a process under a profile and monitors for violations.

```
syscage watch -p nginx.syscage -- /usr/sbin/nginx

# With abort on first violation
syscage watch -p nginx.syscage -a -- /usr/sbin/nginx
```

---

## Critical Syscalls

SYSCAGE automatically injects these syscalls into every generated profile:

| Number | Name | Reason |
|---|---|---|
| 0 | read | I/O |
| 1 | write | I/O |
| 3 | close | I/O |
| 13 | rt_sigaction | Signal handling |
| 15 | rt_sigreturn | Signal handling |
| 35 | nanosleep | Timing |
| 39 | getpid | Process info |
| 60 | exit | Termination |
| 96 | gettimeofday | Timing |
| 157 | prctl | Runtime control |
| 186 | gettid | Thread info |
| 228 | clock_gettime | Timing |
| 231 | exit_group | Termination |
| 317 | seccomp | Filter self-management |

These ensure that even if the trace missed a rarely-called function, the process can still operate normally.

---

## Violation Detection

When a process under enforcement calls a syscall not in its profile:

- **SIGSYS** is delivered to the process
- The kernel kills the process (if default action is KILL)
- In watch mode, the violation is logged

---

## Performance Impact

- **Ptrace tracing:** adds measurable overhead (~2-10x slowdown on syscall-heavy workloads). This is expected — ptrace is an observation tool, not production-safe.
- **eBPF tracing:** negligible overhead (<5% on most workloads).
- **Seccomp enforcement:** near-zero overhead for allowed syscalls. Blocked syscalls incur SIGSYS delivery cost.
