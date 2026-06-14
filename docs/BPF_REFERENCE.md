# SYSCAGE BPF Reference

---

## Seccomp BPF

SYSCAGE generates seccomp-bpf (Berkeley Packet Filter) programs to enforce syscall policies.

seccomp-bpf is the same filter machinery used by `tcpdump` but repurposed to inspect `struct seccomp_data` instead of network packets.

## Filter Architecture

Every SYSCAGE filter follows this structure:

```
 0: LD    abs [offsetof(seccomp_data.nr)]   # load syscall number
 1: JEQ   #0        (read)      -> ALLOW    # if read, allow
 3: JEQ   #1        (write)     -> ALLOW    # if write, allow
 5: JEQ   #60       (exit)      -> ALLOW    # if exit, allow
...
 N: RET   KILL                                # default: deny
```

Each allowed syscall generates 2 instructions:

| Instruction | Purpose |
|---|---|
| `BPF_JUMP(BPF_JMP\|BPF_JEQ\|BPF_K, nr, 0, 1)` | If syscall == nr, skip next instruction (jump 0) → falls to ALLOW |
| `BPF_STMT(BPF_RET\|BPF_K, SECCOMP_RET_ALLOW)` | Allow this syscall |

The default action at the end is `SECCOMP_RET_KILL_PROCESS`.

## Generated Header Example

When using `syscage gen --header`, the output is a C header with a pre-built filter:

```c
static struct sock_filter syscage_filter[] = {
    BPF_STMT(BPF_LD|BPF_W|BPF_ABS, 0),                      /* load nr */
    BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K, 0, 0, 1),              /* read? */
    BPF_STMT(BPF_RET|BPF_K, SECCOMP_RET_ALLOW),
    BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K, 1, 0, 1),              /* write? */
    BPF_STMT(BPF_RET|BPF_K, SECCOMP_RET_ALLOW),
    /* ... more rules ... */
    BPF_STMT(BPF_RET|BPF_K, SECCOMP_RET_KILL),              /* default */
};

static struct sock_fprog syscage_prog = {
    .len = sizeof(syscage_filter) / sizeof(syscage_filter[0]),
    .filter = syscage_filter,
};
```

This header can be `#include`'d into any C program.

## Action Reference

| Action | seccomp constant | Effect |
|---|---|---|
| ALLOW | `SECCOMP_RET_ALLOW` | Allow the syscall |
| KILL | `SECCOMP_RET_KILL_PROCESS` | Kill the thread immediately |
| KILL_THREAD | `SECCOMP_RET_KILL_THREAD` | Kill only the calling thread |
| TRAP | `SECCOMP_RET_TRAP` | Deliver SIGSYS to the process |
| LOG | `SECCOMP_RET_LOG` | Allow but log (kernel 4.14+) |

## eBPF Tracer (Optional)

SYSCAGE's optional eBPF tracer uses `raw_tracepoint/sys_enter` to capture syscalls with minimal overhead.

**Build requirements:**
- libbpf (>=0.7)
- Clang (for BPF compilation)
- Kernel with `CONFIG_DEBUG_INFO_BTF`

**Usage:**
```
syscage learn -e -d 30 -o trace $(pidof target)
```

The eBPF path is **optional** and compiled out by default. Use `make WITH_EBPF=1` to enable it.
