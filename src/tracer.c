#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <errno.h>
#include <time.h>
#include <sys/ptrace.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <sys/prctl.h>
#include <linux/audit.h>
#include <linux/filter.h>
#include <linux/seccomp.h>

#include "syscage.h"
#include "tracer.h"

static const char *g_syscall_names[SYSCAGE_MAX_SYSCALL] = {
    [0]   = "read",
    [1]   = "write",
    [2]   = "open",
    [3]   = "close",
    [4]   = "stat",
    [5]   = "fstat",
    [6]   = "lstat",
    [7]   = "poll",
    [8]   = "lseek",
    [9]   = "mmap",
    [10]  = "mprotect",
    [11]  = "munmap",
    [12]  = "brk",
    [13]  = "rt_sigaction",
    [14]  = "rt_sigprocmask",
    [15]  = "rt_sigreturn",
    [16]  = "ioctl",
    [17]  = "pread64",
    [18]  = "pwrite64",
    [19]  = "readv",
    [20]  = "writev",
    [21]  = "access",
    [22]  = "pipe",
    [23]  = "select",
    [24]  = "sched_yield",
    [25]  = "mremap",
    [26]  = "msync",
    [27]  = "mincore",
    [28]  = "madvise",
    [29]  = "shmget",
    [30]  = "shmat",
    [31]  = "shmctl",
    [32]  = "dup",
    [33]  = "dup2",
    [34]  = "pause",
    [35]  = "nanosleep",
    [36]  = "getitimer",
    [37]  = "alarm",
    [38]  = "setitimer",
    [39]  = "getpid",
    [40]  = "sendfile",
    [41]  = "socket",
    [42]  = "connect",
    [43]  = "accept",
    [44]  = "sendto",
    [45]  = "recvfrom",
    [46]  = "sendmsg",
    [47]  = "recvmsg",
    [48]  = "shutdown",
    [49]  = "bind",
    [50]  = "listen",
    [51]  = "getsockname",
    [52]  = "getpeername",
    [53]  = "socketpair",
    [54]  = "setsockopt",
    [55]  = "getsockopt",
    [56]  = "clone",
    [57]  = "fork",
    [58]  = "vfork",
    [59]  = "execve",
    [60]  = "exit",
    [61]  = "wait4",
    [62]  = "kill",
    [63]  = "uname",
    [78]  = "getdents",
    [79]  = "getcwd",
    [80]  = "chdir",
    [82]  = "rename",
    [83]  = "mkdir",
    [84]  = "rmdir",
    [85]  = "creat",
    [86]  = "link",
    [87]  = "unlink",
    [88]  = "symlink",
    [89]  = "readlink",
    [90]  = "chmod",
    [91]  = "fchmod",
    [92]  = "chown",
    [93]  = "fchown",
    [94]  = "lchown",
    [96]  = "gettimeofday",
    [97]  = "getrlimit",
    [98]  = "getrusage",
    [99]  = "sysinfo",
    [100] = "times",
    [101] = "ptrace",
    [102] = "getuid",
    [104] = "getgid",
    [105] = "setuid",
    [106] = "setgid",
    [107] = "geteuid",
    [108] = "getegid",
    [110] = "getppid",
    [111] = "getpgrp",
    [112] = "setsid",
    [113] = "setreuid",
    [114] = "setregid",
    [115] = "getgroups",
    [116] = "setgroups",
    [118] = "setresuid",
    [119] = "getresuid",
    [120] = "setresgid",
    [121] = "getresgid",
    [122] = "getpgid",
    [123] = "setfsuid",
    [124] = "setfsgid",
    [125] = "getsid",
    [126] = "capget",
    [127] = "capset",
    [128] = "rt_sigpending",
    [129] = "rt_sigtimedwait",
    [130] = "rt_sigqueueinfo",
    [131] = "rt_sigsuspend",
    [132] = "sigaltstack",
    [133] = "utime",
    [134] = "mknod",
    [137] = "statfs",
    [138] = "fstatfs",
    [139] = "sysfs",
    [140] = "getpriority",
    [141] = "setpriority",
    [142] = "sched_setparam",
    [143] = "sched_getparam",
    [144] = "sched_setscheduler",
    [145] = "sched_getscheduler",
    [146] = "sched_get_priority_max",
    [147] = "sched_get_priority_min",
    [148] = "sched_rr_get_interval",
    [149] = "mlock",
    [150] = "munlock",
    [151] = "mlockall",
    [152] = "munlockall",
    [153] = "vhangup",
    [154] = "modify_ldt",
    [155] = "pivot_root",
    [156] = "_sysctl",
    [157] = "prctl",
    [158] = "arch_prctl",
    [159] = "adjtimex",
    [160] = "setrlimit",
    [161] = "chroot",
    [162] = "sync",
    [163] = "acct",
    [164] = "settimeofday",
    [165] = "mount",
    [166] = "umount2",
    [167] = "swapon",
    [168] = "swapoff",
    [169] = "reboot",
    [170] = "sethostname",
    [171] = "setdomainname",
    [172] = "iopl",
    [173] = "ioperm",
    [174] = "create_module",
    [175] = "init_module",
    [176] = "delete_module",
    [177] = "get_kernel_syms",
    [178] = "query_module",
    [179] = "quotactl",
    [180] = "nfsservctl",
    [181] = "getpmsg",
    [182] = "putpmsg",
    [183] = "afs_syscall",
    [184] = "tuxcall",
    [185] = "security",
    [186] = "gettid",
    [187] = "readahead",
    [188] = "setxattr",
    [189] = "lsetxattr",
    [190] = "fsetxattr",
    [191] = "getxattr",
    [192] = "lgetxattr",
    [193] = "fgetxattr",
    [194] = "listxattr",
    [195] = "llistxattr",
    [196] = "flistxattr",
    [197] = "removexattr",
    [198] = "lremovexattr",
    [199] = "fremovexattr",
    [200] = "tkill",
    [201] = "time",
    [202] = "futex",
    [203] = "sched_setaffinity",
    [204] = "sched_getaffinity",
    [205] = "set_thread_area",
    [206] = "io_setup",
    [207] = "io_destroy",
    [208] = "io_getevents",
    [209] = "io_submit",
    [210] = "io_cancel",
    [211] = "get_thread_area",
    [212] = "lookup_dcookie",
    [213] = "epoll_create",
    [214] = "epoll_ctl_old",
    [215] = "epoll_wait_old",
    [216] = "remap_file_pages",
    [217] = "getdents64",
    [218] = "set_tid_address",
    [219] = "restart_syscall",
    [220] = "semtimedop",
    [221] = "fadvise64",
    [222] = "timer_create",
    [223] = "timer_settime",
    [224] = "timer_gettime",
    [225] = "timer_getoverrun",
    [226] = "timer_delete",
    [227] = "clock_settime",
    [228] = "clock_gettime",
    [229] = "clock_getres",
    [230] = "clock_nanosleep",
    [231] = "exit_group",
    [232] = "epoll_wait",
    [233] = "epoll_ctl",
    [234] = "tgkill",
    [235] = "utimes",
    [236] = "vserver",
    [237] = "mbind",
    [238] = "set_mempolicy",
    [239] = "get_mempolicy",
    [240] = "mq_open",
    [241] = "mq_unlink",
    [242] = "mq_timedsend",
    [243] = "mq_timedreceive",
    [244] = "mq_notify",
    [245] = "mq_getsetattr",
    [246] = "kexec_load",
    [247] = "waitid",
    [248] = "add_key",
    [249] = "request_key",
    [250] = "keyctl",
    [251] = "ioprio_set",
    [252] = "ioprio_get",
    [253] = "inotify_init",
    [254] = "inotify_add_watch",
    [255] = "inotify_rm_watch",
    [256] = "migrate_pages",
    [257] = "openat",
    [258] = "mkdirat",
    [259] = "mknodat",
    [260] = "fchownat",
    [261] = "futimesat",
    [262] = "newfstatat",
    [263] = "unlinkat",
    [264] = "renameat",
    [265] = "linkat",
    [266] = "symlinkat",
    [267] = "readlinkat",
    [268] = "fchmodat",
    [269] = "faccessat",
    [270] = "pselect6",
    [271] = "ppoll",
    [272] = "unshare",
    [273] = "set_robust_list",
    [274] = "get_robust_list",
    [275] = "splice",
    [276] = "tee",
    [277] = "sync_file_range",
    [278] = "vmsplice",
    [279] = "move_pages",
    [280] = "utimensat",
    [281] = "epoll_pwait",
    [282] = "signalfd",
    [283] = "timerfd_create",
    [284] = "eventfd",
    [285] = "fallocate",
    [286] = "timerfd_settime",
    [287] = "timerfd_gettime",
    [288] = "accept4",
    [289] = "signalfd4",
    [290] = "eventfd2",
    [291] = "epoll_create1",
    [292] = "dup3",
    [293] = "pipe2",
    [294] = "inotify_init1",
    [295] = "preadv",
    [296] = "pwritev",
    [297] = "rt_tgsigqueueinfo",
    [298] = "perf_event_open",
    [299] = "recvmmsg",
    [300] = "fanotify_init",
    [301] = "fanotify_mark",
    [302] = "prlimit64",
    [303] = "name_to_handle_at",
    [304] = "open_by_handle_at",
    [305] = "clock_adjtime",
    [306] = "syncfs",
    [307] = "sendmmsg",
    [308] = "setns",
    [309] = "getcpu",
    [310] = "process_vm_readv",
    [311] = "process_vm_writev",
    [312] = "kcmp",
    [313] = "finit_module",
    [314] = "sched_setattr",
    [315] = "sched_getattr",
    [316] = "renameat2",
    [317] = "seccomp",
    [318] = "getrandom",
    [319] = "memfd_create",
    [320] = "kexec_file_load",
    [321] = "bpf",
    [322] = "execveat",
    [323] = "userfaultfd",
    [324] = "membarrier",
    [325] = "mlock2",
    [326] = "copy_file_range",
    [327] = "preadv2",
    [328] = "pwritev2",
    [329] = "pkey_mprotect",
    [330] = "pkey_alloc",
    [331] = "pkey_free",
    [332] = "statx",
    [333] = "io_pgetevents",
    [334] = "rseq",
    [424] = "pidfd_send_signal",
    [425] = "io_uring_setup",
    [426] = "io_uring_enter",
    [427] = "io_uring_register",
    [428] = "open_tree",
    [429] = "move_mount",
    [430] = "fsopen",
    [431] = "fsconfig",
    [432] = "fsmount",
    [433] = "fspick",
    [434] = "pidfd_open",
    [435] = "clone3",
    [436] = "close_range",
    [437] = "openat2",
    [438] = "pidfd_getfd",
    [439] = "faccessat2",
    [440] = "process_madvise",
    [441] = "epoll_pwait2",
    [442] = "mount_setattr",
    [443] = "quotactl_fd",
    [444] = "landlock_create_ruleset",
    [445] = "landlock_add_rule",
    [446] = "landlock_restrict_self",
    [447] = "memfd_secret",
    [448] = "process_mrelease",
    [449] = "futex_waitv",
    [450] = "set_mempolicy_home_node",
};

static char g_unknown_name[32];

const char *tracer_syscall_name(long number)
{
    if (number >= 0 && number < SYSCAGE_MAX_SYSCALL
        && g_syscall_names[number]) {
        return g_syscall_names[number];
    }
    snprintf(g_unknown_name, sizeof(g_unknown_name), "syscall_%ld", number);
    return g_unknown_name;
}

typedef struct {
    long number;
    unsigned long count;
} syscall_entry_t;

struct trace_context {
    pid_t target_pid;
    syscall_entry_t entries[SYSCAGE_MAX_SYSCALL];
    unsigned long total_seen;
    int active;
};

static void trace_entry_record(struct trace_context *ctx, long nr)
{
    if (nr >= 0 && nr < SYSCAGE_MAX_SYSCALL) {
        ctx->entries[nr].number = nr;
        ctx->entries[nr].count++;
    }
    ctx->total_seen++;
}

static trace_result_t *context_to_result(struct trace_context *ctx,
                                          double duration)
{
    trace_result_t *tr = calloc(1, sizeof(trace_result_t));
    if (!tr) return NULL;

    size_t n = 0;
    for (int i = 0; i < SYSCAGE_MAX_SYSCALL; i++) {
        if (ctx->entries[i].count > 0) n++;
    }

    tr->calls = calloc(n, sizeof(syscall_obs_t));
    if (!tr->calls) {
        free(tr);
        return NULL;
    }

    size_t idx = 0;
    for (int i = 0; i < SYSCAGE_MAX_SYSCALL; i++) {
        if (ctx->entries[i].count > 0) {
            tr->calls[idx].number = ctx->entries[i].number;
            tr->calls[idx].count = ctx->entries[i].count;
            idx++;
        }
    }

    tr->count = n;
    tr->total = ctx->total_seen;
    tr->target_pid = ctx->target_pid;
    tr->duration_sec = duration;

    return tr;
}

static int ptrace_trace_pid(struct trace_context *ctx, int duration_sec)
{
    int status;
    struct timespec start, now;
    int traced_pid = ctx->target_pid;

    clock_gettime(CLOCK_MONOTONIC, &start);

    if (ptrace(PTRACE_SEIZE, traced_pid, NULL, NULL) < 0) {
        log_error("ptrace(PTRACE_SEIZE) failed: %s\n", strerror(errno));
        return -1;
    }

    if (ptrace(PTRACE_INTERRUPT, traced_pid, NULL, NULL) < 0) {
        log_error("ptrace(PTRACE_INTERRUPT) failed\n");
        ptrace(PTRACE_DETACH, traced_pid, NULL, NULL);
        return -1;
    }

    waitpid(traced_pid, &status, 0);

    if (ptrace(PTRACE_SETOPTIONS, traced_pid, NULL,
               (void *)(uintptr_t)PTRACE_O_TRACESYSGOOD) < 0) {
        log_error("ptrace(PTRACE_SETOPTIONS) failed\n");
        ptrace(PTRACE_DETACH, traced_pid, NULL, NULL);
        return -1;
    }

    ctx->active = 1;

    while (ctx->active) {
        clock_gettime(CLOCK_MONOTONIC, &now);
        double elapsed = (now.tv_sec - start.tv_sec)
                       + (now.tv_nsec - start.tv_nsec) / 1e9;

        if (duration_sec > 0 && elapsed >= duration_sec) {
            break;
        }

        if (ptrace(PTRACE_SYSCALL, traced_pid, NULL, NULL) < 0) {
            break;
        }

        if (waitpid(traced_pid, &status, 0) < 0) break;

        if (WIFEXITED(status) || WIFSIGNALED(status)) {
            log_info("Process %d exited.\n", traced_pid);
            break;
        }

#if defined(__x86_64__)
        struct user_regs_struct regs;
        if (ptrace(PTRACE_GETREGS, traced_pid, NULL, &regs) < 0) {
            break;
        }

        long nr = (long)regs.orig_rax;
#else
        long nr = 0;
        (void)traced_pid;
        break;
#endif
        trace_entry_record(ctx, nr);

        if (ptrace(PTRACE_SYSCALL, traced_pid, NULL, NULL) < 0) break;

        if (waitpid(traced_pid, &status, 0) < 0) break;

        if (WIFEXITED(status) || WIFSIGNALED(status)) {
            break;
        }
    }

    ptrace(PTRACE_DETACH, traced_pid, NULL, NULL);

    clock_gettime(CLOCK_MONOTONIC, &now);
    double elapsed = (now.tv_sec - start.tv_sec)
                   + (now.tv_nsec - start.tv_nsec) / 1e9;

    log_info("Traced %lu syscalls in %.3fs\n", ctx->total_seen, elapsed);
    return 0;
}

static int ptrace_exec_and_trace(struct trace_context *ctx,
                                  const char *cmd,
                                  char *const argv[],
                                  int duration_sec)
{
    pid_t child = fork();
    if (child == 0) {
        ptrace(PTRACE_TRACEME, 0, NULL, NULL);
        raise(SIGSTOP);
        execvp(cmd, argv);
        _exit(127);
    }

    if (child < 0) {
        log_error("fork() failed: %s\n", strerror(errno));
        return -1;
    }

    int status;
    waitpid(child, &status, 0);

    ctx->target_pid = child;
    ctx->active = 1;

    struct timespec start, now;
    clock_gettime(CLOCK_MONOTONIC, &start);

    if (ptrace(PTRACE_SETOPTIONS, child, NULL,
               (void *)(uintptr_t)PTRACE_O_TRACESYSGOOD) < 0) {
        log_error("ptrace(PTRACE_SETOPTIONS) failed\n");
        ptrace(PTRACE_DETACH, child, NULL, NULL);
        return -1;
    }

    while (ctx->active) {
        clock_gettime(CLOCK_MONOTONIC, &now);
        double elapsed = (now.tv_sec - start.tv_sec)
                       + (now.tv_nsec - start.tv_nsec) / 1e9;

        if (duration_sec > 0 && elapsed >= duration_sec) {
            kill(child, SIGTERM);
            break;
        }

        if (ptrace(PTRACE_SYSCALL, child, NULL, NULL) < 0) break;

        if (waitpid(child, &status, 0) < 0) break;

        if (WIFEXITED(status) || WIFSIGNALED(status)) {
            break;
        }

        struct user_regs_struct regs;
        if (ptrace(PTRACE_GETREGS, child, NULL, &regs) < 0) break;

        long nr = (long)regs.orig_rax;
        trace_entry_record(ctx, nr);

        if (ptrace(PTRACE_SYSCALL, child, NULL, NULL) < 0) break;

        if (waitpid(child, &status, 0) < 0) break;

        if (WIFEXITED(status) || WIFSIGNALED(status)) break;
    }

    ptrace(PTRACE_DETACH, child, NULL, NULL);

    clock_gettime(CLOCK_MONOTONIC, &now);
    double elapsed = (now.tv_sec - start.tv_sec)
                   + (now.tv_nsec - start.tv_nsec) / 1e9;

    log_info("Traced %lu syscalls in %.3fs\n", ctx->total_seen, elapsed);
    return 0;
}

trace_result_t *tracer_attach(pid_t pid, const tracer_opts_t *opts)
{
    tracer_opts_t default_opts = TRACER_OPTS_DEFAULT;
    if (!opts) opts = &default_opts;

    struct trace_context ctx;
    memset(&ctx, 0, sizeof(ctx));
    ctx.target_pid = pid;

    if (ptrace_trace_pid(&ctx, opts->duration_sec) != 0) {
        return NULL;
    }

    return context_to_result(&ctx, opts->duration_sec);
}

trace_result_t *tracer_exec(const char *cmd, char *const argv[],
                             const tracer_opts_t *opts)
{
    tracer_opts_t default_opts = TRACER_OPTS_DEFAULT;
    if (!opts) opts = &default_opts;

    struct trace_context ctx;
    memset(&ctx, 0, sizeof(ctx));

    if (ptrace_exec_and_trace(&ctx, cmd, argv, opts->duration_sec) != 0) {
        return NULL;
    }

    return context_to_result(&ctx, opts->duration_sec);
}

int tracer_save(const trace_result_t *tr, const char *path)
{
    FILE *f = fopen(path, "w");
    if (!f) {
        log_error("Cannot write trace to %s\n", path);
        return -1;
    }

    fprintf(f, "# SYSCAGE trace\n");
    fprintf(f, "# PID: %d\n", tr->target_pid);
    fprintf(f, "# Duration: %.1fs\n", tr->duration_sec);
    fprintf(f, "# Total calls: %lu\n", tr->total);
    fprintf(f, "# Unique calls: %zu\n", tr->count);
    fprintf(f, "#\n");
    fprintf(f, "# Format: <syscall_number> <count> <name>\n");

    for (size_t i = 0; i < tr->count; i++) {
        fprintf(f, "%ld %lu %s\n",
                tr->calls[i].number,
                tr->calls[i].count,
                tracer_syscall_name(tr->calls[i].number));
    }

    fclose(f);
    return 0;
}

trace_result_t *tracer_load(const char *path)
{
    char *data = NULL;
    syscage_read_file(path, &data);
    if (!data) return NULL;

    trace_result_t *tr = calloc(1, sizeof(trace_result_t));
    if (!tr) {
        free(data);
        return NULL;
    }

    size_t capacity = 256;
    tr->calls = calloc(capacity, sizeof(syscall_obs_t));
    if (!tr->calls) {
        free(data);
        free(tr);
        return NULL;
    }

    char *line = data;
    char *next;
    size_t idx = 0;

    while (line && *line) {
        next = strchr(line, '\n');
        if (next) *next++ = '\0';

        if (line[0] == '\0') {
            line = next;
            continue;
        }

        if (line[0] == '#') {
            if (strncmp(line, "# PID:", 6) == 0) {
                if (sscanf(line, "# PID: %d", &tr->target_pid) != 1)
                    log_warn("Malformed PID line in trace\n");
            } else if (strncmp(line, "# Duration:", 10) == 0) {
                if (sscanf(line, "# Duration: %lf", &tr->duration_sec) != 1)
                    log_warn("Malformed Duration line in trace\n");
            } else if (strncmp(line, "# Total calls:", 13) == 0) {
                unsigned long val;
                if (sscanf(line, "# Total calls: %lu", &val) == 1)
                    tr->total = val;
            }
            line = next;
            continue;
        }

        long nr;
        unsigned long cnt;
        if (sscanf(line, "%ld %lu", &nr, &cnt) == 2) {
            if (nr < 0 || nr >= SYSCAGE_MAX_SYSCALL) {
                log_warn("Skipping out-of-range syscall %ld\n", nr);
                line = next;
                continue;
            }
            if (idx >= capacity) {
                capacity *= 2;
                syscall_obs_t *newc = realloc(tr->calls,
                    capacity * sizeof(syscall_obs_t));
                if (!newc) break;
                tr->calls = newc;
            }
            tr->calls[idx].number = nr;
            tr->calls[idx].count = cnt;
            idx++;
        }

        line = next;
    }

    tr->count = idx;

    if (tr->total == 0) {
        for (size_t i = 0; i < tr->count; i++) {
            tr->total += tr->calls[i].count;
        }
    }

    free(data);
    return tr;
}

trace_result_t *tracer_merge(trace_result_t **traces, size_t count)
{
    if (!traces || count == 0) return NULL;

    syscall_entry_t entries[SYSCAGE_MAX_SYSCALL] = {{0}};
    unsigned long total = 0;

    for (size_t t = 0; t < count; t++) {
        for (size_t i = 0; i < traces[t]->count; i++) {
            long nr = traces[t]->calls[i].number;
            if (nr >= 0 && nr < (long)SYSCAGE_MAX_SYSCALL) {
                entries[nr].number = nr;
                entries[nr].count += traces[t]->calls[i].count;
            }
            total += traces[t]->calls[i].count;
        }
    }

    size_t n = 0;
    for (int i = 0; i < SYSCAGE_MAX_SYSCALL; i++) {
        if (entries[i].count > 0) n++;
    }

    trace_result_t *tr = calloc(1, sizeof(trace_result_t));
    if (!tr) return NULL;

    tr->calls = calloc(n, sizeof(syscall_obs_t));
    if (!tr->calls) {
        free(tr);
        return NULL;
    }

    size_t idx = 0;
    for (int i = 0; i < SYSCAGE_MAX_SYSCALL; i++) {
        if (entries[i].count > 0) {
            tr->calls[idx].number = entries[i].number;
            tr->calls[idx].count = entries[i].count;
            idx++;
        }
    }

    tr->count = n;
    tr->total = total;
    tr->target_pid = 0;
    tr->duration_sec = 0.0;

    return tr;
}

void tracer_free(trace_result_t *tr)
{
    if (tr) {
        free(tr->calls);
        free(tr);
    }
}
