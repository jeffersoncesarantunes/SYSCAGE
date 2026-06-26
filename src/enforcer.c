#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <errno.h>
#include <sys/ptrace.h>
#include <sys/prctl.h>
#include <sys/wait.h>
#include <sys/user.h>
#include <linux/seccomp.h>
#include <linux/filter.h>
#include <linux/audit.h>

#include "syscage.h"
#include "enforcer.h"
#include "profiler.h"
#include "tracer.h"

static int g_child_pid = 0;

static void child_sig_handler(int sig)
{
    (void)sig;
    if (g_child_pid > 0) {
        kill(g_child_pid, SIGTERM);
    }
}

static struct sock_fprog *build_seccomp_filter(profile_t *pf)
{
    size_t insn_count = 1 + (pf->rule_count * 2) + 1;
    struct sock_filter *filter = calloc(insn_count, sizeof(struct sock_filter));
    if (!filter) return NULL;

    size_t idx = 0;

    filter[idx++] = (struct sock_filter)BPF_STMT(BPF_LD | BPF_W | BPF_ABS,
        offsetof(struct seccomp_data, nr));

    for (size_t i = 0; i < pf->rule_count; i++) {
        if (pf->rules[i].action == ACTION_ALLOW) {
            filter[idx++] = (struct sock_filter)BPF_JUMP(
                BPF_JMP | BPF_JEQ | BPF_K,
                (unsigned int)pf->rules[i].syscall_number,
                0, 1);
            filter[idx++] = (struct sock_filter)BPF_STMT(
                BPF_RET | BPF_K, SECCOMP_RET_ALLOW);
        }
    }

    switch (pf->default_action) {
    case ACTION_KILL:
        filter[idx++] = (struct sock_filter)BPF_STMT(
            BPF_RET | BPF_K, SECCOMP_RET_KILL);
        break;
    case ACTION_TRAP:
        filter[idx++] = (struct sock_filter)BPF_STMT(
            BPF_RET | BPF_K, SECCOMP_RET_TRAP);
        break;
    case ACTION_LOG:
        filter[idx++] = (struct sock_filter)BPF_STMT(
            BPF_RET | BPF_K, SECCOMP_RET_LOG);
        break;
    default:
        filter[idx++] = (struct sock_filter)BPF_STMT(
            BPF_RET | BPF_K, SECCOMP_RET_KILL);
        break;
    }

    struct sock_fprog *prog = calloc(1, sizeof(struct sock_fprog));
    if (!prog) {
        free(filter);
        return NULL;
    }

    prog->len = (unsigned short)idx;
    prog->filter = filter;

    return prog;
}

static void free_filter(struct sock_fprog *prog)
{
    if (prog) {
        free(prog->filter);
        free(prog);
    }
}

/*
 * Find the first writable memory region in the target process
 * large enough to hold our BPF filter data.
 */
static unsigned long find_writable_region(pid_t pid, size_t min_size)
{
    char path[64];
    snprintf(path, sizeof(path), "/proc/%d/maps", pid);

    char *data = NULL;
    syscage_read_file(path, &data);
    if (!data) return 0;

    unsigned long addr = 0;
    char *line = data;
    char *next;

    while (line && *line) {
        next = strchr(line, '\n');
        if (next) *next++ = '\0';

        unsigned long start, end;
        char perms[8];
        if (sscanf(line, "%lx-%lx %4s", &start, &end, perms) == 3) {
            if (perms[1] == 'w' && (end - start) >= min_size) {
                addr = start;
                break;
            }
        }
        line = next;
    }

    free(data);
    return addr;
}

/*
 * Write a buffer into the target process memory via PTRACE_POKEDATA.
 */
static int ptrace_write_mem(pid_t pid, unsigned long addr,
                            const void *buf, size_t len)
{
    const unsigned char *bytes = (const unsigned char *)buf;
    for (size_t i = 0; i < len; i += sizeof(long)) {
        unsigned long word = 0;
        size_t copy = len - i;
        if (copy > sizeof(long)) copy = sizeof(long);
        memcpy(&word, bytes + i, copy);
        if (ptrace(PTRACE_POKEDATA, pid, (void *)(addr + i),
                   (void *)(unsigned long)word) < 0) {
            return -1;
        }
    }
    return 0;
}

/*
 * Inject a single syscall into the target process.
 *
 * Overwrites the instruction at the current RIP with a
 * syscall;int3 gadget, sets registers for the desired syscall,
 * continues execution, and waits for the int3 to fire.
 * The original instruction and register state are restored
 * before returning.
 *
 * Returns the syscall return value (rax) on success, -1 on error.
 */
static long ptrace_inject_syscall(pid_t pid, long number,
                                   long arg1, long arg2, long arg3,
                                   long arg4, long arg5)
{
    struct user_regs_struct regs;
    if (ptrace(PTRACE_GETREGS, pid, NULL, &regs) < 0) return -1;

    /* Save the original instruction word at RIP */
    long saved_insn = ptrace(PTRACE_PEEKTEXT, pid,
                             (void *)(unsigned long)regs.rip, NULL);
    if (saved_insn == -1 && errno != 0) return -1;

    /*
     * Write a syscall;int3 gadget at RIP (8 bytes):
     *   memory: 0F 05 CC 90 90 90 90 90
     *   0F 05 = syscall, CC = int3, 90 = nop padding
     */
    unsigned long gadget = 0x9090909090CC050FULL;
    if (ptrace(PTRACE_POKETEXT, pid,
               (void *)(unsigned long)regs.rip,
               (void *)(unsigned long)gadget) < 0) {
        return -1;
    }

    /* Set up registers for the desired syscall */
    struct user_regs_struct new_regs = regs;
    new_regs.rax = number;
    new_regs.rdi = arg1;
    new_regs.rsi = arg2;
    new_regs.rdx = arg3;
    new_regs.r10 = arg4;
    new_regs.r8  = arg5;
    /* RIP stays at regs.rip — points to our gadget */

    if (ptrace(PTRACE_SETREGS, pid, NULL, &new_regs) < 0) {
        ptrace(PTRACE_POKETEXT, pid,
               (void *)(unsigned long)regs.rip,
               (void *)(unsigned long)saved_insn);
        return -1;
    }

    /* Continue — the tracee executes syscall, then hits int3 */
    if (ptrace(PTRACE_CONT, pid, NULL, NULL) < 0) {
        ptrace(PTRACE_POKETEXT, pid,
               (void *)(unsigned long)regs.rip,
               (void *)(unsigned long)saved_insn);
        ptrace(PTRACE_SETREGS, pid, NULL, &regs);
        return -1;
    }

    int status;
    waitpid(pid, &status, 0);

    if (!WIFSTOPPED(status)) {
        ptrace(PTRACE_POKETEXT, pid,
               (void *)(unsigned long)regs.rip,
               (void *)(unsigned long)saved_insn);
        ptrace(PTRACE_SETREGS, pid, NULL, &regs);
        return -1;
    }

    /* Read the syscall result from rax */
    struct user_regs_struct result_regs;
    if (ptrace(PTRACE_GETREGS, pid, NULL, &result_regs) < 0) {
        ptrace(PTRACE_POKETEXT, pid,
               (void *)(unsigned long)regs.rip,
               (void *)(unsigned long)saved_insn);
        ptrace(PTRACE_SETREGS, pid, NULL, &regs);
        return -1;
    }

    long result = (long)result_regs.rax;

    /* Restore the original instruction and registers */
    ptrace(PTRACE_POKETEXT, pid,
           (void *)(unsigned long)regs.rip,
           (void *)(unsigned long)saved_insn);
    ptrace(PTRACE_SETREGS, pid, NULL, &regs);

    return result;
}

int enforcer_apply_filter(profile_t *pf)
{
    struct sock_fprog *prog = build_seccomp_filter(pf);
    if (!prog) {
        log_error("Failed to build seccomp filter.\n");
        return -1;
    }

    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) < 0) {
        log_error("prctl(PR_SET_NO_NEW_PRIVS) failed: %s\n",
                  strerror(errno));
        free_filter(prog);
        return -1;
    }

    if (prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, prog) < 0) {
        log_error("prctl(PR_SET_SECCOMP) failed: %s\n",
                  strerror(errno));
        free_filter(prog);
        return -1;
    }

    log_info("Seccomp filter applied (%u rules).\n", prog->len);
    free_filter(prog);
    return 0;
}

int enforcer_attach(profile_t *pf, pid_t pid)
{
    struct sock_fprog *prog = build_seccomp_filter(pf);
    if (!prog) {
        log_error("Failed to build seccomp filter.\n");
        return -1;
    }

    size_t filter_size = prog->len * sizeof(struct sock_filter);
    size_t fprog_size = sizeof(struct sock_fprog);
    size_t total_needed = filter_size + fprog_size;

    log_info("Attaching seccomp profile to PID %d (%u rules)...\n",
             pid, prog->len);

    /* Step 1: attach and stop the target process */
    int status;
    if (ptrace(PTRACE_SEIZE, pid, NULL, NULL) < 0) {
        log_error("ptrace(PTRACE_SEIZE) failed: %s\n", strerror(errno));
        free_filter(prog);
        return -1;
    }

    if (ptrace(PTRACE_INTERRUPT, pid, NULL, NULL) < 0) {
        log_error("ptrace(PTRACE_INTERRUPT) failed: %s\n",
                  strerror(errno));
        ptrace(PTRACE_DETACH, pid, NULL, NULL);
        free_filter(prog);
        return -1;
    }

    waitpid(pid, &status, 0);

    /* Step 2: find writable memory in the target for BPF data */
    unsigned long target_addr = find_writable_region(pid, total_needed);
    if (!target_addr) {
        log_error("Cannot find writable memory region in PID %d\n", pid);
        ptrace(PTRACE_DETACH, pid, NULL, NULL);
        free_filter(prog);
        return -1;
    }

    log_debug("Target writable region at 0x%lx\n", target_addr);

    unsigned long filter_addr = target_addr;
    unsigned long fprog_addr  = filter_addr + filter_size;

    /* Step 3: write the BPF filter array into target memory */
    if (ptrace_write_mem(pid, filter_addr, prog->filter, filter_size) < 0) {
        log_error("Failed to write BPF filter into target process\n");
        ptrace(PTRACE_DETACH, pid, NULL, NULL);
        free_filter(prog);
        return -1;
    }

    /* Step 4: write struct sock_fprog pointing to the filter */
    struct sock_fprog target_fprog;
    target_fprog.len = (unsigned short)prog->len;
    target_fprog.filter = (struct sock_filter *)(unsigned long)filter_addr;

    if (ptrace_write_mem(pid, fprog_addr, &target_fprog,
                         sizeof(target_fprog)) < 0) {
        log_error("Failed to write sock_fprog into target process\n");
        ptrace(PTRACE_DETACH, pid, NULL, NULL);
        free_filter(prog);
        return -1;
    }

    /* Step 5: inject prctl(PR_SET_NO_NEW_PRIVS, 1) */
    log_debug("Injecting prctl(NO_NEW_PRIVS) into PID %d\n", pid);
    long ret = ptrace_inject_syscall(pid, 157, PR_SET_NO_NEW_PRIVS,
                                     1, 0, 0, 0);
    if (ret < 0 && ret != -EPERM) {
        log_error("prctl(NO_NEW_PRIVS) injection failed: %ld\n", ret);
        ptrace(PTRACE_DETACH, pid, NULL, NULL);
        free_filter(prog);
        return -1;
    }

    /* Step 6: inject seccomp(SECCOMP_SET_MODE_FILTER, 0, &fprog) */
    log_debug("Injecting seccomp filter into PID %d\n", pid);
    ret = ptrace_inject_syscall(pid, 317, SECCOMP_SET_MODE_FILTER, 0,
                                 (long)(unsigned long)fprog_addr,
                                 0, 0);
    if (ret < 0) {
        log_error("seccomp filter injection failed: %ld\n", ret);
        ptrace(PTRACE_DETACH, pid, NULL, NULL);
        free_filter(prog);
        return -1;
    }

    /* Step 7: clean up injected BPF data (best-effort) */
    unsigned long zero = 0;
    for (size_t i = 0; i < total_needed; i += sizeof(long)) {
        ptrace(PTRACE_POKEDATA, pid, (void *)(target_addr + i),
               (void *)zero);
    }

    /* Step 8: detach, suppressing any pending SIGTRAP from int3 */
    ptrace(PTRACE_DETACH, pid, NULL, NULL);
    free_filter(prog);

    log_info("Seccomp filter attached to PID %d (%u rules).\n",
             pid, target_fprog.len);
    return 0;
}

pid_t enforcer_exec(profile_t *pf, const char *cmd,
                     char *const argv[])
{
    pid_t child = fork();
    if (child == 0) {
        struct sock_fprog *prog = build_seccomp_filter(pf);
        if (!prog) {
            log_error("Child: failed to build filter.\n");
            _exit(1);
        }

        if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) < 0) {
            log_error("Child: prctl(NO_NEW_PRIVS) failed: %s\n",
                      strerror(errno));
            _exit(1);
        }

        if (prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, prog) < 0) {
            log_error("Child: prctl(SECCOMP) failed: %s\n",
                      strerror(errno));
            _exit(1);
        }

        free_filter(prog);

        execvp(cmd, argv);
        log_error("Child: execvp(%s) failed: %s\n",
                  cmd, strerror(errno));
        _exit(127);
    }

    if (child < 0) {
        log_error("fork() failed: %s\n", strerror(errno));
        return -1;
    }

    log_info("Spawned PID %d under seccomp profile.\n", child);
    return child;
}

int enforcer_watch(profile_t *pf, const char *cmd,
                    char *const argv[])
{
    pid_t child = fork();
    if (child == 0) {
        struct sock_fprog *prog = build_seccomp_filter(pf);
        if (!prog) _exit(1);

        if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) < 0) _exit(1);

        if (prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, prog) < 0) {
            _exit(1);
        }

        free_filter(prog);
        execvp(cmd, argv);
        _exit(127);
    }

    if (child < 0) {
        log_error("fork() failed: %s\n", strerror(errno));
        return -1;
    }

    log_info("Watching PID %d under seccomp profile.\n", child);

    signal(SIGINT, child_sig_handler);
    signal(SIGTERM, child_sig_handler);
    g_child_pid = child;

    int status;
    if (waitpid(child, &status, 0) < 0) {
        log_error("waitpid() failed: %s\n", strerror(errno));
        return -1;
    }

    if (WIFEXITED(status)) {
        log_info("Process exited with code %d\n",
                 WEXITSTATUS(status));
    } else if (WIFSIGNALED(status)) {
        int sig = WTERMSIG(status);
        log_warn("Process killed by signal %d (%s)\n",
                 sig, strsignal(sig));

        if (sig == SIGSYS) {
            log_warn("Seccomp violation detected!\n");
        }
    }

    g_child_pid = 0;
    return 0;
}
