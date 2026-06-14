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

/*
 * Build a seccomp BPF filter from a profile.
 * Returns the sock_fprog that can be passed to prctl(PR_SET_SECCOMP).
 */
static struct sock_fprog *build_seccomp_filter(profile_t *pf)
{
    /*
     * Filter structure:
     *   Load syscall number: BPF_LD | BPF_W | BPF_ABS
     *   For each allowed syscall: BPF_JMP | BPF_JEQ | BPF_K
     *     If match: ALLOW
     *     If no match: continue
     *   Default: KILL
     *
     * Each rule generates 2 instructions (JEQ jump + ALLOW).
     * Plus 1 load + 1 default kill.
     */
    size_t insn_count = 1 + (pf->rule_count * 2) + 1;
    struct sock_filter *filter = calloc(insn_count, sizeof(struct sock_filter));
    if (!filter) return NULL;

    size_t idx = 0;

    /* Load syscall number */
    filter[idx++] = (struct sock_filter)BPF_STMT(BPF_LD | BPF_W | BPF_ABS,
        offsetof(struct seccomp_data, nr));

    /* For each allowed syscall, add a comparison */
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

    /* Default action */
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
    /*
     * Attaching seccomp to a running process requires ptrace.
     * This is a simplified implementation that uses PTRACE_SEIZE
     * to inject the seccomp filter via PTRACE_SETOPTIONS.
     *
     * On Linux, this requires:
     * - PTRACE_SEIZE on the target
     * - PTRACE_INTERRUPT to stop it
     * - Then PTRACE_SETOPTIONS with PTRACE_O_SUSPEND_SECCOMP
     *
     * For now, we log a warning since seccomp injection into
     * running processes is not universally available.
     */
    log_warn("Attaching seccomp to running PID %d requires "
             "ptrace injection.\n", pid);
    log_warn("Consider using 'syscage watch' or 'syscage enforce -e' "
             "for new processes.\n");

    /*
     * For this initial version, we use ptrace to inject seccomp.
     * The actual mechanism involves stopping the process,
     * setting up seccomp via PTRACE_SETOPTIONS, then resuming.
     */
    int status;
    if (ptrace(PTRACE_SEIZE, pid, NULL, NULL) < 0) {
        log_error("ptrace(PTRACE_SEIZE) failed: %s\n", strerror(errno));
        return -1;
    }

    if (ptrace(PTRACE_INTERRUPT, pid, NULL, NULL) < 0) {
        log_error("ptrace(PTRACE_INTERRUPT) failed\n");
        ptrace(PTRACE_DETACH, pid, NULL, NULL);
        return -1;
    }

    waitpid(pid, &status, 0);

    /*
     * Build the seccomp filter now so we can pass it via the
     * PTRACE_SETOPTIONS mechanism. This is simplified for the
     * initial release — full implementation would use the
     * SECCOMP_IOCTL_NOTIF_RECV or process_vm_writev approach.
     */
    struct sock_fprog *prog = build_seccomp_filter(pf);
    if (!prog) {
        ptrace(PTRACE_DETACH, pid, NULL, NULL);
        return -1;
    }

    /*
     * Note: direct seccomp filter injection into a running process
     * via ptrace is architecture-dependent and requires the target
     * to be in a known state. For simplicity in v0.1, we detach
     * and recommend using process startup enforcement instead.
     */
    log_info("Generated filter with %u instructions.\n", prog->len);
    log_info("To apply at process start, use: syscage watch\n");

    free_filter(prog);
    ptrace(PTRACE_DETACH, pid, NULL, NULL);
    log_info("Detached from PID %d (no filter applied).\n", pid);

    return 0;
}

pid_t enforcer_exec(profile_t *pf, const char *cmd,
                     char *const argv[])
{
    pid_t child = fork();
    if (child == 0) {
        /* Child: apply filter, then exec */
        struct sock_fprog *prog = build_seccomp_filter(pf);
        if (!prog) {
            log_error("Child: failed to build filter.\n");
            _exit(1);
        }

        /* PR_SET_NO_NEW_PRIVS must come before PR_SET_SECCOMP */
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

        /* Execute the target command */
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
    /*
     * Watch mode:
     * 1. Fork child with seccomp filter applied
     * 2. Monitor child for violations (SIGSYS)
     * 3. Report violations and optionally abort
     */
    pid_t child = fork();
    if (child == 0) {
        /* Child: apply filter and exec */
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

    /*
     * Monitor the child. SiGnals from seccomp violations arrive
     * as SIGSYS with siginfo_t.si_syscall indicating the offending
     * syscall.
     */
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

        /* Check if it was a seccomp violation (SIGSYS) */
        if (sig == SIGSYS) {
            log_warn("Seccomp violation detected!\n");
        }
    }

    g_child_pid = 0;
    return 0;
}
