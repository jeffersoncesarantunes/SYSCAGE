#ifndef ENFORCER_H
#define ENFORCER_H

#include <sys/types.h>
#include <stddef.h>
#include "profiler.h"

/* Enforcement mode */
typedef enum {
    ENFORCE_ATTACH,   /* attach to existing process */
    ENFORCE_EXEC,     /* spawn new process with filter */
    ENFORCE_WATCH     /* spawn + monitor for violations */
} enforce_mode_t;

/* Enforcement options */
typedef struct {
    enforce_mode_t mode;
    int abort_on_violation;
    int log_violations;
    const char *profile_path;
} enforce_opts_t;

#define ENFORCE_OPTS_DEFAULT { \
    .mode = ENFORCE_ATTACH,    \
    .abort_on_violation = 1,   \
    .log_violations = 1,       \
    .profile_path = NULL       \
}

/* Violation event */
typedef struct {
    pid_t pid;
    long syscall_number;
    unsigned long timestamp_ms;
    const char *syscall_name;
} violation_event_t;

/* ---- Enforcer API ---- */

/*
 * Apply a profile to a running process via seccomp(2).
 * pf: compiled profile.
 * pid: target process ID.
 * Returns 0 on success, -1 on error.
 */
int enforcer_attach(profile_t *pf, pid_t pid);

/*
 * Spawn a new process under the given profile.
 * pf: compiled profile.
 * cmd: executable path.
 * argv: argument vector.
 * Returns the child PID on success, -1 on error.
 */
pid_t enforcer_exec(profile_t *pf, const char *cmd,
                    char *const argv[]);

/*
 * Watch mode: spawn process under profile and monitor violations.
 * Returns 0 on success, -1 on error.
 */
int enforcer_watch(profile_t *pf, const char *cmd,
                   char *const argv[]);

/*
 * Compile a profile into a seccomp BPF filter and apply.
 * Internal: generates sock_fprog and calls prctl/seccomp.
 */
int enforcer_apply_filter(profile_t *pf);

#endif
