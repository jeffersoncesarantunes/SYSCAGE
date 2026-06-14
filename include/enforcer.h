#ifndef ENFORCER_H
#define ENFORCER_H

#include <sys/types.h>
#include <stddef.h>
#include "profiler.h"

typedef enum {
    ENFORCE_ATTACH,
    ENFORCE_EXEC,
    ENFORCE_WATCH
} enforce_mode_t;

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

typedef struct {
    pid_t pid;
    long syscall_number;
    unsigned long timestamp_ms;
    const char *syscall_name;
} violation_event_t;

int enforcer_attach(profile_t *pf, pid_t pid);
pid_t enforcer_exec(profile_t *pf, const char *cmd,
                    char *const argv[]);
int enforcer_watch(profile_t *pf, const char *cmd,
                   char *const argv[]);
int enforcer_apply_filter(profile_t *pf);

#endif
