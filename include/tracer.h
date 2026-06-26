#ifndef TRACER_H
#define TRACER_H

#include <sys/types.h>
#include <stdint.h>
#include <stddef.h>

typedef struct {
    long number;
    unsigned long count;
} syscall_obs_t;

typedef struct {
    syscall_obs_t *calls;
    size_t count;
    unsigned long total;
    pid_t target_pid;
    double duration_sec;
} trace_result_t;

typedef enum {
    TRACER_PTRACE = 0,
    TRACER_EBPF
} tracer_backend_t;

typedef struct {
    tracer_backend_t backend;
    int duration_sec;
    int trace_children;
    int resolve_names;
    const char *output;
} tracer_opts_t;

#define TRACER_OPTS_DEFAULT { \
    .backend = TRACER_PTRACE, \
    .duration_sec = 10,       \
    .trace_children = 0,      \
    .resolve_names = 1,       \
    .output = NULL            \
}

trace_result_t *tracer_attach(pid_t pid, const tracer_opts_t *opts);
trace_result_t *tracer_exec(const char *cmd, char *const argv[],
                            const tracer_opts_t *opts);
int tracer_save(const trace_result_t *tr, const char *path);
trace_result_t *tracer_load(const char *path);
trace_result_t *tracer_merge(trace_result_t **traces, size_t count);
void tracer_free(trace_result_t *tr);
const char *tracer_syscall_name(long number);

#endif
