#ifndef TRACER_H
#define TRACER_H

#include <sys/types.h>
#include <stdint.h>
#include <stddef.h>

/* A single syscall observation */
typedef struct {
    long number;
    unsigned long count;
} syscall_obs_t;

/* Trace result: frequency map of observed syscalls */
typedef struct {
    syscall_obs_t *calls;
    size_t count;
    unsigned long total;
    pid_t target_pid;
    double duration_sec;
} trace_result_t;

/* Tracer backend */
typedef enum {
    TRACER_PTRACE = 0,  /* ptrace-based, no deps */
    TRACER_EBPF         /* eBPF-based, needs libbpf */
} tracer_backend_t;

/* Tracer options */
typedef struct {
    tracer_backend_t backend;
    int duration_sec;
    int trace_children;
    int resolve_names;
    const char *output;
} tracer_opts_t;

/* Default tracer options */
#define TRACER_OPTS_DEFAULT { \
    .backend = TRACER_PTRACE, \
    .duration_sec = 10,       \
    .trace_children = 0,      \
    .resolve_names = 1,       \
    .output = NULL            \
}

/* ---- Tracer API ---- */

/*
 * Attach to a running process and observe its syscalls.
 * pid: target process ID.
 * opts: tracer options (can be NULL for defaults).
 * Returns a trace_result_t on success, NULL on error.
 */
trace_result_t *tracer_attach(pid_t pid, const tracer_opts_t *opts);

/*
 * Execute a command under tracing.
 * cmd: command to execute (e.g. "/usr/bin/nginx").
 * argv: argument vector.
 * opts: tracer options.
 * Returns a trace_result_t on success, NULL on error.
 */
trace_result_t *tracer_exec(const char *cmd, char *const argv[],
                            const tracer_opts_t *opts);

/*
 * Save trace result to a file.
 */
int tracer_save(const trace_result_t *tr, const char *path);

/*
 * Load trace result from a file.
 */
trace_result_t *tracer_load(const char *path);

/*
 * Free a trace result.
 */
void tracer_free(trace_result_t *tr);

/*
 * Get syscall name string (from internal table).
 */
const char *tracer_syscall_name(long number);

#endif
