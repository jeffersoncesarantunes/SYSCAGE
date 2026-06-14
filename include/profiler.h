#ifndef PROFILER_H
#define PROFILER_H

#include <stdint.h>
#include <stddef.h>
#include "tracer.h"

/* Policy action for a syscall */
typedef enum {
    ACTION_ALLOW = 0,
    ACTION_KILL,
    ACTION_TRAP,
    ACTION_LOG,
    ACTION_KILL_PROCESS
} policy_action_t;

/* A single rule in a profile */
typedef struct {
    long syscall_number;
    policy_action_t action;
    const char *name;  /* syscall name, for readability */
} profile_rule_t;

/* A complete syscage profile */
typedef struct {
    profile_rule_t *rules;
    size_t rule_count;
    unsigned long total_observations;
    pid_t source_pid;
    char source_cmd[256];
    double duration_sec;
    /* Default action for syscalls not in the profile */
    policy_action_t default_action;
} profile_t;

/* Profile generation options */
typedef struct {
    int whitelist;            /* generate allowlist (default) */
    int include_critical;     /* always include critical syscalls */
    int min_frequency;        /* minimum count to include */
    int generate_header;      /* also emit C header */
    const char *output;       /* output file path */
} profile_opts_t;

#define PROFILE_OPTS_DEFAULT { \
    .whitelist = 1,             \
    .include_critical = 1,      \
    .min_frequency = 1,         \
    .generate_header = 0,       \
    .output = NULL              \
}

/* ---- Profiler API ---- */

/*
 * Generate a seccomp profile from a trace result.
 * tr: trace data from the tracer.
 * opts: profile options (NULL for defaults).
 * Returns a profile_t on success, NULL on error.
 */
profile_t *profiler_generate(const trace_result_t *tr,
                             const profile_opts_t *opts);

/*
 * Save a profile in SYSCAGE text format.
 */
int profiler_save(const profile_t *pf, const char *path);

/*
 * Save a profile as a C header file for embedding.
 */
int profiler_save_header(const profile_t *pf, const char *path);

/*
 * Load a profile from a SYSCAGE text file.
 */
profile_t *profiler_load(const char *path);

/*
 * Free a profile.
 */
void profiler_free(profile_t *pf);

/*
 * Print a profile summary to stdout.
 */
void profiler_print(const profile_t *pf);

#endif
