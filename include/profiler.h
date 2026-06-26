#ifndef PROFILER_H
#define PROFILER_H

#include <stdint.h>
#include <stddef.h>
#include "tracer.h"

typedef enum {
    ACTION_ALLOW = 0,
    ACTION_KILL,
    ACTION_TRAP,
    ACTION_LOG,
    ACTION_KILL_PROCESS
} policy_action_t;

typedef struct {
    long syscall_number;
    policy_action_t action;
    const char *name;
} profile_rule_t;

typedef struct {
    profile_rule_t *rules;
    size_t rule_count;
    unsigned long total_observations;
    pid_t source_pid;
    char source_cmd[256];
    double duration_sec;
    policy_action_t default_action;
} profile_t;

typedef struct {
    int whitelist;
    int include_critical;
    int min_frequency;
    int generate_header;
    int generate_json;
    const char *output;
} profile_opts_t;

#define PROFILE_OPTS_DEFAULT { \
    .whitelist = 1,             \
    .include_critical = 1,      \
    .min_frequency = 1,         \
    .generate_header = 0,       \
    .generate_json = 0,         \
    .output = NULL              \
}

profile_t *profiler_generate(const trace_result_t *tr,
                             const profile_opts_t *opts);
int profiler_save(const profile_t *pf, const char *path);
int profiler_save_header(const profile_t *pf, const char *path);
int profiler_save_json(const profile_t *pf, const char *path);
profile_t *profiler_load(const char *path);
void profiler_free(profile_t *pf);
void profiler_print(const profile_t *pf);

#endif
