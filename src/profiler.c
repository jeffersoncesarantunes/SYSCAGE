#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

#include "syscage.h"
#include "profiler.h"
#include "tracer.h"

static int compare_syscall_count(const void *a, const void *b)
{
    const profile_rule_t *ra = (const profile_rule_t *)a;
    const profile_rule_t *rb = (const profile_rule_t *)b;
    if (ra->syscall_number < rb->syscall_number) return -1;
    if (ra->syscall_number > rb->syscall_number) return 1;
    return 0;
}

static const long g_critical_syscalls[] = {
    0,
    1,
    3,
    60,
    231,
    186,
    39,
    110,
    96,
    228,
    35,
    13,
    14,
    15,
    157,
    317,
};
static const size_t g_critical_count =
    sizeof(g_critical_syscalls) / sizeof(g_critical_syscalls[0]);

static int rule_has_syscall(const profile_rule_t *rules, size_t count,
                              long nr)
{
    for (size_t i = 0; i < count; i++) {
        if (rules[i].syscall_number == nr) return 1;
    }
    return 0;
}

profile_t *profiler_generate(const trace_result_t *tr,
                              const profile_opts_t *opts)
{
    profile_opts_t default_opts = PROFILE_OPTS_DEFAULT;
    if (!opts) opts = &default_opts;

    size_t max_rules = tr->count + g_critical_count + 64;
    profile_rule_t *rules = calloc(max_rules, sizeof(profile_rule_t));
    if (!rules) return NULL;

    size_t idx = 0;

    for (size_t i = 0; i < tr->count; i++) {
        if (tr->calls[i].count >= (unsigned long)opts->min_frequency) {
            rules[idx].syscall_number = tr->calls[i].number;
            rules[idx].action = ACTION_ALLOW;
            rules[idx].name = tracer_syscall_name(tr->calls[i].number);
            idx++;
        }
    }

    if (opts->include_critical) {
        for (size_t i = 0; i < g_critical_count; i++) {
            if (!rule_has_syscall(rules, idx, g_critical_syscalls[i])) {
                rules[idx].syscall_number = g_critical_syscalls[i];
                rules[idx].action = ACTION_ALLOW;
                rules[idx].name =
                    tracer_syscall_name(g_critical_syscalls[i]);
                idx++;
            }
        }
    }

    qsort(rules, idx, sizeof(profile_rule_t), compare_syscall_count);

    profile_t *pf = calloc(1, sizeof(profile_t));
    if (!pf) {
        free(rules);
        return NULL;
    }

    pf->rules = rules;
    pf->rule_count = idx;
    pf->total_observations = tr->total;
    pf->source_pid = tr->target_pid;
    pf->duration_sec = tr->duration_sec;
    pf->default_action = ACTION_KILL;
    snprintf(pf->source_cmd, sizeof(pf->source_cmd), "pid_%d",
             tr->target_pid);

    return pf;
}

int profiler_save(const profile_t *pf, const char *path)
{
    FILE *f = fopen(path, "w");
    if (!f) {
        log_error("Cannot write profile to %s\n", path);
        return -1;
    }

    fprintf(f, "# SYSCAGE seccomp profile\n");
    fprintf(f, "# Source PID: %d (%s)\n",
            pf->source_pid, pf->source_cmd);
    fprintf(f, "# Duration: %.1fs\n", pf->duration_sec);
    fprintf(f, "# Observations: %lu total\n", pf->total_observations);
    fprintf(f, "# Rules: %zu\n", pf->rule_count);
    fprintf(f, "# Default action: %s\n",
            pf->default_action == ACTION_ALLOW ? "ALLOW" :
            pf->default_action == ACTION_KILL ? "KILL" :
            pf->default_action == ACTION_TRAP ? "TRAP" : "KILL_PROCESS");
    fprintf(f, "#\n");
    fprintf(f, "# Format: <syscall_number> <action> # <name>\n");
    fprintf(f, "# Actions: A=ALLOW K=KILL T=TRAP\n");

    for (size_t i = 0; i < pf->rule_count; i++) {
        char action_char = 'A';
        switch (pf->rules[i].action) {
        case ACTION_ALLOW: action_char = 'A'; break;
        case ACTION_KILL:  action_char = 'K'; break;
        case ACTION_TRAP:  action_char = 'T'; break;
        default:           action_char = '?'; break;
        }

        fprintf(f, "%-5ld %c  # %s\n",
                pf->rules[i].syscall_number,
                action_char,
                pf->rules[i].name ?
                    pf->rules[i].name :
                    tracer_syscall_name(pf->rules[i].syscall_number));
    }

    fclose(f);
    return 0;
}

int profiler_save_header(const profile_t *pf, const char *path)
{
    FILE *f = fopen(path, "w");
    if (!f) {
        log_error("Cannot write header to %s\n", path);
        return -1;
    }

    fprintf(f, "/* SYSCAGE generated seccomp profile */\n");
    fprintf(f, "/* Source PID: %d */\n", pf->source_pid);
    fprintf(f, "/* Rules: %zu */\n\n", pf->rule_count);

    fprintf(f, "#ifndef SYSCAGE_PROFILE_H\n");
    fprintf(f, "#define SYSCAGE_PROFILE_H\n\n");

    fprintf(f, "#include <linux/filter.h>\n");
    fprintf(f, "#include <linux/seccomp.h>\n\n");

    fprintf(f, "static struct sock_filter syscage_filter[] = {\n");

    for (size_t i = 0; i < pf->rule_count; i++) {
        if (pf->rules[i].action == ACTION_ALLOW) {
            fprintf(f, "    BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K, "
                    "%ld, 0, 1),\n", pf->rules[i].syscall_number);
            fprintf(f, "    BPF_STMT(BPF_RET|BPF_K, "
                    "SECCOMP_RET_ALLOW),\n");
        }
    }

    fprintf(f, "    BPF_STMT(BPF_RET|BPF_K, "
            "SECCOMP_RET_KILL),\n");

    fprintf(f, "};\n\n");

    fprintf(f, "static struct sock_fprog syscage_prog = {\n");
    fprintf(f, "    .len = (unsigned short)"
            "(sizeof(syscage_filter) / sizeof(syscage_filter[0])),\n");
    fprintf(f, "    .filter = syscage_filter,\n");
    fprintf(f, "};\n\n");

    fprintf(f, "#endif /* SYSCAGE_PROFILE_H */\n");

    fclose(f);
    return 0;
}

profile_t *profiler_load(const char *path)
{
    char *data = NULL;
    syscage_read_file(path, &data);
    if (!data) return NULL;

    size_t capacity = 256;
    profile_rule_t *rules = calloc(capacity, sizeof(profile_rule_t));
    if (!rules) {
        free(data);
        return NULL;
    }

    size_t idx = 0;
    profile_t *pf = calloc(1, sizeof(profile_t));
    if (!pf) {
        free(rules);
        free(data);
        return NULL;
    }

    char *line = data;
    char *next;

    while (line && *line) {
        next = strchr(line, '\n');
        if (next) *next++ = '\0';

        if (line[0] == '\0' || line[0] == '\n') {
            line = next;
            continue;
        }

        if (strncmp(line, "# Source PID:", 12) == 0) {
            if (sscanf(line, "# Source PID: %d", &pf->source_pid) != 1)
                log_warn("Malformed Source PID line\n");
            line = next;
            continue;
        }
        if (strncmp(line, "# Duration:", 10) == 0) {
            if (sscanf(line, "# Duration: %lf", &pf->duration_sec) != 1)
                log_warn("Malformed Duration line\n");
            line = next;
            continue;
        }
        if (strncmp(line, "# Observations:", 14) == 0) {
            if (sscanf(line, "# Observations: %lu", &pf->total_observations) != 1)
                log_warn("Malformed Observations line\n");
            line = next;
            continue;
        }
        if (strncmp(line, "# Rules:", 7) == 0) {
            if (sscanf(line, "# Rules: %zu", &pf->rule_count) != 1)
                log_warn("Malformed Rules line\n");
            line = next;
            continue;
        }
        if (line[0] == '#') {
            line = next;
            continue;
        }

        long nr;
        char action;
        if (sscanf(line, "%ld %c", &nr, &action) >= 1) {
            if (idx >= capacity) {
                capacity *= 2;
                profile_rule_t *newr = realloc(rules,
                    capacity * sizeof(profile_rule_t));
                if (!newr) break;
                rules = newr;
            }

            rules[idx].syscall_number = nr;
            rules[idx].name = tracer_syscall_name(nr);

            switch (action) {
            case 'A': rules[idx].action = ACTION_ALLOW; break;
            case 'K': rules[idx].action = ACTION_KILL; break;
            case 'T': rules[idx].action = ACTION_TRAP; break;
            default:  rules[idx].action = ACTION_ALLOW; break;
            }
            idx++;
        }

        line = next;
    }

    pf->rules = rules;
    pf->rule_count = idx;

    free(data);
    return pf;
}

void profiler_free(profile_t *pf)
{
    if (pf) {
        free(pf->rules);
        free(pf);
    }
}

void profiler_print(const profile_t *pf)
{
    printf("\n  Profile Summary\n");
    printf("  %s\n", "──────────────────────────────");
    printf("  Rules:        %zu\n", pf->rule_count);
    printf("  Observations: %lu\n", pf->total_observations);
    printf("  Source PID:   %d\n", pf->source_pid);
    printf("  Duration:     %.1fs\n", pf->duration_sec);
    printf("  Default:      %s\n",
           pf->default_action == ACTION_ALLOW ? "ALLOW" : "KILL");
    printf("\n");

    size_t show = pf->rule_count < 20 ? pf->rule_count : 20;
    printf("  %-5s  %s\n", "NR", "SYSCALL");
    printf("  %s\n", "  ─────────────────");
    for (size_t i = 0; i < show; i++) {
        printf("  %-5ld  %s\n",
               pf->rules[i].syscall_number,
               pf->rules[i].name ?
                   pf->rules[i].name :
                   tracer_syscall_name(pf->rules[i].syscall_number));
    }
    if (pf->rule_count > 20) {
        printf("  ... and %zu more\n", pf->rule_count - 20);
    }
    printf("\n");
}
