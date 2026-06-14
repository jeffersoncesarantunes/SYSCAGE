#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include "syscage.h"
#include "tracer.h"
#include "profiler.h"
#include "enforcer.h"

static int test_syscall_name(void)
{
    assert(strcmp(tracer_syscall_name(0), "read") == 0);
    assert(strcmp(tracer_syscall_name(1), "write") == 0);
    assert(strcmp(tracer_syscall_name(59), "execve") == 0);
    assert(strcmp(tracer_syscall_name(60), "exit") == 0);
    assert(strcmp(tracer_syscall_name(317), "seccomp") == 0);

    assert(strcmp(tracer_syscall_name(999), "syscall_999") == 0);
    assert(strcmp(tracer_syscall_name(-1), "syscall_-1") == 0);

    printf("  [PASS] syscall_name\n");
    return 0;
}

static int test_trace_save_load(void)
{
    trace_result_t *tr = calloc(1, sizeof(trace_result_t));
    assert(tr != NULL);

    tr->calls = calloc(3, sizeof(syscall_obs_t));
    assert(tr->calls != NULL);

    tr->calls[0].number = 0;
    tr->calls[0].count = 50;
    tr->calls[1].number = 1;
    tr->calls[1].count = 30;
    tr->calls[2].number = 60;
    tr->calls[2].count = 5;

    tr->count = 3;
    tr->total = 85;
    tr->target_pid = 1234;
    tr->duration_sec = 10.5;

    const char *test_path = "/tmp/syscage_test_trace.trace";
    assert(tracer_save(tr, test_path) == 0);

    trace_result_t *loaded = tracer_load(test_path);
    assert(loaded != NULL);
    assert(loaded->count == 3);
    assert(loaded->total == 85);
    assert(loaded->target_pid == 1234);

    int found[3] = {0, 0, 0};
    for (size_t i = 0; i < loaded->count; i++) {
        if (loaded->calls[i].number == 0) {
            assert(loaded->calls[i].count == 50);
            found[0] = 1;
        }
        if (loaded->calls[i].number == 1) {
            assert(loaded->calls[i].count == 30);
            found[1] = 1;
        }
        if (loaded->calls[i].number == 60) {
            assert(loaded->calls[i].count == 5);
            found[2] = 1;
        }
    }
    assert(found[0] && found[1] && found[2]);

    tracer_free(tr);
    tracer_free(loaded);
    remove(test_path);

    printf("  [PASS] trace_save_load\n");
    return 0;
}

static int test_profile_generation(void)
{
    trace_result_t *tr = calloc(1, sizeof(trace_result_t));
    assert(tr != NULL);

    tr->calls = calloc(2, sizeof(syscall_obs_t));
    assert(tr->calls != NULL);

    tr->calls[0].number = 0;
    tr->calls[0].count = 100;
    tr->calls[1].number = 2;
    tr->calls[1].count = 5;

    tr->count = 2;
    tr->total = 105;
    tr->target_pid = 999;
    tr->duration_sec = 5.0;

    profile_t *pf = profiler_generate(tr, NULL);
    assert(pf != NULL);
    assert(pf->rule_count >= 2);

    int has_read = 0, has_open = 0, has_exit = 0;
    for (size_t i = 0; i < pf->rule_count; i++) {
        if (pf->rules[i].syscall_number == 0) has_read = 1;
        if (pf->rules[i].syscall_number == 2) has_open = 1;
        if (pf->rules[i].syscall_number == 60) has_exit = 1;
    }
    assert(has_read);
    assert(has_open);
    assert(has_exit);

    const char *test_path = "/tmp/syscage_test_profile.syscage";
    assert(profiler_save(pf, test_path) == 0);

    profile_t *loaded = profiler_load(test_path);
    assert(loaded != NULL);
    assert(loaded->rule_count == pf->rule_count);

    profiler_free(pf);
    profiler_free(loaded);
    tracer_free(tr);
    remove(test_path);

    printf("  [PASS] profile_generation\n");
    return 0;
}

static int test_header_generation(void)
{
    trace_result_t *tr = calloc(1, sizeof(trace_result_t));
    assert(tr != NULL);

    tr->calls = calloc(1, sizeof(syscall_obs_t));
    tr->calls[0].number = 0;
    tr->calls[0].count = 10;
    tr->count = 1;
    tr->total = 10;
    tr->target_pid = 100;
    tr->duration_sec = 3.0;

    profile_t *pf = profiler_generate(tr, NULL);
    assert(pf != NULL);

    const char *test_path = "/tmp/syscage_test_profile.h";
    assert(profiler_save_header(pf, test_path) == 0);

    char *content = NULL;
    syscage_read_file(test_path, &content);
    assert(content != NULL);
    assert(strstr(content, "SECCOMP_RET_ALLOW") != NULL);
    assert(strstr(content, "SECCOMP_RET_KILL") != NULL);
    assert(strstr(content, "syscage_filter") != NULL);
    assert(strstr(content, "syscage_prog") != NULL);

    free(content);
    profiler_free(pf);
    tracer_free(tr);
    remove(test_path);

    printf("  [PASS] header_generation\n");
    return 0;
}

int main(void)
{
    printf("SYSCAGE Test Suite\n");
    printf("──────────────────\n\n");

    int failed = 0;
    failed += test_syscall_name();
    failed += test_trace_save_load();
    failed += test_profile_generation();
    failed += test_header_generation();

    printf("\n");
    if (failed == 0) {
        printf("All tests passed.\n");
    } else {
        printf("%d tests FAILED.\n", failed);
    }
    return failed;
}
