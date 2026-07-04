#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <getopt.h>
#include <signal.h>

#include "syscage.h"
#include "tracer.h"
#include "profiler.h"
#include "enforcer.h"

static volatile int g_running = 1;

static void handle_signal(int sig)
{
    (void)sig;
    g_running = 0;
}

static void print_banner(void)
{
    if (g_config.quiet) return;
    fprintf(stdout,
        "\342\224\214\342\224\200 SYSCAGE \342\224\200\342\224\200\342\224\200\342\224\200\342\224\200\342\224\200\342\224\200\342\224\200\342\224\200\342\224\200\342\224\200\342\224\200\342\224\200\342\224\200\342\224\200\342\224\200\342\224\200\342\224\200\342\224\200\342\224\200\342\224\220\n"
        "\342\224\202  Kernel Policy Fence         \342\224\202\n"
        "\342\224\202  Syscall Profiling/Seccomp   \342\224\202\n"
        "\342\224\224\342\224\200\342\224\200\342\224\200\342\224\200\342\224\200\342\224\200\342\224\200\342\224\200\342\224\200\342\224\200\342\224\200\342\224\200\342\224\200\342\224\200\342\224\200\342\224\200\342\224\200\342\224\200\342\224\200\342\224\200\342\224\200\342\224\200\342\224\200\342\224\200\342\224\200\342\224\200\342\224\200\342\224\200\342\224\200\342\224\200\342\224\230\n"
        "\n");
}

static void print_usage(const char *prog)
{
    fprintf(stdout,
        "Usage: %s <command> [options] [target]\n"
        "\n"
        "Commands:\n"
        "  learn       Trace syscalls from a process or command\n"
        "  gen         Generate seccomp profile from trace data\n"
        "  enforce     Apply a profile to a process\n"
        "  watch       Spawn a process under profile enforcement\n"
        "\n"
        "Global options:\n"
        "  -q, --quiet        Suppress banner and non-essential output\n"
        "  -v, --verbose      Increase log level\n"
        "  -h, --help         Show this help\n"
        "  --version          Show version\n"
        "\n"
        "See '%s <command> --help' for command-specific options.\n",
        prog, prog);
}

static int cmd_learn(int argc, char **argv, const char *prog)
{
    tracer_opts_t opts = TRACER_OPTS_DEFAULT;
    int opt;

    struct option long_opts[] = {
        {"duration",  required_argument, 0, 'd'},
        {"output",    required_argument, 0, 'o'},
        {"children",  no_argument,       0, 'c'},
        {"ebpf",      no_argument,       0, 'e'},
        {"quiet",     no_argument,       0, 'q'},
        {"help",      no_argument,       0, 'h'},
        {0, 0, 0, 0}
    };

    while ((opt = getopt_long(argc, argv, "d:o:ceqh", long_opts, NULL)) != -1) {
        switch (opt) {
        case 'd': {
            char *end;
            long val = strtol(optarg, &end, 10);
            if (*end != '\0' || val <= 0) val = 10;
            opts.duration_sec = (int)val;
            break;
        }
        case 'o':
            opts.output = optarg;
            break;
        case 'c':
            opts.trace_children = 1;
            break;
        case 'e':
            fprintf(stderr, "Error: eBPF backend not yet implemented, use ptrace backend\n");
            return 1;
        case 'q':
            g_config.quiet = 1;
            break;
        case 'h':
            print_banner();
            fprintf(stdout,
                "Usage: %s learn [options] <pid|command...>\n"
                "\n"
                "Trace syscalls from a running process or execute a command under trace.\n"
                "\n"
                "Options:\n"
                "  -d, --duration SEC   Tracing duration in seconds (default: 10)\n"
                "  -o, --output FILE    Save trace data to FILE\n"
                "  -c, --children       Also trace child processes\n"
                "  -e, --ebpf           Use eBPF backend (requires libbpf)\n"
                "  -q, --quiet          Suppress non-essential output\n"
                "  -h, --help           Show this help\n"
                "\n"
                "Examples:\n"
                "  syscage learn -d 30 -o nginx.trace $(pidof nginx)\n"
                "  syscage learn -d 5 -- /usr/bin/ls -la\n",
                prog);
            return 0;
        default:
            return SYSCAGE_ERR_ARG;
        }
    }

    if (optind >= argc) {
        log_error("No target specified. Use --help for usage.\n");
        return SYSCAGE_ERR_ARG;
    }

    print_banner();

    signal(SIGINT, handle_signal);
    signal(SIGTERM, handle_signal);

    trace_result_t *result = NULL;

    char *endptr;
    long pid = strtol(argv[optind], &endptr, 10);

    if (*endptr == '\0' && pid > 0) {
        log_info("Attaching to PID %ld...\n", pid);
        result = tracer_attach((pid_t)pid, &opts);
    } else {
        log_info("Executing '%s' under trace...\n", argv[optind]);
        result = tracer_exec(argv[optind], &argv[optind], &opts);
    }

    if (!result) {
        log_error("Tracing failed.\n");
        return SYSCAGE_ERR;
    }

    log_info("Trace complete: %lu syscalls observed, %zu unique.\n",
             result->total, result->count);

    if (opts.output) {
        if (tracer_save(result, opts.output) == 0) {
            log_info("Trace saved to %s\n", opts.output);
        } else {
            log_error("Failed to save trace to %s\n", opts.output);
        }
    }

    tracer_free(result);
    return SYSCAGE_OK;
}

static int cmd_gen(int argc, char **argv, const char *prog)
{
    profile_opts_t opts = PROFILE_OPTS_DEFAULT;
    int opt;

    struct option long_opts[] = {
        {"output",    required_argument, 0, 'o'},
        {"header",    no_argument,       0, 'H'},
        {"json",      no_argument,       0, 'j'},
        {"frequency", required_argument, 0, 'f'},
        {"quiet",     no_argument,       0, 'q'},
        {"help",      no_argument,       0, 'h'},
        {0, 0, 0, 0}
    };

    while ((opt = getopt_long(argc, argv, "o:Hjf:qh", long_opts, NULL)) != -1) {
        switch (opt) {
        case 'o':
            opts.output = optarg;
            break;
        case 'H':
            opts.generate_header = 1;
            break;
        case 'j':
            opts.generate_json = 1;
            break;
        case 'f': {
            char *end;
            long val = strtol(optarg, &end, 10);
            if (*end != '\0' || val < 1) val = 1;
            opts.min_frequency = (int)val;
            break;
        }
        case 'q':
            g_config.quiet = 1;
            break;
        case 'h':
            print_banner();
            fprintf(stdout,
                "Usage: %s gen [options] <trace-file...>\n"
                "\n"
                "Generate a seccomp profile from trace data.\n"
                "Multiple trace files are merged before profile generation.\n"
                "\n"
                "Options:\n"
                "  -o, --output FILE    Save profile to FILE (default: <trace>.syscage)\n"
                "  -H, --header         Also emit a C header file\n"
                "  -j, --json           Also emit a JSON profile\n"
                "  -f, --frequency N    Minimum syscall frequency to include (default: 1)\n"
                "  -q, --quiet          Suppress non-essential output\n"
                "  -h, --help           Show this help\n"
                "\n"
                "Examples:\n"
                "  syscage gen -o nginx.syscage nginx.trace\n"
                "  syscage gen --header nginx.trace\n"
                "  syscage gen --json trace1.trace trace2.trace -o combined.syscage\n",
                prog);
            return 0;
        default:
            return SYSCAGE_ERR_ARG;
        }
    }

    if (optind >= argc) {
        log_error("No trace file specified. Use --help for usage.\n");
        return SYSCAGE_ERR_ARG;
    }

    print_banner();

    size_t trace_count = (size_t)(argc - optind);
    trace_result_t *tr = NULL;

    if (trace_count == 1) {
        tr = tracer_load(argv[optind]);
        if (!tr) {
            log_error("Failed to load trace from %s\n", argv[optind]);
            return SYSCAGE_ERR;
        }
    } else {
        trace_result_t **traces = calloc(trace_count, sizeof(trace_result_t *));
        if (!traces) return SYSCAGE_ERR;

        size_t loaded = 0;
        for (size_t i = 0; i < trace_count; i++) {
            traces[loaded] = tracer_load(argv[optind + i]);
            if (!traces[loaded]) {
                log_error("Failed to load trace from %s\n", argv[optind + i]);
                while (loaded > 0) tracer_free(traces[--loaded]);
                free(traces);
                return SYSCAGE_ERR;
            }
            loaded++;
        }

        tr = tracer_merge(traces, loaded);
        for (size_t j = 0; j < loaded; j++) tracer_free(traces[j]);
        free(traces);

        if (!tr) {
            log_error("Failed to merge traces.\n");
            return SYSCAGE_ERR;
        }

        log_info("Merged %zu trace files.\n", trace_count);
    }

    profile_t *pf = profiler_generate(tr, &opts);
    if (!pf) {
        log_error("Profile generation failed.\n");
        tracer_free(tr);
        return SYSCAGE_ERR;
    }

    char out_path[1024];
    if (opts.output) {
        snprintf(out_path, sizeof(out_path), "%s", opts.output);
    } else {
        snprintf(out_path, sizeof(out_path), "%s%s", argv[optind],
                 SYSCAGE_PROFILE_EXT);
    }

    if (profiler_save(pf, out_path) == 0) {
        log_info("Profile saved to %s\n", out_path);
    } else {
        log_error("Failed to save profile.\n");
        profiler_free(pf);
        tracer_free(tr);
        return SYSCAGE_ERR;
    }

    if (opts.generate_header) {
        char header_path[1028];
        snprintf(header_path, sizeof(header_path), "%s.h", out_path);
        if (profiler_save_header(pf, header_path) == 0) {
            log_info("Header saved to %s\n", header_path);
        }
    }

    if (opts.generate_json) {
        char json_path[1032];
        snprintf(json_path, sizeof(json_path), "%s.json", out_path);
        if (profiler_save_json(pf, json_path) == 0) {
            log_info("JSON profile saved to %s\n", json_path);
        }
    }

    if (!g_config.quiet) {
        profiler_print(pf);
    }

    profiler_free(pf);
    tracer_free(tr);
    return SYSCAGE_OK;
}

static int cmd_enforce(int argc, char **argv, const char *prog)
{
    enforce_opts_t opts = ENFORCE_OPTS_DEFAULT;
    int opt;

    struct option long_opts[] = {
        {"profile",   required_argument, 0, 'p'},
        {"exec",      no_argument,       0, 'e'},
        {"quiet",     no_argument,       0, 'q'},
        {"help",      no_argument,       0, 'h'},
        {0, 0, 0, 0}
    };

    while ((opt = getopt_long(argc, argv, "p:eqh", long_opts, NULL)) != -1) {
        switch (opt) {
        case 'p':
            opts.profile_path = optarg;
            break;
        case 'e':
            opts.mode = ENFORCE_EXEC;
            break;
        case 'q':
            g_config.quiet = 1;
            break;
        case 'h':
            print_banner();
            fprintf(stdout,
                "Usage: %s enforce [options] <pid|command...>\n"
                "\n"
                "Apply a seccomp profile to a process.\n"
                "\n"
                "Options:\n"
                "  -p, --profile FILE   Profile file to apply (required)\n"
                "  -e, --exec           Spawn new process instead of attaching\n"
                "  -q, --quiet          Suppress non-essential output\n"
                "  -h, --help           Show this help\n"
                "\n"
                "Examples:\n"
                "  syscage enforce -p nginx.syscage $(pidof nginx)\n"
                "  syscage enforce -p ls.syscage -e -- /bin/ls -la\n",
                prog);
            return 0;
        default:
            return SYSCAGE_ERR_ARG;
        }
    }

    if (!opts.profile_path) {
        log_error("No profile specified. Use -p/--profile.\n");
        return SYSCAGE_ERR_ARG;
    }

    if (optind >= argc) {
        log_error("No target specified.\n");
        return SYSCAGE_ERR_ARG;
    }

    print_banner();

    profile_t *pf = profiler_load(opts.profile_path);
    if (!pf) {
        log_error("Failed to load profile from %s\n", opts.profile_path);
        return SYSCAGE_ERR;
    }

    int ret;
    if (opts.mode == ENFORCE_EXEC) {
        log_info("Spawning '%s' under profile...\n", argv[optind]);
        pid_t child = enforcer_exec(pf, argv[optind], &argv[optind]);
        if (child > 0) {
            log_info("Child PID: %d\n", child);
            ret = SYSCAGE_OK;
        } else {
            log_error("Failed to spawn under profile.\n");
            ret = SYSCAGE_ERR;
        }
    } else {
        char *endptr;
        long pid = strtol(argv[optind], &endptr, 10);
        if (*endptr != '\0' || pid <= 0) {
            log_error("For attach mode, provide a numeric PID.\n");
            profiler_free(pf);
            return SYSCAGE_ERR_ARG;
        }
        log_info("Attaching profile to PID %ld...\n", pid);
        ret = enforcer_attach(pf, (pid_t)pid);
    }

    profiler_free(pf);
    return ret;
}

static int cmd_watch(int argc, char **argv, const char *prog)
{
    enforce_opts_t opts = ENFORCE_OPTS_DEFAULT;
    opts.mode = ENFORCE_WATCH;
    int opt;

    struct option long_opts[] = {
        {"profile",   required_argument, 0, 'p'},
        {"abort",     no_argument,       0, 'a'},
        {"quiet",     no_argument,       0, 'q'},
        {"help",      no_argument,       0, 'h'},
        {0, 0, 0, 0}
    };

    while ((opt = getopt_long(argc, argv, "p:aqh", long_opts, NULL)) != -1) {
        switch (opt) {
        case 'p':
            opts.profile_path = optarg;
            break;
        case 'a':
            opts.abort_on_violation = 1;
            break;
        case 'q':
            g_config.quiet = 1;
            break;
        case 'h':
            print_banner();
            fprintf(stdout,
                "Usage: %s watch [options] <command...>\n"
                "\n"
                "Spawn a process under profile enforcement with violation monitoring.\n"
                "\n"
                "Options:\n"
                "  -p, --profile FILE   Profile file to apply (required)\n"
                "  -a, --abort          Abort on first violation\n"
                "  -q, --quiet          Suppress non-essential output\n"
                "  -h, --help           Show this help\n"
                "\n"
                "Examples:\n"
                "  syscage watch -p nginx.syscage -- /usr/sbin/nginx\n",
                prog);
            return 0;
        default:
            return SYSCAGE_ERR_ARG;
        }
    }

    if (!opts.profile_path) {
        log_error("No profile specified. Use -p/--profile.\n");
        return SYSCAGE_ERR_ARG;
    }

    if (optind >= argc) {
        log_error("No command specified.\n");
        return SYSCAGE_ERR_ARG;
    }

    print_banner();

    profile_t *pf = profiler_load(opts.profile_path);
    if (!pf) {
        log_error("Failed to load profile from %s\n", opts.profile_path);
        return SYSCAGE_ERR;
    }

    log_info("Watch mode: spawning '%s' under profile %s\n",
             argv[optind], opts.profile_path);
    int ret = enforcer_watch(pf, argv[optind], &argv[optind]);

    profiler_free(pf);
    return ret;
}

int main(int argc, char **argv)
{
    const char *prog = argv[0];

    if (argc < 2) {
        print_banner();
        print_usage(prog);
        return SYSCAGE_ERR_ARG;
    }

    if (strcmp(argv[1], "--help") == 0 || strcmp(argv[1], "-h") == 0) {
        print_banner();
        print_usage(prog);
        return SYSCAGE_OK;
    }

    if (strcmp(argv[1], "--version") == 0) {
        fprintf(stdout, "%s\n", SYSCAGE_NAME);
        return SYSCAGE_OK;
    }

    if (strcmp(argv[1], "-v") == 0 || strcmp(argv[1], "--verbose") == 0) {
        g_config.log_level = LOG_DEBUG;
        argc--;
        argv++;
    }

    if (strcmp(argv[1], "-q") == 0 || strcmp(argv[1], "--quiet") == 0) {
        g_config.quiet = 1;
        argc--;
        argv++;
    }

    const char *cmd = argv[1];

    if (strcmp(cmd, "learn") == 0) {
        return cmd_learn(argc - 1, argv + 1, prog);
    } else if (strcmp(cmd, "gen") == 0) {
        return cmd_gen(argc - 1, argv + 1, prog);
    } else if (strcmp(cmd, "enforce") == 0) {
        return cmd_enforce(argc - 1, argv + 1, prog);
    } else if (strcmp(cmd, "watch") == 0) {
        return cmd_watch(argc - 1, argv + 1, prog);
    } else {
        log_error("Unknown command: %s\n", cmd);
        fprintf(stderr, "Run '%s --help' for usage.\n", prog);
        return SYSCAGE_ERR_ARG;
    }
}
