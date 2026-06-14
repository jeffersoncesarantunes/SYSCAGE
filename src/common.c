#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <time.h>
#include <dirent.h>
#include <ctype.h>
#include <unistd.h>
#include <libgen.h>
#include <sys/stat.h>
#include <sys/types.h>

#include "syscage.h"

syscage_config_t g_config = {
    .log_level = LOG_INFO,
    .color_output = 1,
    .quiet = 0
};

static const char *log_label(log_level_t level)
{
    switch (level) {
    case LOG_ERROR: return "ERR";
    case LOG_WARN:  return "WRN";
    case LOG_INFO:  return "INF";
    case LOG_DEBUG: return "DBG";
    default:        return "???";
    }
}

static const char *log_color(log_level_t level)
{
    if (!g_config.color_output) return "";
    switch (level) {
    case LOG_ERROR: return "\033[1;31m";
    case LOG_WARN:  return "\033[1;33m";
    case LOG_INFO:  return "\033[1;32m";
    case LOG_DEBUG: return "\033[1;36m";
    default:        return "\033[0m";
    }
}

static const char *log_reset(void)
{
    return g_config.color_output ? "\033[0m" : "";
}

void log_write(log_level_t level, const char *fmt, ...)
{
    if (level > g_config.log_level) return;

    time_t now = time(NULL);
    struct tm *tm = localtime(&now);

    fprintf(stderr, "%s[%s]%s %02d:%02d:%02d  ",
            log_color(level), log_label(level), log_reset(),
            tm->tm_hour, tm->tm_min, tm->tm_sec);

    va_list args;
    va_start(args, fmt);
    vfprintf(stderr, fmt, args);
    va_end(args);
}

size_t syscage_read_file(const char *path, char **out)
{
    FILE *f = fopen(path, "rb");
    if (!f) {
        log_error("Cannot open %s\n", path);
        return 0;
    }

    struct stat st;
    if (fstat(fileno(f), &st) != 0) {
        fclose(f);
        return 0;
    }

    *out = malloc((size_t)st.st_size + 1);
    if (!*out) {
        fclose(f);
        return 0;
    }

    size_t nread = fread(*out, 1, (size_t)st.st_size, f);
    fclose(f);

    (*out)[nread] = '\0';
    return nread;
}

int syscage_write_file(const char *path, const char *data, size_t len)
{
    FILE *f = fopen(path, "wb");
    if (!f) {
        log_error("Cannot write %s\n", path);
        return -1;
    }

    size_t written = fwrite(data, 1, len, f);
    fclose(f);

    return (written == len) ? 0 : -1;
}

pid_t syscage_resolve_target(const char *spec)
{
    char *endptr;
    long val = strtol(spec, &endptr, 10);
    if (*endptr == '\0' && val > 0) {
        return (pid_t)val;
    }

    DIR *proc = opendir("/proc");
    if (!proc) return -1;

    struct dirent *entry;
    while ((entry = readdir(proc)) != NULL) {
        if (!isdigit((unsigned char)entry->d_name[0])) continue;

        char cmdline_path[512];
        snprintf(cmdline_path, sizeof(cmdline_path),
                 "/proc/%s/comm", entry->d_name);

        char *comm = NULL;
        size_t len = syscage_read_file(cmdline_path, &comm);
        if (!comm) continue;

        if (len > 0 && comm[len - 1] == '\n') comm[len - 1] = '\0';

        if (strcmp(comm, spec) == 0) {
            pid_t pid = (pid_t)atol(entry->d_name);
            free(comm);
            closedir(proc);
            return pid;
        }
        free(comm);
    }

    closedir(proc);
    return -1;
}
