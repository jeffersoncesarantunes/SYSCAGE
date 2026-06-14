#ifndef SYSCAGE_H
#define SYSCAGE_H

#include <stdint.h>
#include <stddef.h>
#include <sys/types.h>

#define SYSCAGE_VERSION "0.1.0"
#define SYSCAGE_NAME    "syscage"
#define SYSCAGE_DESC    "Behavioral syscall profiler and seccomp policy generator"

/* Maximum syscall number for x86_64 (currently ~450) */
#define SYSCAGE_MAX_SYSCALL 512

/* Profile file extension */
#define SYSCAGE_PROFILE_EXT ".syscage"

/* Trace file extension */
#define SYSCAGE_TRACE_EXT ".trace"

/* Return codes */
#define SYSCAGE_OK       0
#define SYSCAGE_ERR     -1
#define SYSCAGE_ERR_ARG -2
#define SYSCAGE_ERR_SYS -3
#define SYSCAGE_ERR_PERM -4

/* Log levels */
typedef enum {
    LOG_SILENT = 0,
    LOG_ERROR,
    LOG_WARN,
    LOG_INFO,
    LOG_DEBUG
} log_level_t;

/* Runtime configuration */
typedef struct {
    log_level_t log_level;
    int color_output;
    int quiet;
} syscage_config_t;

extern syscage_config_t g_config;

/* Logging */
void log_write(log_level_t level, const char *fmt, ...)
    __attribute__((format(printf, 2, 3)));

#define log_error(...)  log_write(LOG_ERROR, __VA_ARGS__)
#define log_warn(...)   log_write(LOG_WARN,  __VA_ARGS__)
#define log_info(...)   log_write(LOG_INFO,  __VA_ARGS__)
#define log_debug(...)  log_write(LOG_DEBUG, __VA_ARGS__)

/* Utilities */
size_t syscage_read_file(const char *path, char **out);
int    syscage_write_file(const char *path, const char *data, size_t len);
pid_t  syscage_resolve_target(const char *spec);

#endif
