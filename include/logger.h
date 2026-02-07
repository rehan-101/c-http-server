#ifndef LOGGER_H
#define LOGGER_H

#include <stdio.h>
#include <time.h>
#include <pthread.h>

/**
 * Logging System
 * 
 * Why we need structured logging:
 * - Debug issues in production
 * - Monitor server health
 * - Audit security events
 * - Performance analysis
 * 
 * Features:
 * - Multiple log levels
 * - Thread-safe
 * - File + console output
 * - Timestamp + severity
 * - Source location (file:line)
 */

/* Log Levels */
typedef enum {
    LOG_DEBUG = 0,    // Detailed debugging info
    LOG_INFO = 1,     // General information
    LOG_WARN = 2,     // Warning messages
    LOG_ERROR = 3,    // Error messages
    LOG_FATAL = 4     // Fatal errors (server should exit)
} LogLevel;

/* Log entry structure (for future structured logging) */
typedef struct {
    time_t timestamp;
    LogLevel level;
    const char *file;
    int line;
    const char *function;
    char message[1024];
} LogEntry;

/**
 * Initialize logging system
 * 
 *  Path to log file (NULL for console only)
 *  Minimum level to log (DEBUG=0, INFO=1, etc.)
 *  Also log to stdout (1) or not (0)
 * 
 * Returns: 0 on success, -1 on error
 */
int logger_init(const char *log_file, LogLevel min_level, int to_console);

/**
 * Close logging system
 * Flushes buffers and closes files
 */
void logger_shutdown();
/**
 * Core logging function (don't call directly, use macros below)
 */
void logger_log(LogLevel level, const char *file, int line, 
                const char *func, const char *format, ...)
                __attribute__((format(printf, 5, 6)));

/**
 * Flush log buffer to disk
 * Important: Call periodically or before shutdown
 */
void logger_flush();

/**
 * Get string representation of log level
 */
const char* logger_level_string(LogLevel level);

/**
 * Convenience Macros - Use these for logging!
 * 
 * Automatically includes:
 * - File name (__FILE__)
 * - Line number (__LINE__)
 * - Function name (__func__)
 * 
 * Usage:
 *   LOG_DEBUG("Client connected from %s:%d", ip, port);
 *   LOG_ERROR("Failed to allocate memory: %s", strerror(errno));
 */

#define LOG_DEBUG(...) \
    logger_log(LOG_DEBUG, __FILE__, __LINE__, __func__, __VA_ARGS__)

#define LOG_INFO(...) \
    logger_log(LOG_INFO, __FILE__, __LINE__, __func__, __VA_ARGS__)

#define LOG_WARN(...) \
    logger_log(LOG_WARN, __FILE__, __LINE__, __func__, __VA_ARGS__)

#define LOG_ERROR(...) \
    logger_log(LOG_ERROR, __FILE__, __LINE__, __func__, __VA_ARGS__)

#define LOG_FATAL(...) \
    logger_log(LOG_FATAL, __FILE__, __LINE__, __func__, __VA_ARGS__)

/**
 * Conditional logging (only if condition is true)
 */
#define LOG_DEBUG_IF(cond, ...) \
    do { if (cond) LOG_DEBUG(__VA_ARGS__); } while(0)

#define LOG_INFO_IF(cond, ...) \
    do { if (cond) LOG_INFO(__VA_ARGS__); } while(0)

/**
 * Log with error number (errno)
 * Automatically appends: strerror(errno)
 */
#define LOG_ERRNO(level, msg) \
    logger_log(level, __FILE__, __LINE__, __func__, "%s: %s", msg, strerror(errno))

/**
 * Performance logging - log time taken
 * 
 * Usage:
 *   PERF_START();
 *   // ... expensive operation ...
 *   PERF_END("Database query");
 */
#define PERF_START() \
    struct timespec _perf_start, _perf_end; \
    clock_gettime(CLOCK_MONOTONIC, &_perf_start)

#define PERF_END(operation) \
    do { \
        clock_gettime(CLOCK_MONOTONIC, &_perf_end); \
        long ms = (_perf_end.tv_sec - _perf_start.tv_sec) * 1000 + \
                  (_perf_end.tv_nsec - _perf_start.tv_nsec) / 1000000; \
        LOG_INFO("PERF: %s took %ld ms", operation, ms); \
    } while(0)

/**
 * Assert macro with logging
 * Logs error and returns if condition is false
 */
#define LOG_ASSERT(condition, ...) \
    do { \
        if (!(condition)) { \
            LOG_ERROR(__VA_ARGS__); \
            return -1; \
        } \
    } while(0)

/**
 * Log hexdump (for debugging binary data)
 * Useful for debugging protocol issues
 */
void logger_hexdump(LogLevel level, const char *desc, 
                    const void *data, size_t len);

#endif