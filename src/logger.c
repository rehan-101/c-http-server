#include "../include/logger.h"
#include <stdarg.h>
#include <string.h>
#include <errno.h>

/**
 * Logger Implementation
 *
 * Thread-safe logging with multiple outputs
 */

/* Global logger state */
static struct
{
    FILE *log_file;       // Log file handle
    LogLevel min_level;   // Minimum level to log
    int to_console;       // Log to stdout too
    pthread_mutex_t lock; // Thread safety
    int initialized;      // Init flag
} g_logger = {
    .log_file = NULL,
    .min_level = LOG_INFO,
    .to_console = 1,
    .lock = PTHREAD_MUTEX_INITIALIZER,
    .initialized = 0};

int logger_init(const char *log_file, LogLevel min_level, int to_console)
{
    pthread_mutex_lock(&g_logger.lock);

    if (g_logger.initialized)
    {
        pthread_mutex_unlock(&g_logger.lock);
        return 0; // Already initialized
    }

    g_logger.min_level = min_level;
    g_logger.to_console = to_console;

    /* Open log file if specified */
    if (log_file)
    {
        g_logger.log_file = fopen(log_file, "a"); // Append mode
        if (!g_logger.log_file)
        {
            fprintf(stderr,"ERROR: Could not open log file '%s': %s\n",
                    log_file, strerror(errno));
            pthread_mutex_unlock(&g_logger.lock);
            return -1;
        }

        /* Line buffering for better real-time logging */
        setlinebuf(g_logger.log_file);
    }

    g_logger.initialized = 1;

    pthread_mutex_unlock(&g_logger.lock);

    /* Log initialization */
    LOG_INFO("Logger initialized (file=%s, level=%s, console=%s)",
             log_file ? log_file : "none",
             logger_level_string(min_level),
             to_console ? "yes" : "no");

    return 0;
}
/*
*** logger_shutdown - Clean shutdown
*/
void logger_shutdown()
{
    pthread_mutex_lock(&g_logger.lock);

    if (!g_logger.initialized)
    {
        pthread_mutex_unlock(&g_logger.lock);
        return;
    }

    LOG_INFO("Logger shutting down");

    if (g_logger.log_file)
    {
        fflush(g_logger.log_file);
        fclose(g_logger.log_file);
        g_logger.log_file = NULL;
    }

    g_logger.initialized = 0;

    pthread_mutex_unlock(&g_logger.lock);
}
/**
 * logger_level_string - Human-readable level names
 */
const char *logger_level_string(LogLevel level)
{
    switch (level)
    {
    case LOG_DEBUG:
        return "DEBUG";
    case LOG_INFO:
        return "INFO ";
    case LOG_WARN:
        return "WARN ";
    case LOG_ERROR:
        return "ERROR";
    case LOG_FATAL:
        return "FATAL";
    default:
        return "?????";
    }
}
/**
 * logger_log - Core logging function
 *
 * Format: [TIMESTAMP] [LEVEL] [file:line] message
 * Example: [2024-02-04 10:30:45] [INFO ] [server.c:123] Client connected
 *
 * Why this format:
 * - Timestamp: Know when it happened
 * - Level: Filter by severity
 * - Location: Find code quickly
 * - Message: What happened
 */
void logger_log(LogLevel level, const char *file, int line,
                const char *func, const char *format, ...)
{

    /* Skip if below minimum level */
    if (level < g_logger.min_level)
    {
        return;
    }

    pthread_mutex_lock(&g_logger.lock);

    if (!g_logger.initialized)
    {
        pthread_mutex_unlock(&g_logger.lock);
        return;
    }

    /* Get current time */
    time_t now = time(NULL);
    struct tm *tm_info = localtime(&now);
    char timestamp[32];
    strftime(timestamp, sizeof(timestamp), "%Y-%m-%d %H:%M:%S", tm_info);

    /* Extract just filename (not full path) */
    const char *filename = strrchr(file, '/');
    if (filename)
    {
        filename++; // Skip the '/'
    }
    else
    {
        filename = file;
    }

    /* Format the message */
    char message[1024];
    va_list args;
    va_start(args, format);
    vsnprintf(message, sizeof(message), format, args);
    va_end(args);

    /* Build log line */
    char log_line[1280];
    int len = snprintf(log_line, sizeof(log_line),
                       "[%s] [%s] [%s:%d] %s\n",
                       timestamp,
                       logger_level_string(level),
                       filename,
                       line,
                       message);

    /* Write to console */
    if (g_logger.to_console)
    {
        /* Use stderr for WARN/ERROR/FATAL */
        FILE *out = (level >= LOG_WARN) ? stderr : stdout;
        fputs(log_line, out);
        fflush(out);
    }

    /* Write to file */
    if (g_logger.log_file)
    {
        fputs(log_line, g_logger.log_file);
        /* Auto-flush for ERROR and FATAL */
        if (level >= LOG_ERROR)
        {
            fflush(g_logger.log_file);
        }
    }

    pthread_mutex_unlock(&g_logger.lock);
}
/**
 * logger_flush - Force flush to disk
 *
 * Why: Buffered I/O is fast but can lose data on crash
 * Call this periodically or before critical operations
 */
void logger_flush()
{
    pthread_mutex_lock(&g_logger.lock);

    if (g_logger.log_file)
    {
        fflush(g_logger.log_file);
    }

    pthread_mutex_unlock(&g_logger.lock);
}

/**
 * logger_hexdump - Dump binary data in hex
 *
 * Format:
 * 00000000: 48 65 6c 6c 6f 20 57 6f  72 6c 64 00 00 00 00 00  Hello World.....
 *
 * Useful for debugging WebSocket frames, SSL data, etc.
 */
void logger_hexdump(LogLevel level, const char *desc,
                    const void *data, size_t len)
{

    if (level < g_logger.min_level)
    {
        return;
    }

    pthread_mutex_lock(&g_logger.lock);

    const unsigned char *bytes = (const unsigned char *)data;
    char line[80];
    size_t offset = 0;

    LOG_INFO("HEXDUMP: %s (%zu bytes)", desc, len);

    while (offset < len)
    {
        int line_len = 0;

        /* Offset */
        line_len += sprintf(line + line_len, "%08zx: ", offset);

        /* Hex bytes */
        for (size_t i = 0; i < 16; i++)
        {
            if (offset + i < len)
            {
                line_len += sprintf(line + line_len, "%02x ", bytes[offset + i]);
            }
            else
            {
                line_len += sprintf(line + line_len, "   ");
            }

            if (i == 7)
            {
                line_len += sprintf(line + line_len, " ");
            }
        }

        line_len += sprintf(line + line_len, " ");

        /* ASCII */
        for (size_t i = 0; i < 16 && offset + i < len; i++)
        {
            unsigned char c = bytes[offset + i];
            line_len += sprintf(line + line_len, "%c",
                                (c >= 32 && c < 127) ? c : '.');
        }

        LOG_INFO("%s", line);
        offset += 16;
    }

    pthread_mutex_unlock(&g_logger.lock);
}
