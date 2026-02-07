#include "../include/server.h"
#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>

SSL_CTX *global_ssl_ctx = NULL;
ConnLimitsTracker *g_conn_tracker = NULL; // Global connection limits tracker
ServerConfig g_config = {0};              // Global configuration instance

int main(int argc, char const *argv[])
{
    (void)argc;
    (void)argv;

    config_init_defaults(&g_config);
    config_load_from_file(&g_config, "server.conf");
    config_load_from_env(&g_config);

    if (config_validate(&g_config) < 0)
    {
        LOG_ERROR("Config validation failed\n");
        return EXIT_FAILURE;
    }

    if (logger_init(g_config.log_file_path,
                    g_config.log_level,
                    g_config.log_to_console) < 0)
    {
        LOG_ERROR("Logger init failed\n");
        return EXIT_FAILURE;
    }

    LOG_INFO("Server starting...");

    config_print(&g_config);

    // Initialize connection limits tracker
    g_conn_tracker = conn_limits_init(
        g_config.max_connections,
        g_config.max_connections_per_ip);
    if (!g_conn_tracker)
    {
        LOG_ERROR("Failed to initialize connection limits tracker");
        return EXIT_FAILURE;
    }

    // Initialize signal handlers
    if (signals_init() < 0)
    {
        LOG_ERROR("Failed to initialize signal handlers");
        return EXIT_FAILURE;
    }

    printf("\n");
    printf("╔════════════════════════════════════════════════╗\n");
    printf("║   HTTP/WebSocket Server with EPOLL            ║\n");
    printf("║   I/O Multiplexing - No Threading!            ║\n");
    printf("╚════════════════════════════════════════════════╝\n\n");

    struct Server server = server_constructor(AF_INET, g_config.port, SOCK_STREAM, 0, g_config.backlog, INADDR_ANY);
    /* store ssl context globally if needed */
    global_ssl_ctx = server.ssl_ctx;
    /* Start epoll event loop (replaces multithreading) */
    listening_to_client_epoll(server.socket_fd, server.ssl_ctx);

    logger_flush();
    logger_shutdown();
    config_cleanup(&g_config);
    if (g_conn_tracker)
        conn_limits_destroy(g_conn_tracker);
    return 0;
}
void clean_things(void *first, ...)
{
    va_list args;
    va_start(args, first);
    void *ptr = first;
    while (ptr != NULL)
    {
        free(ptr);
        ptr = va_arg(args, void *);
    }
    va_end(args);
}