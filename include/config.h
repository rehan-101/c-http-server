#ifndef CONFIG_H
#define CONFIG_H

#include <stdint.h>
#include <stdio.h>

/**
 * Server Configuration Structure
 * 
 * This centralizes all server configuration in one place.
 * Values can be loaded from a config file or environment variables.
 * 
 * Why we need this:
 * - Hardcoded values make deployment difficult
 * - Different environments (dev/prod) need different settings
 * - Makes testing easier (can use test config)
 */
typedef struct {
    /* Network Configuration */
    int port;                           // Server listening port
    char *bind_address;                 // IP to bind to ("0.0.0.0" for all)
    int backlog;                        // Listen queue size
    
    /* Connection Limits (Critical for preventing DoS) */
    int max_connections;                // Max simultaneous connections
    int max_connections_per_ip;         // Max connections from single IP
    
    /* Timeouts (Critical for resource management) */
    int connection_timeout_sec;         // Max time for connection to be idle
    int ssl_handshake_timeout_sec;      // Max time for SSL handshake
    int request_timeout_sec;            // Max time to receive complete request
    int keepalive_timeout_sec;          // Keep-alive timeout
    
    /* Request Limits (Prevent DoS via large requests) */
    size_t max_request_size;            // Max HTTP request size in bytes
    size_t max_header_size;             // Max size of all headers
    int max_header_count;               // Max number of headers
    size_t max_uri_length;              // Max URI length
    
    /* SSL/TLS Configuration */
    char *ssl_cert_path;                // Path to SSL certificate
    char *ssl_key_path;                 // Path to SSL private key
    int ssl_verify_client;              // Require client certificates (0/1)
    
    /* Database Configuration */
    char *db_path;                      // Path to SQLite database
    int db_pool_size;                   // Number of DB connections in pool
    
    /* Logging Configuration */
    char *log_file_path;                // Path to log file
    int log_level;                      // 0=DEBUG, 1=INFO, 2=WARN, 3=ERROR
    int log_to_console;                 // Also log to stdout (0/1)
    int log_to_file;                    // Log to file (0/1)
    
    /* Worker Configuration (for future multi-process) */
    int worker_processes;               // Number of worker processes
    
    /* JWT Configuration */
    char *jwt_secret;                   // JWT signing secret
    int jwt_expiry_seconds;             // JWT token expiry time
    
    /* WebSocket Configuration */
    int ws_max_frame_size;              // Max WebSocket frame size
    int ws_ping_interval_sec;           // WebSocket ping interval
    
    /* Performance Tuning */
    int epoll_timeout_ms;               // Epoll wait timeout
    int epoll_max_events;               // Max events per epoll_wait
    
} ServerConfig;

/* Default configuration values */
#define DEFAULT_PORT 8443
#define DEFAULT_BIND_ADDRESS "0.0.0.0"
#define DEFAULT_BACKLOG 128
#define DEFAULT_MAX_CONNECTIONS 10000
#define DEFAULT_MAX_CONNECTIONS_PER_IP 100
#define DEFAULT_CONNECTION_TIMEOUT 60
#define DEFAULT_SSL_HANDSHAKE_TIMEOUT 10
#define DEFAULT_REQUEST_TIMEOUT 30
#define DEFAULT_KEEPALIVE_TIMEOUT 60
#define DEFAULT_MAX_REQUEST_SIZE (1024 * 1024)  // 1MB
#define DEFAULT_MAX_HEADER_SIZE (64 * 1024)     // 64KB
#define DEFAULT_MAX_HEADER_COUNT 100
#define DEFAULT_MAX_URI_LENGTH 8192
#define DEFAULT_SSL_CERT_PATH "certs/cert.pem"
#define DEFAULT_SSL_KEY_PATH "certs/key.pem"
#define DEFAULT_DB_PATH "users.db"
#define DEFAULT_LOG_FILE_PATH "server.log"
#define DEFAULT_LOG_LEVEL 1  // INFO
#define DEFAULT_EPOLL_TIMEOUT_MS 1000
#define DEFAULT_EPOLL_MAX_EVENTS 1024
#define DEFAULT_WS_MAX_FRAME_SIZE (1024 * 1024)  // 1MB
#define DEFAULT_WS_PING_INTERVAL 30

/* Global configuration instance */
extern ServerConfig g_config;

/**
 * Initialize configuration with defaults
 * Call this before loading config file
 */
void config_init_defaults(ServerConfig *config);

/**
 * Load configuration from file
 * Format: KEY=VALUE (one per line)
 * 
 * Returns: 0 on success, -1 on error
 */
int config_load_from_file(ServerConfig *config, const char *filepath);

/**
 * Load configuration from environment variables
 * Overrides file config if set
 * 
 * Environment variables:
 * - SERVER_PORT
 * - SERVER_MAX_CONNECTIONS
 * - SERVER_LOG_LEVEL
 * etc.
 */
void config_load_from_env(ServerConfig *config);

/**
 * Validate configuration
 * Ensures all values are within acceptable ranges
 * 
 * Returns: 0 if valid, -1 if invalid
 */
int config_validate(const ServerConfig *config);

/**
 * Print current configuration (for debugging)
 */
void config_print(const ServerConfig *config);

/**
 * Free allocated configuration resources
 */
void config_cleanup(ServerConfig *config);

#endif