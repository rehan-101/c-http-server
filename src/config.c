#include "config.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

/**
 * config_init_defaults - Initialize with sensible defaults
 * 
 * Why: Always start with known good values
 * Then override with file/env config
 */

void config_init_defaults(ServerConfig *config) {
    memset(config, 0, sizeof(ServerConfig));
    
    /* Network */
    config->port = DEFAULT_PORT;
    config->bind_address = strdup(DEFAULT_BIND_ADDRESS);
    config->backlog = DEFAULT_BACKLOG;
    
    /* Connection Limits */
    config->max_connections = DEFAULT_MAX_CONNECTIONS;
    config->max_connections_per_ip = DEFAULT_MAX_CONNECTIONS_PER_IP;
    
    /* Timeouts */
    config->connection_timeout_sec = DEFAULT_CONNECTION_TIMEOUT;
    config->ssl_handshake_timeout_sec = DEFAULT_SSL_HANDSHAKE_TIMEOUT;
    config->request_timeout_sec = DEFAULT_REQUEST_TIMEOUT;
    config->keepalive_timeout_sec = DEFAULT_KEEPALIVE_TIMEOUT;
    
    /* Request Limits */
    config->max_request_size = DEFAULT_MAX_REQUEST_SIZE;
    config->max_header_size = DEFAULT_MAX_HEADER_SIZE;
    config->max_header_count = DEFAULT_MAX_HEADER_COUNT;
    config->max_uri_length = DEFAULT_MAX_URI_LENGTH;
    
    /* SSL/TLS */
    config->ssl_cert_path = strdup(DEFAULT_SSL_CERT_PATH);
    config->ssl_key_path = strdup(DEFAULT_SSL_KEY_PATH);
    config->ssl_verify_client = 0;
    
    /* Database */
    config->db_path = strdup(DEFAULT_DB_PATH);
    config->db_pool_size = 1;  // Single connection for now
    
    /* Logging */
    config->log_file_path = strdup(DEFAULT_LOG_FILE_PATH);
    config->log_level = DEFAULT_LOG_LEVEL;
    config->log_to_console = 1;
    config->log_to_file = 1;
    
    /* Workers */
    config->worker_processes = 1;
    
    /* JWT */
    config->jwt_secret = NULL;  // Must be set via env
    config->jwt_expiry_seconds = 3600;  // 1 hour
    
    /* WebSocket */
    config->ws_max_frame_size = DEFAULT_WS_MAX_FRAME_SIZE;
    config->ws_ping_interval_sec = DEFAULT_WS_PING_INTERVAL;
    
    /* Performance */
    config->epoll_timeout_ms = DEFAULT_EPOLL_TIMEOUT_MS;
    config->epoll_max_events = DEFAULT_EPOLL_MAX_EVENTS;
}

/**
 * trim - Remove leading/trailing whitespace
 * Helper function for config parsing
 */
static char* trim(char* str) {
    char *end;
    
    /* Trim leading space */
    while(isspace((unsigned char)*str)) str++;
    
    if(*str == 0)  /* All spaces? */
        return str;
    
    /* Trim trailing space */
    end = str + strlen(str) - 1;
    while(end > str && isspace((unsigned char)*end)) end--;
    
    /* Write new null terminator */
    end[1] = '\0';
    
    return str;
}

/**
 * config_load_from_file - Load configuration from file
 * 
 * Format: KEY=VALUE
 * Comments start with #
 * 
 * Example:
 * # Server configuration
 * port=8443
 * max_connections=10000
 * log_level=1
 */
int config_load_from_file(ServerConfig *config, const char *filepath) {
    FILE *fp = fopen(filepath, "r");
    if (!fp) {
        fprintf(stderr, "[CONFIG] Warning: Could not open config file '%s', using defaults\n", filepath);
        return -1;
    }
    
    char line[256];
    int line_num = 0;
    
    while (fgets(line, sizeof(line), fp)) {
        line_num++;
        
        /* Trim whitespace */
        char *trimmed = trim(line);
        
        /* Skip empty lines and comments */
        if (trimmed[0] == '\0' || trimmed[0] == '#') {
            continue;
        }
        
        /* Parse KEY=VALUE */
        char *equals = strchr(trimmed, '=');
        if (!equals) {
            fprintf(stderr, "[CONFIG] Warning: Invalid config line %d: %s\n", line_num, trimmed);
            continue;
        }
        
        *equals = '\0';
        char *key = trim(trimmed);
        char *value = trim(equals + 1);
        
        /* Parse known keys */
        if (strcmp(key, "port") == 0) {
            config->port = atoi(value);
        }
        else if (strcmp(key, "max_connections") == 0) {
            config->max_connections = atoi(value);
        }
        else if (strcmp(key, "max_connections_per_ip") == 0) {
            config->max_connections_per_ip = atoi(value);
        }
        else if (strcmp(key, "connection_timeout") == 0) {
            config->connection_timeout_sec = atoi(value);
        }
        else if (strcmp(key, "ssl_handshake_timeout") == 0) {
            config->ssl_handshake_timeout_sec = atoi(value);
        }
        else if (strcmp(key, "request_timeout") == 0) {
            config->request_timeout_sec = atoi(value);
        }
        else if (strcmp(key, "log_level") == 0) {
            config->log_level = atoi(value);
        }
        else if (strcmp(key, "ssl_cert_path") == 0) {
            free(config->ssl_cert_path);
            config->ssl_cert_path = strdup(value);
        }
        else if (strcmp(key, "ssl_key_path") == 0) {
            free(config->ssl_key_path);
            config->ssl_key_path = strdup(value);
        }
        else if (strcmp(key, "db_path") == 0) {
            free(config->db_path);
            config->db_path = strdup(value);
        }
        else if (strcmp(key, "log_file_path") == 0) {
            free(config->log_file_path);
            config->log_file_path = strdup(value);
        }
        else {
            fprintf(stderr, "[CONFIG] Warning: Unknown config key '%s' on line %d\n", key, line_num);
        }
    }
    
    fclose(fp);
    printf("[CONFIG] Loaded configuration from '%s'\n", filepath);
    return 0;
}

/**
 * config_load_from_env - Override with environment variables
 * 
 * Why: Env vars are standard in containerized deployments
 * They override file config for flexibility
 */

void config_load_from_env(ServerConfig *config) {
    char *env_value;
    
    if ((env_value = getenv("SERVER_PORT")) != NULL) {
        config->port = atoi(env_value);
        printf("[CONFIG] Override port from env: %d\n", config->port);
    }
    
    if ((env_value = getenv("SERVER_MAX_CONNECTIONS")) != NULL) {
        config->max_connections = atoi(env_value);
        printf("[CONFIG] Override max_connections from env: %d\n", config->max_connections);
    }
    
    if ((env_value = getenv("SERVER_LOG_LEVEL")) != NULL) {
        config->log_level = atoi(env_value);
        printf("[CONFIG] Override log_level from env: %d\n", config->log_level);
    }
    
    if ((env_value = getenv("SECRET_KEY")) != NULL) {
        free(config->jwt_secret);
        config->jwt_secret = strdup(env_value);
        printf("[CONFIG] JWT secret loaded from env\n");
    }
    
    if ((env_value = getenv("DB_PATH")) != NULL) {
        free(config->db_path);
        config->db_path = strdup(env_value);
        printf("[CONFIG] Override db_path from env: %s\n", config->db_path);
    }
}

/**
 * config_validate - Ensure configuration is sane
 * 
 * Why: Catch configuration errors early
 * Better to fail at startup than at runtime
 */

int config_validate(const ServerConfig *config) {
    int errors = 0;
    
    /* Port validation */
    if (config->port < 1 || config->port > 65535) {
        fprintf(stderr, "[CONFIG] ERROR: Invalid port %d (must be 1-65535)\n", config->port);
        errors++;
    }
    
    /* Connection limits */
    if (config->max_connections < 1) {
        fprintf(stderr, "[CONFIG] ERROR: max_connections must be at least 1\n");
        errors++;
    }
    
    if (config->max_connections_per_ip < 1) {
        fprintf(stderr, "[CONFIG] ERROR: max_connections_per_ip must be at least 1\n");
        errors++;
    }
    
    /* Timeouts */
    if (config->connection_timeout_sec < 1) {
        fprintf(stderr, "[CONFIG] ERROR: connection_timeout must be at least 1 second\n");
        errors++;
    }
    
    /* Request limits */
    if (config->max_request_size < 1024) {
        fprintf(stderr, "[CONFIG] ERROR: max_request_size too small (min 1KB)\n");
        errors++;
    }
    
    /* SSL paths */
    if (!config->ssl_cert_path || strlen(config->ssl_cert_path) == 0) {
        fprintf(stderr, "[CONFIG] ERROR: ssl_cert_path not set\n");
        errors++;
    }
    
    if (!config->ssl_key_path || strlen(config->ssl_key_path) == 0) {
        fprintf(stderr, "[CONFIG] ERROR: ssl_key_path not set\n");
        errors++;
    }
    
    /* JWT secret (critical for security!) */
    if (!config->jwt_secret || strlen(config->jwt_secret) < 16) {
        fprintf(stderr, "[CONFIG] ERROR: JWT secret not set or too short (min 16 chars)\n");
        fprintf(stderr, "[CONFIG] Set JWT_SECRET environment variable\n");
        errors++;
    }
    
    if (errors > 0) {
        fprintf(stderr, "[CONFIG] Configuration validation failed with %d errors\n", errors);
        return -1;
    }
    
    printf("[CONFIG] Configuration validated successfully\n");
    return 0;
}

/**
 * config_print - Display current configuration
 * 
 * Why: Helpful for debugging and verifying config
 * Don't print secrets!
 */
void config_print(const ServerConfig *config) {
    printf("\n========== Server Configuration ==========\n");
    printf("Network:\n");
    printf("  Port: %d\n", config->port);
    printf("  Bind Address: %s\n", config->bind_address);
    printf("  Backlog: %d\n", config->backlog);
    
    printf("\nConnection Limits:\n");
    printf("  Max Connections: %d\n", config->max_connections);
    printf("  Max Per IP: %d\n", config->max_connections_per_ip);
    
    printf("\nTimeouts:\n");
    printf("  Connection: %d sec\n", config->connection_timeout_sec);
    printf("  SSL Handshake: %d sec\n", config->ssl_handshake_timeout_sec);
    printf("  Request: %d sec\n", config->request_timeout_sec);
    printf("  Keep-Alive: %d sec\n", config->keepalive_timeout_sec);
    
    printf("\nRequest Limits:\n");
    printf("  Max Request Size: %zu bytes\n", config->max_request_size);
    printf("  Max Header Size: %zu bytes\n", config->max_header_size);
    printf("  Max Headers: %d\n", config->max_header_count);
    printf("  Max URI Length: %zu\n", config->max_uri_length);
    
    printf("\nSSL/TLS:\n");
    printf("  Cert Path: %s\n", config->ssl_cert_path);
    printf("  Key Path: %s\n", config->ssl_key_path);
    
    printf("\nDatabase:\n");
    printf("  DB Path: %s\n", config->db_path);
    
    printf("\nLogging:\n");
    printf("  Log File: %s\n", config->log_file_path);
    printf("  Log Level: %d\n", config->log_level);
    printf("  Console: %s\n", config->log_to_console ? "yes" : "no");
    printf("  File: %s\n", config->log_to_file ? "yes" : "no");
    
    printf("\nJWT:\n");
    printf("  Secret: %s\n", config->jwt_secret ? "[SET]" : "[NOT SET]");
    printf("  Expiry: %d sec\n", config->jwt_expiry_seconds);
    
    printf("==========================================\n\n");
}

/**
 * config_cleanup - Free allocated memory
 */
void config_cleanup(ServerConfig *config) {
    free(config->bind_address);
    free(config->ssl_cert_path);
    free(config->ssl_key_path);
    free(config->db_path);
    free(config->log_file_path);
    free(config->jwt_secret);
    
    memset(config, 0, sizeof(ServerConfig));
}
