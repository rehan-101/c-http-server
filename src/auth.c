#include "../include/auth.h"
#include "../include/database.h"
#include "../include/logger.h"
#include <string.h>
#include <time.h>
#include <stdlib.h>

// Internal helper: Decode and validate JWT
static jwt_t *decode_and_validate(const char *token) {
    if (!token) return NULL;
    
    char *secret = getenv("SECRET_KEY");
    if (!secret) {
        LOG_ERROR("[AUTH] ERROR: SECRET_KEY not set");
        return NULL;
    }
    
    size_t sec_len = strlen(secret);
    jwt_t *jwt = NULL;
    
    // Decode JWT
    if (jwt_decode(&jwt, token, (const unsigned char *)secret, (int)sec_len) != 0) {
        LOG_WARN("[AUTH] JWT decode failed: invalid signature or format");
        return NULL;
    }
    
    // Check expiration
    time_t exp = jwt_get_grant_int(jwt, "exp");
    if (exp < time(NULL)) {
        LOG_WARN("[AUTH] JWT expired (exp: %ld, now: %ld)", exp, time(NULL));
        jwt_free(jwt);
        return NULL;
    }
    
    return jwt;
}

int auth_validate_token(const char *headers, auth_context_t *ctx) {
    memset(ctx, 0, sizeof(auth_context_t));
    
    // Extract token from "Authorization: Bearer <token>"
    char *token = auth_extract_token(headers);
    if (!token) {
        LOG_WARN("[AUTH] No Authorization header found");
        return -1;
    }
    
    // Decode and validate
    jwt_t *jwt = decode_and_validate(token);
    free(token);
    
    if (!jwt) {
        return -1;
    }
    
    // Extract claims
    ctx->user_id = jwt_get_grant_int(jwt, "sub");
    const char *role = jwt_get_grant(jwt, "role");
    if (role) {
        strncpy(ctx->role, role, sizeof(ctx->role) - 1);
    }
    
    // Lookup username from database
    if (auth_get_username_from_id(ctx->user_id, ctx->username) != 0) {
        LOG_ERROR("[AUTH] User ID %d not found in database", ctx->user_id);
        jwt_free(jwt);
        return -1;
    }
    
    ctx->authenticated = 1;
    jwt_free(jwt);
    
    LOG_INFO("[AUTH] User authenticated: %s (ID: %d)", ctx->username, ctx->user_id);
    return 0;
}

int auth_validate_websocket_token(const char *headers, auth_context_t *ctx) {
    memset(ctx, 0, sizeof(auth_context_t));
    
    // Extract token from Sec-WebSocket-Protocol: Bearer.<token>
    const char *proto_header = strstr(headers, "Sec-WebSocket-Protocol:");
    if (!proto_header) {
        LOG_WARN("[AUTH] WS: No Sec-WebSocket-Protocol header");
        return -1;
    }
    
    // Format: "Sec-WebSocket-Protocol: Bearer.<JWT_TOKEN>"
    const char *bearer_start = strstr(proto_header, "Bearer.");
    if (!bearer_start) {
        LOG_WARN("[AUTH] WS: Bearer. not found in protocol header");
        return -1;
    }
    
    bearer_start += strlen("Bearer.");
    char *line_end = strstr(bearer_start, "\r\n");
    if (!line_end) {
        line_end = strstr(bearer_start, "\n");
    }
    
    size_t token_len = line_end ? (size_t)(line_end - bearer_start) : strlen(bearer_start);
    char *token = strndup(bearer_start, token_len);
    
    // Trim whitespace
    while (token_len > 0 && (token[token_len-1] == ' ' || token[token_len-1] == '\t')) {
        token[--token_len] = '\0';
    }
    
    // Decode and validate
    jwt_t *jwt = decode_and_validate(token);
    free(token);
    
    if (!jwt) {
        return -1;
    }
    
    // Extract claims
    ctx->user_id = jwt_get_grant_int(jwt, "sub");
    const char *role = jwt_get_grant(jwt, "role");
    if (role) {
        strncpy(ctx->role, role, sizeof(ctx->role) - 1);
    }
    
    // Lookup username
    if (auth_get_username_from_id(ctx->user_id, ctx->username) != 0) {
        LOG_ERROR("[AUTH] WS: User ID %d not found in database", ctx->user_id);
        jwt_free(jwt);
        return -1;
    }
    
    ctx->authenticated = 1;
    jwt_free(jwt);
    
    LOG_INFO("[AUTH] WebSocket authenticated: %s (ID: %d)", ctx->username, ctx->user_id);
    return 0;
}

int auth_get_username_from_id(int user_id, char *username_out) {
    sqlite3_stmt *stmt = NULL;
    const char *query = "SELECT username FROM User WHERE id = ?;";
    
    if (sqlite3_prepare_v2(db, query, -1, &stmt, NULL) != SQLITE_OK) {
        LOG_ERROR("[AUTH] Failed to prepare user lookup query: %s", sqlite3_errmsg(db));
        return -1;
    }
    
    sqlite3_bind_int(stmt, 1, user_id);
    
    int result = -1;
    if (sqlite3_step(stmt) == SQLITE_ROW) {
        const char *username = (const char *)sqlite3_column_text(stmt, 0);
        if (username) {
            strncpy(username_out, username, 31);
            username_out[31] = '\0';
            result = 0;
        }
    } else {
        LOG_WARN("[AUTH] User ID %d not found in database", user_id);
    }
    
    sqlite3_finalize(stmt);
    return result;
}

char *auth_extract_token(const char *headers) {
    const char *auth_header = strstr(headers, "Authorization: Bearer ");
    if (!auth_header) {
        return NULL;
    }
    
    auth_header += strlen("Authorization: Bearer ");
    char *line_end = strstr(auth_header, "\r\n");
    if (!line_end) {
        line_end = strstr(auth_header, "\n");
    }
    
    size_t token_len = line_end ? (size_t)(line_end - auth_header) : strlen(auth_header);
    return strndup(auth_header, token_len);
}

int auth_endpoint_requires_auth(const char *uri, Methods method) {
    // Public endpoints (NO auth required)
    if (strcmp(uri, "/login") == 0) return 0;
    if (strcmp(uri, "/register") == 0) return 0;
    if (strcmp(uri, "/") == 0) return 0;  // Root
    
    // *** IMPORTANT: HTML pages served via GET should be public ***
    // Browser navigation can't send Authorization headers
    // Authentication happens when:
    // 1. WebSocket connects (validated during upgrade)
    // 2. API calls are made (fetch with Authorization header)
    if (method == GET) {
        if (strcmp(uri, "/chat") == 0) return 0;      // Serve chat.html (public)
        if (strcmp(uri, "/profile") == 0) return 0;   // Serve profile.html (public)
        // Note: /login and /register already handled above
    }
    
    // Protected API endpoints (auth required)
    if (strcmp(uri, "/user_info") == 0) return 1;
    if (strcmp(uri, "/users") == 0) return 1;
    if (strncmp(uri, "/users/", 7) == 0) return 1;
    if (strcmp(uri, "/me") == 0) return 1;  // PUT /me requires auth
    
    // Default: require auth for unknown endpoints (secure by default)
    return 1;
}
