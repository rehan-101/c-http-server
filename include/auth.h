#ifndef AUTH_H
#define AUTH_H

#include <jwt.h>
#include "server.h"

// Authentication context (attached to each request)
typedef struct {
    int user_id;        // From JWT 'sub' claim
    char username[32];  // From database lookup (cached)
    char role[16];      // From JWT 'role' claim
    int authenticated;  // 1 if token valid, 0 otherwise
} auth_context_t;

/**
 * Validate JWT token from Authorization header
 * 
 * @param headers - Full HTTP headers string
 * @param ctx - Output: populated auth context
 * @return 0 on success, -1 on failure (invalid/expired/missing token)
 */
int auth_validate_token(const char *headers, auth_context_t *ctx);

/**
 * Validate JWT token from WebSocket Sec-WebSocket-Protocol header
 * 
 * @param headers - WebSocket upgrade headers
 * @param ctx - Output: populated auth context
 * @return 0 on success, -1 on failure
 */
int auth_validate_websocket_token(const char *headers, auth_context_t *ctx);

/**
 * Get username from user ID (database lookup with caching)
 * 
 * @param user_id - User ID from JWT
 * @param username_out - Buffer to store username (min 32 bytes)
 * @return 0 on success, -1 if user not found
 */
int auth_get_username_from_id(int user_id, char *username_out);

/**
 * Helper: Extract token from Authorization header
 * Reuses existing get_token() but makes it part of auth module
 */
char *auth_extract_token(const char *headers);

/**
 * Check if endpoint requires authentication
 * Returns 1 if protected, 0 if public
 */
int auth_endpoint_requires_auth(const char *uri, Methods method);

#endif
