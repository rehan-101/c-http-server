#ifndef RATE_LIMITER_H
#define RATE_LIMITER_H

#include <time.h>
#include <stdint.h>
#include <pthread.h>

// Rate limit: 100 messages per 60 seconds per user
#define RATE_LIMIT_MESSAGES_PER_MIN 100
#define RATE_LIMIT_WINDOW_SEC 60

typedef struct {
    uint32_t user_id;
    uint32_t message_count;
    time_t window_start;
} RateLimitEntry;

/**
 * Initialize rate limiter
 * Returns: 0 on success, -1 on failure
 */
int rate_limiter_init(void);

/**
 * Check if user has exceeded rate limit
 * Returns: 1 if allowed, 0 if rate limited
 */
int rate_limit_check(uint32_t user_id);

/**
 * Get remaining messages for user in current window
 * Returns: number of messages user can still send, -1 on error
 */
int rate_limit_remaining(uint32_t user_id);

/**
 * Reset rate limiter (cleanup)
 */
void rate_limiter_cleanup(void);

#endif
