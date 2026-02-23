#include "../include/rate_limiter.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include "../include/logger.h"

// Simple hash table implementation for rate limiting
#define RATE_LIMIT_TABLE_SIZE 10007  // Prime number for better distribution

typedef struct RateLimitNode {
    RateLimitEntry entry;
    struct RateLimitNode *next;
} RateLimitNode;

static RateLimitNode **rate_limit_table = NULL;
static pthread_mutex_t rate_limit_mutex = PTHREAD_MUTEX_INITIALIZER;
static int initialized = 0;

static uint32_t hash_user_id(uint32_t user_id)
{
    return user_id % RATE_LIMIT_TABLE_SIZE;
}

int rate_limiter_init(void)
{
    if (initialized) return 0;
    
    rate_limit_table = (RateLimitNode **)calloc(RATE_LIMIT_TABLE_SIZE, sizeof(RateLimitNode *));
    if (!rate_limit_table) {
        LOG_ERROR("Failed to allocate rate limit table");
        return -1;
    }
    
    initialized = 1;
    return 0;
}

int rate_limit_check(uint32_t user_id)
{
    if (!initialized) {
        LOG_WARN("Rate limiter not initialized");
        return 1;  // Allow by default if not initialized
    }
    
    time_t now = time(NULL);
    int allowed = 1;
    
    pthread_mutex_lock(&rate_limit_mutex);
    {
        uint32_t hash = hash_user_id(user_id);
        RateLimitNode *node = rate_limit_table[hash];
        
        // Search for existing entry
        while (node) {
            if (node->entry.user_id == user_id) {
                break;
            }
            node = node->next;
        }
        
        if (!node) {
            // Create new entry
            node = (RateLimitNode *)malloc(sizeof(RateLimitNode));
            if (!node) {
                LOG_ERROR("Failed to allocate rate limit entry");
                allowed = 1;  // Allow on allocation failure
            } else {
                node->entry.user_id = user_id;
                node->entry.message_count = 1;
                node->entry.window_start = now;
                node->next = rate_limit_table[hash];
                rate_limit_table[hash] = node;
            }
        } else if (now - node->entry.window_start > RATE_LIMIT_WINDOW_SEC) {
            // Window expired, reset
            node->entry.message_count = 1;
            node->entry.window_start = now;
        } else {
            // Same window, increment counter
            node->entry.message_count++;
            if (node->entry.message_count > RATE_LIMIT_MESSAGES_PER_MIN) {
                allowed = 0;
                LOG_WARN("Rate limit exceeded for user_id=%u (count=%u)", 
                        user_id, node->entry.message_count);
            }
        }
    }
    pthread_mutex_unlock(&rate_limit_mutex);
    
    return allowed;
}

int rate_limit_remaining(uint32_t user_id)
{
    if (!initialized) {
        return RATE_LIMIT_MESSAGES_PER_MIN;
    }
    
    time_t now = time(NULL);
    int remaining = RATE_LIMIT_MESSAGES_PER_MIN;
    
    pthread_mutex_lock(&rate_limit_mutex);
    {
        uint32_t hash = hash_user_id(user_id);
        RateLimitNode *node = rate_limit_table[hash];
        
        while (node) {
            if (node->entry.user_id == user_id) {
                if (now - node->entry.window_start > RATE_LIMIT_WINDOW_SEC) {
                    remaining = RATE_LIMIT_MESSAGES_PER_MIN;
                } else {
                    remaining = RATE_LIMIT_MESSAGES_PER_MIN - node->entry.message_count;
                    if (remaining < 0) remaining = 0;
                }
                break;
            }
            node = node->next;
        }
    }
    pthread_mutex_unlock(&rate_limit_mutex);
    
    return remaining;
}

void rate_limiter_cleanup(void)
{
    if (!initialized) return;
    
    pthread_mutex_lock(&rate_limit_mutex);
    {
        if (rate_limit_table) {
            for (int i = 0; i < RATE_LIMIT_TABLE_SIZE; i++) {
                RateLimitNode *node = rate_limit_table[i];
                while (node) {
                    RateLimitNode *next = node->next;
                    free(node);
                    node = next;
                }
            }
            free(rate_limit_table);
            rate_limit_table = NULL;
        }
        initialized = 0;
    }
    pthread_mutex_unlock(&rate_limit_mutex);
}
