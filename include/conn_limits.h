#ifndef CONN_LIMITS_H
#define CONN_LIMITS_H

#include <stdint.h>
#include <netinet/in.h>
#include <pthread.h>

/**
 * Connection Limits Tracker
 * 
 * Why we need this (DoS Prevention):
 * - Attacker opens many connections → server runs out of resources
 * - Single IP opens 1000s of connections → monopolizes server
 * - Need to enforce fair usage limits
 * 
 * Features:
 * - Track total active connections
 * - Track connections per IP address
 * - Reject new connections when limits exceeded
 * - Thread-safe
 */

#define MAX_IP_BUCKETS 1024  // Hash table size for IP tracking

/**
 * Per-IP connection tracking entry
 */
typedef struct ip_conn_entry {
    uint32_t ip_addr;            // IP address (network byte order)
    int connection_count;        // Number of active connections
    struct ip_conn_entry *next;  // Hash table collision chain
} IpConnEntry;

/**
 * Connection limits tracker
 */
typedef struct {
    /* Global limits */
    int max_total_connections;
    int max_connections_per_ip;
    
    /* Current state */
    int current_total;
    
    /* Per-IP tracking (hash table) */
    IpConnEntry *ip_buckets[MAX_IP_BUCKETS];
    
    /* Thread safety */
    pthread_mutex_t lock;
    
} ConnLimitsTracker;

/**
 * Initialize connection limits tracker
 * 
 *  Maximum total connections
 *  Maximum connections per IP
 * 
 * Returns: Pointer to tracker, or NULL on error
 */
ConnLimitsTracker* conn_limits_init(int max_total, int max_per_ip);

/**
 * Destroy connection limits tracker
 */
void conn_limits_destroy(ConnLimitsTracker *tracker);

/**
 * Check if new connection is allowed
 * 
 *  Tracker instance
 *  Client IP address (network byte order)
 * 
 * Returns:
 *   0 = Connection allowed
 *  -1 = Too many total connections
 *  -2 = Too many connections from this IP
 */
int conn_limits_can_accept(ConnLimitsTracker *tracker, uint32_t client_ip);

/**
 * Register new connection
 * Call after accepting connection
 * 
 *  Tracker instance
 *  Client IP address
 * 
 * Returns: 0 on success, -1 on error
 */
int conn_limits_add(ConnLimitsTracker *tracker, uint32_t client_ip);

/**
 * Unregister connection
 * Call when connection closes
 * 
 *  Tracker instance
 *  Client IP address
 */
void conn_limits_remove(ConnLimitsTracker *tracker, uint32_t client_ip);

/**
 * Get current connection counts
 * 
 *  Tracker instance
 *  Output for total connections
 *  Output for connections from specific IP
 *  IP address to check
 */
void conn_limits_get_counts(ConnLimitsTracker *tracker,
                            int *total,
                            int *ip_count,
                            uint32_t client_ip);

/**
 * Print statistics (for debugging)
 */
void conn_limits_print_stats(ConnLimitsTracker *tracker);

#endif