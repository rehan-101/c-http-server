#include "conn_limits.h"
#include "logger.h"
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>

/**
 * Hash function for IP addresses
 * Simple but effective for distributing IPs across buckets
 */
static inline unsigned int ip_hash(uint32_t ip)
{
    return ip % MAX_IP_BUCKETS;
}

/**
 * conn_limits_init - Create and initialize tracker
 */
ConnLimitsTracker *conn_limits_init(int max_total, int max_per_ip)
{
    ConnLimitsTracker *tracker = calloc(1, sizeof(ConnLimitsTracker));
    if (!tracker)
    {
        LOG_ERROR("Failed to allocate connection limits tracker");
        return NULL;
    }

    tracker->max_total_connections = max_total;
    tracker->max_connections_per_ip = max_per_ip;
    tracker->current_total = 0;

    /* Initialize hash table */
    memset(tracker->ip_buckets, 0, sizeof(tracker->ip_buckets));

    /* Initialize mutex */
    pthread_mutex_init(&tracker->lock, NULL);

    LOG_INFO("Connection limits initialized (max_total=%d, max_per_ip=%d)",
             max_total, max_per_ip);

    return tracker;
}

/**
 * conn_limits_destroy - Clean up tracker
 */
void conn_limits_destroy(ConnLimitsTracker *tracker)
{
    if (!tracker)
        return;

    pthread_mutex_lock(&tracker->lock);

    /* Free all hash table entries */
    for (int i = 0; i < MAX_IP_BUCKETS; i++)
    {
        IpConnEntry *entry = tracker->ip_buckets[i];
        while (entry)
        {
            IpConnEntry *next = entry->next;
            free(entry);
            entry = next;
        }
    }

    pthread_mutex_unlock(&tracker->lock);
    pthread_mutex_destroy(&tracker->lock);

    free(tracker);

    LOG_INFO("Connection limits tracker destroyed");
}

/**
 * Find or create IP entry in hash table
 * Must be called with lock held!
 */
static IpConnEntry *find_or_create_ip_entry(ConnLimitsTracker *tracker,
                                            uint32_t ip,
                                            int create)
{
    unsigned int bucket = ip_hash(ip);
    IpConnEntry *entry = tracker->ip_buckets[bucket];

    /* Search for existing entry */
    while (entry)
    {
        if (entry->ip_addr == ip)
        {
            return entry;
        }
        entry = entry->next;
    }

    /* Not found - create if requested */
    if (create)
    {
        entry = calloc(1, sizeof(IpConnEntry));
        if (!entry)
        {
            LOG_ERROR("Failed to allocate IP entry");
            return NULL;
        }

        entry->ip_addr = ip;
        entry->connection_count = 0;

        /* Insert at head of bucket */
        entry->next = tracker->ip_buckets[bucket];
        tracker->ip_buckets[bucket] = entry;
    }

    return entry;
}

/**
 * conn_limits_can_accept - Check if new connection is allowed
 *
 * This is the CRITICAL function for DoS prevention!
 */
int conn_limits_can_accept(ConnLimitsTracker *tracker, uint32_t client_ip)
{
    if (!tracker)
        return 0;

    pthread_mutex_lock(&tracker->lock);

    /* Check total connection limit */
    if (tracker->current_total >= tracker->max_total_connections)
    {
        pthread_mutex_unlock(&tracker->lock);

        /* Log this - it's important! */
        struct in_addr addr;
        addr.s_addr = client_ip;
        LOG_WARN("Rejecting connection from %s: total limit reached (%d/%d)",
                 inet_ntoa(addr),
                 tracker->current_total,
                 tracker->max_total_connections);

        return -1; // Too many total connections
    }

    /* Check per-IP limit */
    IpConnEntry *entry = find_or_create_ip_entry(tracker, client_ip, 0);
    if (entry && entry->connection_count >= tracker->max_connections_per_ip)
    {
        pthread_mutex_unlock(&tracker->lock);

        struct in_addr addr;
        addr.s_addr = client_ip;
        LOG_WARN("Rejecting connection from %s: IP limit reached (%d/%d)",
                 inet_ntoa(addr),
                 entry->connection_count,
                 tracker->max_connections_per_ip);

        return -2; // Too many connections from this IP
    }

    pthread_mutex_unlock(&tracker->lock);
    return 0; // Connection allowed
}

/**
 * conn_limits_add - Register new connection
 */
int conn_limits_add(ConnLimitsTracker *tracker, uint32_t client_ip)
{
    if (!tracker)
        return -1;

    pthread_mutex_lock(&tracker->lock);

    /* Increment total */
    tracker->current_total++;

    /* Increment per-IP count */
    IpConnEntry *entry = find_or_create_ip_entry(tracker, client_ip, 1);
    if (entry)
    {
        entry->connection_count++;
    }

    /* Log at INFO level occasionally */
    if (tracker->current_total % 100 == 0)
    {
        LOG_INFO("Active connections: %d/%d",
                 tracker->current_total,
                 tracker->max_total_connections);
    }

    pthread_mutex_unlock(&tracker->lock);
    return 0;
}

/**
 * conn_limits_remove - Unregister connection
 */
void conn_limits_remove(ConnLimitsTracker *tracker, uint32_t client_ip)
{
    if (!tracker)
        return;

    pthread_mutex_lock(&tracker->lock);

    /* Decrement total */
    if (tracker->current_total > 0)
    {
        tracker->current_total--;
    }

    /* Decrement per-IP count */
    IpConnEntry *entry = find_or_create_ip_entry(tracker, client_ip, 0);
    if (entry && entry->connection_count > 0)
    {
        entry->connection_count--;

        /* If count reaches 0, we could remove the entry to save memory
         * But we keep it for simplicity - it will be reused */
    }

    pthread_mutex_unlock(&tracker->lock);
}

/**
 * conn_limits_get_counts - Get current connection counts
 */
void conn_limits_get_counts(ConnLimitsTracker *tracker,
                            int *total,
                            int *ip_count,
                            uint32_t client_ip)
{
    if (!tracker)
    {
        if (total)
            *total = 0;
        if (ip_count)
            *ip_count = 0;
        return;
    }

    pthread_mutex_lock(&tracker->lock);

    if (total)
    {
        *total = tracker->current_total;
    }

    if (ip_count)
    {
        IpConnEntry *entry = find_or_create_ip_entry(tracker, client_ip, 0);
        *ip_count = entry ? entry->connection_count : 0;
    }

    pthread_mutex_unlock(&tracker->lock);
}

/**
 * conn_limits_print_stats - Debugging information
 */
void conn_limits_print_stats(ConnLimitsTracker *tracker)
{
    if (!tracker)
        return;

    pthread_mutex_lock(&tracker->lock);

    LOG_INFO("=== Connection Limits Stats ===");
    LOG_INFO("Total connections: %d/%d",
             tracker->current_total,
             tracker->max_total_connections);

    /* Count unique IPs */
    int unique_ips = 0;
    for (int i = 0; i < MAX_IP_BUCKETS; i++)
    {
        IpConnEntry *entry = tracker->ip_buckets[i];
        while (entry)
        {
            if (entry->connection_count > 0)
            {
                unique_ips++;

                /* Log top connections */
                if (entry->connection_count > 10)
                {
                    struct in_addr addr;
                    addr.s_addr = entry->ip_addr;
                    LOG_INFO("  IP %s: %d connections",
                             inet_ntoa(addr),
                             entry->connection_count);
                }
            }
            entry = entry->next;
        }
    }

    LOG_INFO("Unique IP addresses: %d", unique_ips);
    LOG_INFO("==============================");

    pthread_mutex_unlock(&tracker->lock);
}