#ifndef TIMEOUT_H
#define TIMEOUT_H

#include <time.h>
#include <stdint.h>

/**
 * Timeout Tracking System
 *
 * Why timeouts are CRITICAL:
 * - Slow clients can exhaust server resources
 * - DoS attack: open connection, never send data
 * - Memory leak: connections stay open forever
 *
 * We track multiple timeout types:
 * - Connection idle timeout
 * - SSL handshake timeout
 * - Request read timeout
 * - Keep-alive timeout
 *
 * How it works:
 * - Each client has timestamps for different phases
 * - Periodically check if any timeout expired
 * - Close timed-out connections
 */

/**
 * Timeout tracking for a connection
 * Embed this in your epoll_client_t structure
 */
typedef struct
{
    time_t connection_start;    // When connection was accepted
    time_t last_activity;       // Last time we received data
    time_t ssl_handshake_start; // When SSL handshake started
    time_t request_start;       // When request reading started

    /* Timeout flags */
    uint8_t in_ssl_handshake : 1;  // Currently doing SSL handshake
    uint8_t in_request_read : 1;   // Currently reading request
    uint8_t keepalive_enabled : 1; // Keep-alive connection
} TimeoutTracker;

/**
 * Initialize timeout tracker
 * Call when new connection is accepted
 */
static inline void timeout_tracker_init(TimeoutTracker *tracker)
{
    time_t now = time(NULL);
    tracker->connection_start = now;
    tracker->last_activity = now;
    tracker->ssl_handshake_start = now;
    tracker->request_start = 0;
    tracker->in_ssl_handshake = 1;
    tracker->in_request_read = 0;
    tracker->keepalive_enabled = 0;
}

/**
 * Update activity timestamp
 * Call whenever data is received
 */
static inline void timeout_tracker_activity(TimeoutTracker *tracker)
{
    tracker->last_activity = time(NULL);
}

/**
 * Mark SSL handshake complete
 */
static inline void timeout_tracker_ssl_complete(TimeoutTracker *tracker)
{
    tracker->in_ssl_handshake = 0;
    tracker->request_start = time(NULL);
    tracker->in_request_read = 1;
}

/**
 * Mark request reading complete
 */
static inline void timeout_tracker_request_complete(TimeoutTracker *tracker)
{
    tracker->in_request_read = 0;
}

/**
 * Enable keep-alive
 */
static inline void timeout_tracker_enable_keepalive(TimeoutTracker *tracker)
{
    tracker->keepalive_enabled = 1;
    tracker->last_activity = time(NULL);
}

/**
 * Check if connection has timed out
 *
 *  Timeout tracker
 *  SSL handshake timeout in seconds
 *  Request read timeout in seconds
 *  General idle timeout in seconds
 *  Keep-alive timeout in seconds
 *
 * Returns: 1 if timed out, 0 if still valid
 */
static inline int timeout_tracker_is_expired(const TimeoutTracker *tracker,
                                             int ssl_handshake_timeout,
                                             int request_timeout,
                                             int idle_timeout,
                                             int keepalive_timeout)
{
    time_t now = time(NULL);

    /* Check SSL handshake timeout */
    if (tracker->in_ssl_handshake)
    {
        if (now - tracker->ssl_handshake_start > ssl_handshake_timeout)
        {
            return 1; // SSL handshake took too long
        }
    }

    /* Check request read timeout */
    if (tracker->in_request_read && tracker->request_start > 0)
    {
        if (now - tracker->request_start > request_timeout)
        {
            return 1; // Reading request took too long
        }
    }

    /* Check idle timeout */
    if (tracker->keepalive_enabled)
    {
        if (now - tracker->last_activity > keepalive_timeout)
        {
            return 1; // Keep-alive connection idle too long
        }
    }
    else
    {
        if (now - tracker->last_activity > idle_timeout)
        {
            return 1; // Connection idle too long
        }
    }

    return 0; // Still valid
}

/**
 * Get human-readable timeout reason
 */
static inline const char *timeout_tracker_reason(const TimeoutTracker *tracker,
                                                 int ssl_handshake_timeout,
                                                 int request_timeout,
                                                 int idle_timeout,
                                                 int keepalive_timeout)
{
    time_t now = time(NULL);

    if (tracker->in_ssl_handshake)
    {
        if (now - tracker->ssl_handshake_start > ssl_handshake_timeout)
        {
            return "SSL handshake timeout";
        }
    }

    if (tracker->in_request_read && tracker->request_start > 0)
    {
        if (now - tracker->request_start > request_timeout)
        {
            return "Request read timeout";
        }
    }

    if (tracker->keepalive_enabled)
    {
        if (now - tracker->last_activity > keepalive_timeout)
        {
            return "Keep-alive timeout";
        }
    }
    else
    {
        if (now - tracker->last_activity > idle_timeout)
        {
            return "Idle timeout";
        }
    }

    return "Unknown timeout";
}

#endif