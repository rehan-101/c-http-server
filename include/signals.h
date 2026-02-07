#ifndef SIGNALS_H
#define SIGNALS_H

#include <signal.h>
#include <stdio.h>

/**
 * Signal Handling for Graceful Shutdown
 * 
 * Why we need this:
 * - Server receives SIGTERM/SIGINT (Ctrl+C)
 * - Without handler: Immediate exit, connections dropped
 * - With handler: Clean shutdown
 *   - Stop accepting new connections
 *   - Finish processing current requests
 *   - Close all connections cleanly
 *   - Flush logs
 *   - Close database
 *   - Free memory
 * 
 * Signals we handle:
 * - SIGTERM: Terminate signal (systemd, kill)
 * - SIGINT: Interrupt signal (Ctrl+C)
 * - SIGHUP: Hang up (optional: reload config)
 * - SIGPIPE: Ignore (broken pipe on write)
 */

/* Global shutdown flag
 * Set to 1 when shutdown requested
 * Main event loop checks this */
extern volatile sig_atomic_t g_shutdown_requested;

/* Global reload flag
 * Set to 1 when config reload requested (SIGHUP) */
extern volatile sig_atomic_t g_reload_requested;

/**
 * Install signal handlers
 * 
 * Call this early in main()
 * Must be called before creating any threads
 * 
 * Returns: 0 on success, -1 on error
 */
int signals_init();

/**
 * Signal handler function
 * Sets appropriate flags for main loop to handle
 */
void signal_handler(int signum);

/**
 * Check if shutdown was requested
 * Main loop should check this regularly
 */
static inline int should_shutdown() {
    return g_shutdown_requested;
}

/**
 * Check if config reload was requested
 */
static inline int should_reload() {
    return g_reload_requested;
}

/**
 * Clear reload flag
 * Call after reloading config
 */
static inline void clear_reload_flag() {
    g_reload_requested = 0;
}

/**
 * Block signals in worker threads
 * Only main thread should handle signals
 * 
 * Call this at the start of each thread function
 */
int signals_block_in_thread();

#endif