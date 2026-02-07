#include "signals.h"
#include "logger.h"
#include <string.h>
#include <errno.h>
#include <unistd.h>


/**
 * Global flags (volatile sig_atomic_t for signal safety)
 *
 * sig_atomic_t: Guaranteed atomic access (no race conditions)
 * volatile: Compiler won't optimize away checks
 */
volatile sig_atomic_t g_shutdown_requested = 0;
volatile sig_atomic_t g_reload_requested = 0;

/**
 * signal_handler - Handle termination signals
 *
 * Important: Signal handlers must be simple!
 * - No malloc/free (not signal-safe)
 * - No logging that uses malloc
 * - Just set flags and return
 *
 * Main loop will see the flags and handle gracefully
 */
void signal_handler(int signum)
{
    switch (signum)
    {
    case SIGTERM:
    case SIGINT:
        /* Request shutdown */
        g_shutdown_requested = 1;

        /* Can use write() as it's signal-safe */
        const char msg[] = "\n[SIGNAL] Shutdown requested\n";
        write(STDERR_FILENO, msg, sizeof(msg) - 1);
        break;

    case SIGHUP:
        /* Request config reload */
        g_reload_requested = 1;

        const char reload_msg[] = "\n[SIGNAL] Config reload requested\n";
        write(STDERR_FILENO, reload_msg, sizeof(reload_msg) - 1);
        break;

    case SIGPIPE:
        /** Ignore SIGPIPE
         * Happens when writing to closed socket
         * We handle this error case explicitly in code */
        break;

    default:
        break;
    }
}

/**
 * signals_init - Install signal handlers
 *
 * Uses sigaction() instead of signal() for portability
 * and better control
 */
int signals_init()
{
    struct sigaction sa;

    /* Zero out structure */
    memset(&sa, 0, sizeof(sa));

    /* Set handler function */
    sa.sa_handler = signal_handler;

    /* No special flags */
    sa.sa_flags = 0;

    /* Don't block any signals during handler */
    sigemptyset(&sa.sa_mask);

    /* Install handlers */
    if (sigaction(SIGTERM, &sa, NULL) < 0)
    {
        LOG_ERROR("Failed to install SIGTERM handler: %s", strerror(errno));
        return -1;
    }

    if (sigaction(SIGINT, &sa, NULL) < 0)
    {
        LOG_ERROR("Failed to install SIGINT handler: %s", strerror(errno));
        return -1;
    }

    if (sigaction(SIGHUP, &sa, NULL) < 0)
    {
        LOG_ERROR("Failed to install SIGHUP handler: %s", strerror(errno));
        return -1;
    }

    /* Ignore SIGPIPE */
    sa.sa_handler = SIG_IGN;
    if (sigaction(SIGPIPE, &sa, NULL) < 0)
    {
        LOG_ERROR("Failed to ignore SIGPIPE: %s", strerror(errno));
        return -1;
    }

    LOG_INFO("Signal handlers installed (SIGTERM, SIGINT, SIGHUP, SIGPIPE)");
    return 0;
}

/**
 * signals_block_in_thread - Block signals in worker threads
 *
 * Why: Only main thread should handle signals
 * Worker threads should ignore them
 *
 * Call this at the start of each pthread function
 */
int signals_block_in_thread()
{
    sigset_t set;

    /* Block all signals */
    sigfillset(&set);

    if (pthread_sigmask(SIG_BLOCK, &set, NULL) != 0)
    {
        LOG_ERROR("Failed to block signals in thread: %s", strerror(errno));
        return -1;
    }

    return 0;
}