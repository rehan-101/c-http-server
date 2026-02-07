#include "../include/server.h"
#include "../include/json.h"
#include "../include/database.h"
#include "../include/websocket.h"
#include <stdio.h>
#include <jwt.h>
#include <string.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/sendfile.h>
#include <sqlite3.h>
#include <pthread.h>
#include <sys/epoll.h>
#include <errno.h>

Client *clients = NULL;
pthread_mutex_t client_mutex = PTHREAD_MUTEX_INITIALIZER;

/* === Epoll global state === */
static int epoll_fd = -1;
static epoll_client_t *epoll_clients_head = NULL;
static int ws_client_counter = 1;
/* === End Epoll globals === */

Route routes[] = {
    {.method = GET, .enum_for_uri = {ROOT_URI, URI_USER_INFO, URI_USERS, URI_USERS_WITH_ID, URI_FOR_LOGIN, URI_FOR_REGISTRATION, URI_FOR_PROFILE, URI_FOR_CHAT, 0}, .handler = get_func},
    {.method = POST, .enum_for_uri = {URI_USERS, URI_FOR_REGISTRATION, URI_FOR_LOGIN, 0}, .handler = post_func},
    {.method = PUT, .enum_for_uri = {URI_USERS_WITH_ID, URI_USER_INFO, 0}, .handler = put_func},
    {.method = DELETE, .enum_for_uri = {URI_USERS_WITH_ID, 0}, .handler = delete_func},
    {.method = PATCH, .enum_for_uri = {URI_USERS_WITH_ID, 0}, .handler = patch_func},
};
int no_of_routes = sizeof(routes) / sizeof(routes[0]);
const char *headers_request = NULL; // global pointer for collecting the headers of the request

struct Server server_constructor(int domain, int port, int service, int protocol, int backlog, u_long interface)
{
    struct Server server_obj = {
        .domain = domain,
        .port = port,
        .service = service,
        .protocol = protocol,
        .backlog = backlog,
        .interface = interface,
        .address = {
            .sin_addr.s_addr = INADDR_ANY,
            .sin_port = htons(port),
            .sin_family = domain,
        },
    };

    server_obj.socket_fd = socket(domain, service, protocol);
    if (server_obj.socket_fd < 0)
    {
        perror("socket");
        exit(EXIT_FAILURE);
    }

    int opt = 1;
    setsockopt(server_obj.socket_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    if (bind(server_obj.socket_fd, (struct sockaddr *)&server_obj.address, sizeof(server_obj.address)) < 0)
    {
        perror("bind");
        exit(EXIT_FAILURE);
    }
    if (listen(server_obj.socket_fd, server_obj.backlog) < 0)
    {
        perror("Failed to listen for connections...");
        exit(EXIT_FAILURE);
    }

    /*SSL Initialization*/
    init_openssl();
    server_obj.ssl_ctx = create_ssl_context();
    configure_ssl_context(server_obj.ssl_ctx);

    db = start_db();
    return server_obj;
}

/* ============================================================
 *                   EPOLL HELPER FUNCTIONS
 * ============================================================ */

/**
 * set_nonblocking - Make a file descriptor non-blocking
 *
 * This is CRITICAL for epoll. Without non-blocking I/O, a single
 * slow read() would freeze the entire event loop, blocking ALL clients.
 *
 * How it works:
 * 1. Get current file flags with F_GETFL
 * 2. Add O_NONBLOCK flag
 * 3. Set new flags with F_SETFL
 *
 * After this, read/write/accept return immediately even if not ready.
 * If no data: returns -1 with errno = EAGAIN or EWOULDBLOCK
 */

int set_nonblocking(int fd)
{
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags == -1)
    {
        perror("fcntl F_GETFL");
        return -1;
    }
    if (fcntl(fd, F_SETFL, flags | O_NONBLOCK) == -1)
    {
        perror("fcntl F_SETFL O_NONBLOCK");
        return -1;
    }
    return 0;
}

/**
 * create_epoll_client - Allocate and initialize epoll client structure
 *
 * Why we need this:
 * In threading, the thread stack stores all state (local variables, position in code).
 * With epoll, we have ONE function handling ALL clients.
 * This structure replaces the thread stack - stores per-client state.
 *
 * Stores:
 * - Which state the connection is in (SSL handshake? Reading? WebSocket?)
 * - Partial data buffer (for incremental reads)
 * - SSL state (wants read? wants write?)
 */

epoll_client_t *create_epoll_client(socket_t fd, SSL *ssl, uint32_t client_ip)
{
    epoll_client_t *client = calloc(1, sizeof(epoll_client_t));
    if (!client)
    {
        perror("Failed to allocate client structure");
        return NULL;
    }

    client->fd = fd;
    client->ssl = ssl;
    client->state = CONN_STATE_SSL_HANDSHAKE; // all connections start with the handshake
    client->is_websocket = 0;
    client->client_id = 0;
    client->buffer_used = 0;
    client->want_ssl_read = 0;
    client->want_ssl_write = 0;

    /* Store client ip for connection limits */
    client->client_ip = client_ip;

    /* Initialize timeout tracker */
    timeout_tracker_init(&client->timeout);

    LOG_DEBUG("Created client fd=%d from IP=0x%08x with timeout tracking", fd, client_ip);
    client->next = epoll_clients_head;
    epoll_clients_head = client;

    return client;
}

/**
 * find_epoll_client - Find client by file descriptor
 *
 * When epoll_wait() returns "fd 42 is ready", we need to find
 * the client structure to know:
 * - What state is this connection in?
 * - Where's the SSL context?
 * - Where's the buffer?
 *
 * Simple O(n) linear search. Fine for <10K connections.
 * For millions, use hash table.
 */

epoll_client_t *find_epoll_client(socket_t fd)
{
    epoll_client_t *current = epoll_clients_head;
    while (current)
    {
        if (current->fd == fd)
            return current;
        current = current->next;
    }
    return NULL;
}

/**
 * remove_epoll_client - Remove client from list and free resources
 *
 * Unlike threading where thread exit automatically frees stack,
 * we must manually clean up client structures.
 *
 * Steps:
 * 1. Find client in linked list
 * 2. Remove from list
 * 3. Shutdown SSL
 * 4. Remove from epoll
 * 5. Close socket
 * 6. Free memory
 */

void remove_epoll_client(socket_t fd)
{
    epoll_client_t **current = &epoll_clients_head;
    while (*current)
    {
        if ((*current)->fd == fd)
        {
            epoll_client_t *to_free = *current;
            *current = (*current)->next;

            // Remove from connection limits tracker
            if (g_conn_tracker && to_free->client_ip)
            {
                conn_limits_remove(g_conn_tracker, to_free->client_ip);
            }
            // cleanup resouces
            if (to_free->ssl)
            {
                SSL_shutdown(to_free->ssl);
                SSL_free(to_free->ssl);
            }
            if (to_free->fd >= 0)
            {
                epoll_ctl(epoll_fd, EPOLL_CTL_DEL, to_free->fd, NULL);
                close(to_free->fd);
            }
            LOG_INFO("Removed client fd=%d", fd);
            free(to_free);
            return;
        }
        current = &(*current)->next;
    }
}

/**
 * free_epoll_client - Free client directly without list traversal
 */
void free_epoll_client(epoll_client_t *client)
{
    if (!client)
        return;

    if (client->ssl)
    {
        SSL_shutdown(client->ssl);
        SSL_free(client->ssl);
    }
    if (client->fd >= 0)
    {
        epoll_ctl(epoll_fd, EPOLL_CTL_DEL, client->fd, NULL);
        close(client->fd);
    }

    free(client);
}

/* ============================================================
 *                   EPOLL STATE HANDLERS
 * ============================================================ */

/**
 * handle_ssl_handshake - Perform non-blocking SSL handshake
 *
 * SSL handshake is complex with non-blocking I/O because:
 * - Requires multiple round-trips (ClientHello, ServerHello, etc.)
 * - Might need to READ before writing
 * - Might need to WRITE before reading
 *
 * Returns:
 *   0 = In progress (try again later)
 *  -1 = Fatal error (close connection)
 */

static int handle_ssl_handshake(epoll_client_t *client)
{

    // Check SSL handshake timeout
    if (timeout_tracker_is_expired(&client->timeout,
                                   g_config.ssl_handshake_timeout_sec,
                                   g_config.request_timeout_sec,
                                   g_config.connection_timeout_sec,
                                   g_config.keepalive_timeout_sec))
    {
        LOG_WARN("SSL handshake timeout for fd=%d", client->fd);
        return -1;
    }

    int ret = SSL_accept(client->ssl);

    if (ret == 1)
    {
        // Success ! Handshake is completed
        client->state = CONN_STATE_READING_REQUEST;
        client->want_ssl_read = 0;
        client->want_ssl_write = 0;

        // Mark SSL handshake complete
        timeout_tracker_ssl_complete(&client->timeout);
        LOG_INFO("SSL handshake success for fd=%d", client->fd);

        // Make sure you are monitoring for reads
        struct epoll_event ev;
        ev.events = EPOLLIN | EPOLLET;
        ev.data.fd = client->fd;
        epoll_ctl(epoll_fd, EPOLL_CTL_MOD, client->fd, &ev);
        return 0;
    }
    // Not completed yet : check why
    int err = SSL_get_error(client->ssl, ret);
    if (err == SSL_ERROR_WANT_READ)
    {
        // SSL needs more data to read
        client->want_ssl_read = 1;
        client->want_ssl_write = 0;

        // Ensure monitoring for EPOLLIN
        struct epoll_event ev;
        ev.events = EPOLLIN | EPOLLET;
        ev.data.fd = client->fd;
        epoll_ctl(epoll_fd, EPOLL_CTL_MOD, client->fd, &ev);
        return 0;
    }
    else if (err == SSL_ERROR_WANT_WRITE)
    {
        // SSL needs data to write before reading (handshake renegotiation)
        client->want_ssl_read = 0;
        client->want_ssl_write = 1;

        // switch to monitoring EPOLLOUT
        struct epoll_event ev;
        ev.events = EPOLLOUT | EPOLLET;
        ev.data.fd = client->fd;
        epoll_ctl(epoll_fd, EPOLL_CTL_MOD, client->fd, &ev);
        return 0;
    }
    else
    {
        ERR_print_errors_fp(stderr);
        LOG_ERROR("SSL handshake FAILED for fd=%d", client->fd);
        return -1;
    }
}

/**
 * handle_client_read - Read HTTP/WebSocket request
 *
 * Edge-triggered epoll requirement: MUST read ALL available data.
 *
 * Why buffering:
 * Data might arrive in chunks:
 *   Event 1: "GET /use"
 *   Event 2: "rs HTTP/1"
 *   Event 3: ".1\r\n\r\n"
 *
 * We buffer partial data until we have a complete request.
 *
 * Returns:
 *   1 = Complete request received
 *   0 = Incomplete, need more data
 *  -1 = Error or connection closed
 */

static int handle_client_read(epoll_client_t *client)
{
    // Read in loop until EAGAIN
    while (1)
    {
        size_t available = BUFFER_SIZE - client->buffer_used - 1;
        if (available == 0)
        {
            LOG_ERROR("Buffer full for fd=%d", client->fd);
            return -1;
        }
        int bytes = SSL_read(client->ssl, client->buffer + client->buffer_used, available);
        if (bytes > 0)
        {
            // Got data
            client->buffer_used += bytes;
            client->buffer[client->buffer_used] = '\0';

            // Update timeout tracker
            timeout_tracker_activity(&client->timeout);

            LOG_DEBUG("Read %d bytes from fd=%d (total: %zu)\n", bytes, client->fd, client->buffer_used);
            // check for complete HTTP request (ends with \r\n\r\n)
            if (strstr(client->buffer, "\r\n\r\n"))
            {
                LOG_INFO("Complete request received from fd = %d", client->fd);
                timeout_tracker_request_complete(&client->timeout);
                return 1;
            }
            continue; // might have more data
        }
        // bytes <= 0
        int err = SSL_get_error(client->ssl, bytes);
        if (err == SSL_ERROR_WANT_READ)
        {
            // No more data right now - normal with non-blocking
            return 0;
        }
        else if (err == SSL_ERROR_WANT_WRITE)
        {
            client->state = CONN_STATE_SSL_HANDSHAKE;
            // SSL needs to write before reading
            struct epoll_event ev;
            ev.events = EPOLLOUT | EPOLLET;
            ev.data.fd = client->fd;
            epoll_ctl(epoll_fd, EPOLL_CTL_MOD, client->fd, &ev);
            return 0;
        }
        else if (err == SSL_ERROR_ZERO_RETURN)
        {
            // clean shutdown
            LOG_INFO("Client fd=%d closed cleanly", client->fd);
            return -1;
        }
        else
        {
            if (bytes == 0)
                LOG_INFO(" Client fd = %d disconnected\n", client->fd);
            else
                ERR_print_errors_fp(stderr);
            return -1;
        }
    }
}

/**
 * process_http_request - Parse and route HTTP request
 *
 * This is simpler than threading! We just:
 * 1. Check if WebSocket upgrade
 * 2. Parse HTTP request
 * 3. Call existing handlers (UNCHANGED from threading!)
 * 4. Close connection or upgrade to WebSocket
 *
 * The beauty: All your existing get_func, post_func, etc. work as-is!
 */

static void process_http_request(epoll_client_t *client)
{
    // Check for web socket upgrade
    if (strstr(client->buffer, "Upgrade: websocket") != NULL)
    {
        LOG_INFO("Websocket upgrade request on fd = %d\n", client->fd);
        if (ws_handshake(client->fd, client->ssl, client->buffer) < 0)
        {
            LOG_ERROR("Websocket handshake failed\n");
            remove_epoll_client(client->fd);
            return;
        }
        // Upgrade Successful
        client->is_websocket = 1;
        client->client_id = ws_client_counter++;
        client->state = CONN_STATE_WEBSOCKET;
        client->buffer_used = 0;

        LOG_INFO("Client fd=%d upgraded to websocket", client->fd);
        // Send welcome
        char welcome[256];
        snprintf(welcome, sizeof(welcome),
                 "{\"type\":\"system\",\"message\":\"Welcome! You are client #%d\"}",
                 client->client_id);
        ws_send_frame(client->fd, client->ssl, WS_OPCODE_TEXT,
                      welcome, strlen(welcome));
        return;
    }

    // Regular HTTPS request - parse it
    struct httpRequest *request = parse_methods(client->buffer);
    if (!request)
    {
        LOG_ERROR("Failed to parse HTTP request\n");
        remove_epoll_client(client->fd);
        return;
    }
    LOG_INFO(" HTTP %s %s from fd=%d\n",
             request->enum_of_method == GET ? "GET" : request->enum_of_method == POST ? "POST"
                                                  : request->enum_of_method == PUT    ? "PUT"
                                                  : request->enum_of_method == DELETE ? "DELETE"
                                                                                      : "PATCH",
             request->uri, client->fd);

    // Route to handler (SAME LOGIC as threading!)
    int method_found = 0;
    int route_matched = 0;

    for (int i = 0; i < no_of_routes; i++)
    {
        if (routes[i].method == request->enum_of_method)
        {
            method_found = 1;
            int j = 0;
            while (routes[i].enum_for_uri[j] != 0)
            {
                if (routes[i].enum_for_uri[j] == request->enum_for_uri)
                {
                    route_matched = 1;
                    routes[i].handler(client->fd, client->ssl, request);
                    goto done;
                }
                j++;
            }
        }
    }

    if (method_found && !route_matched)
    {
        send_json(client->fd, client->ssl, 404, "Not Found",
                  "{\"error\":\"Wrong endpoint for this method\"}");
    }
    else if (!method_found)
    {
        send_json(client->fd, client->ssl, 405, "Method Not Allowed",
                  "{\"error\":\"Method not supported\"}");
    }

done:
    clean_things(request->uri, request->header_info->body,
                 request->header_info->content_type, request, NULL);

    // HTTP complete - close connection
    remove_epoll_client(client->fd);
}

/**
 * handle_websocket_frame - Process WebSocket frames
 *
 * Threading: while(1) { read_frame(); } - blocks forever
 * Epoll: Read available frames, return to event loop
 *
 * Returns:
 *   0 = Success, keep connection
 *  -1 = Close connection
 */

static int handle_websocket_frame(epoll_client_t *client)
{
    char ws_buffer[BUFFER_SIZE];

    // Read all available frames (edge-triggered requirement)
    while (1)
    {
        int bytes = SSL_read(client->ssl, ws_buffer, sizeof(ws_buffer) - 1);

        if (bytes <= 0)
        {
            int err = SSL_get_error(client->ssl, bytes);
            if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE)
            {
                return 0; // Normal - no more frames
            }

            LOG_INFO("WebSocket client #%d disconnected\n", client->client_id);
            return -1;
        }
        ws_frame_t *frame = ws_parse_frame((uint8_t *)ws_buffer, bytes);
        if (!frame)
        {
            LOG_ERROR("Failed to parse frame from client fd = %d\n", client->client_id);
            continue;
        }
        // Handle frame types
        switch (frame->opcode)
        {
        case WS_OPCODE_TEXT:
            LOG_INFO("WebSocket client #%d: %s\n",
                     client->client_id, frame->payload);

            // Broadcast
            cJSON *msg_obj = cJSON_CreateObject();
            cJSON_AddNumberToObject(msg_obj, "sender_id", client->client_id);
            cJSON_AddStringToObject(msg_obj, "type", "message");
            cJSON_AddStringToObject(msg_obj, "message", frame->payload);
            cJSON_AddNumberToObject(msg_obj, "timestamp", time(NULL));

            char *json_str = cJSON_PrintUnformatted(msg_obj);

            // Broadcast to all WebSocket clients
            epoll_client_t *curr = epoll_clients_head;
            while (curr)
            {
                if (curr->fd != client->fd && curr->is_websocket)
                {
                    ws_send_frame(curr->fd, curr->ssl, WS_OPCODE_TEXT,
                                  json_str, strlen(json_str));
                }
                curr = curr->next;
            }

            free(json_str);
            cJSON_Delete(msg_obj);
            break;

        case WS_OPCODE_PING:
            ws_send_frame(client->fd, client->ssl, WS_OPCODE_PONG,
                          frame->payload, frame->payload_len);
            break;

        case WS_OPCODE_CLOSE:
            LOG_INFO("WebSocket client #%d requested close\n",
                     client->client_id);
            ws_send_frame(client->fd, client->ssl, WS_OPCODE_CLOSE, NULL, 0);
            ws_free_frame(frame);
            return -1;

        default:
            LOG_ERROR("Unknown opcode %d from client #%d\n",
                      frame->opcode, client->client_id);
        }

        ws_free_frame(frame);
    }
    return 0;
}

/* ============================================================
 *                   EPOLL MAIN FUNCTIONS
 * ============================================================ */

/**
 * accept_new_connections - Accept all pending connections
 *
 * Why loop until EAGAIN:
 * With edge-triggered epoll, we get ONE notification when state changes.
 * Multiple clients might have connected. Accept ALL of them!
 */

static void accept_new_connections(socket_t server_fd, SSL_CTX *ssl_ctx)
{
    while (1)
    {
        struct sockaddr_in client_addr;
        socklen_t addrlen = sizeof(client_addr);

        int client_fd = accept(server_fd, (struct sockaddr *)&client_addr, &addrlen);

        if (client_fd < 0)
        {
            if (errno == EAGAIN || errno == EWOULDBLOCK)
            {
                break; // All connections accepted
            }
            LOG_ERRNO(LOG_ERROR, "accept");
            continue;
        }

        // check connection limits
        if (g_conn_tracker && conn_limits_can_accept(g_conn_tracker, client_addr.sin_addr.s_addr) < 0)
        {
            struct in_addr addr = client_addr.sin_addr;
            LOG_WARN("Connection limit exceeded for %s, rejecting",
                     inet_ntoa(addr));
            close(client_fd);
            continue;
        }

        LOG_INFO("New connection: fd=%d from %s:%d\n",
                 client_fd,
                 inet_ntoa(client_addr.sin_addr),
                 ntohs(client_addr.sin_port));

        // Make non-blocking
        if (set_nonblocking(client_fd) < 0)
        {
            close(client_fd);
            continue;
        }

        // Create SSL
        SSL *ssl = SSL_new(ssl_ctx);
        if (!ssl)
        {
            LOG_ERROR("Failed to create SSL structure\n");
            ERR_print_errors_fp(stderr);
            close(client_fd);
            continue;
        }

        SSL_set_fd(ssl, client_fd);

        // Create client structure with ip and timeout initialized
        epoll_client_t *client = create_epoll_client(client_fd, ssl, client_addr.sin_addr.s_addr);
        if (!client)
        {
            SSL_free(ssl);
            close(client_fd);
            continue;
        }
        // Add to connection limits tracker
        if (g_conn_tracker)
        {
            conn_limits_add(g_conn_tracker, client->client_ip);
        }
        // Add to epoll
        struct epoll_event ev;
        ev.events = EPOLLIN | EPOLLET; // Edge-triggered
        ev.data.fd = client_fd;

        if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, client_fd, &ev) < 0)
        {
            LOG_ERRNO(LOG_ERROR, "epoll_ctl: client_fd");
            free_epoll_client(client);
            continue;
        }

        LOG_INFO("Added client fd=%d to epoll\n", client_fd);
    }
}

/**
 * handle_client_event - Process event for existing client
 *
 * This is the STATE MACHINE heart!
 * Based on current state, call appropriate handler.
 */

static void handle_client_event(int fd, uint32_t events)
{
    epoll_client_t *client = find_epoll_client(fd);
    if (!client)
    {
        LOG_ERROR(" Client not found for fd=%d\n", fd);
        epoll_ctl(epoll_fd, EPOLL_CTL_DEL, fd, NULL);
        close(fd);
        return;
    }
    // Handle errors
    if (events & (EPOLLERR | EPOLLHUP))
    {
        LOG_ERROR(" Error/hangup on fd=%d\n", fd);
        remove_epoll_client(fd);
        return;
    }
    // Process based on state
    int result = 0;
    switch (client->state)
    {
    case CONN_STATE_SSL_HANDSHAKE:
        result = handle_ssl_handshake(client);
        if (result < 0)
        {
            remove_epoll_client(fd);
        }
        break;
    case CONN_STATE_READING_REQUEST:
        result = handle_client_read(client);
        if (result < 0)
            remove_epoll_client(fd);
        else if (result > 0)
            // complete request!
            process_http_request(client);
        break;
    case CONN_STATE_WEBSOCKET:
        result = handle_websocket_frame(client);
        if (result < 0)
            remove_epoll_client(fd);
        break;
    case CONN_STATE_CLOSING:
        remove_epoll_client(fd);
        break;
    default:
        LOG_ERROR("Unknown state %d for fd=%d\n",
                  client->state, fd);
        remove_epoll_client(fd);
    }
}

static void check_timeouts(void)
{
    epoll_client_t *current = epoll_clients_head;
    epoll_client_t *next;

    while (current)
    {
        next = current->next;

        if (timeout_tracker_is_expired(&current->timeout,
                                       g_config.ssl_handshake_timeout_sec,
                                       g_config.request_timeout_sec,
                                       g_config.connection_timeout_sec,
                                       g_config.keepalive_timeout_sec))
        {
            const char *reason = timeout_tracker_reason(&current->timeout,
                                                        g_config.ssl_handshake_timeout_sec,
                                                        g_config.request_timeout_sec,
                                                        g_config.connection_timeout_sec,
                                                        g_config.keepalive_timeout_sec);

            LOG_INFO("Connection fd=%d timed out: %s", current->fd, reason);
            remove_epoll_client(current->fd);
        }

        current = next;
    }
}

/**
 * listening_to_client_epoll - Main epoll event loop
 *
 * One loop handles ALL connections. No threads!
 *
 * Flow:
 * 1. Wait for events (epoll_wait blocks here)
 * 2. Loop through ready FDs
 * 3. If server socket: accept new connections
 * 4. If client socket: handle based on state
 * 5. Repeat forever
 */

void listening_to_client_epoll(socket_t server_fd, SSL_CTX *ssl)
{
    LOG_INFO("Entering epoll event loop on server_fd=%d", server_fd);

    // Create epoll instance
    epoll_fd = epoll_create1(EPOLL_CLOEXEC);
    if (epoll_fd < 0)
    {
        LOG_ERRNO(LOG_ERROR, "epoll_create1 failed");
        return;
    }
    LOG_INFO("Created epoll instance: fd=%d\n", epoll_fd);
    // Make server socket non blocking
    if (set_nonblocking(server_fd) < 0)
    {
        LOG_ERRNO(LOG_ERROR, "Failed to set server socket non-blocking\n");
        return;
    }
    LOG_INFO("Server socket set to non-blocking\n");

    // Add server socket to epoll
    struct epoll_event ev;
    ev.events = EPOLLIN;
    ev.data.fd = server_fd;

    if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, server_fd, &ev) < 0)
    {
        LOG_ERRNO(LOG_ERROR, "epoll_ctl add server_fd failed");
        close(epoll_fd);
        return;
    }
    LOG_DEBUG("Added server_fd=%d to epoll", server_fd);
    // Main event loop
    struct epoll_event events[MAX_EPOLL_EVENTS];
    int timeout_counter = 0;
    const int TIMEOUT_CHECK_INTERVAL = 10; // Check timeout every 10 iterations
    while (!should_shutdown())             // Check shutdown flag from signals
    {
        // Wait for events - THIS IS THE ONLY BLOCKING POINT
        int n_events = epoll_wait(epoll_fd, events, MAX_EPOLL_EVENTS, EPOLL_TIMEOUT_MS);

        if (n_events < 0)
        {
            if (errno == EINTR)
            {
                if (should_shutdown())
                {
                    LOG_INFO("Shutting down server...");
                    break;
                }
                else
                    continue;
            }
            LOG_ERRNO(LOG_ERROR, "epoll_wait");
            break;
        }
        if (n_events == 0)
        {
            timeout_counter++;
            if (timeout_counter >= TIMEOUT_CHECK_INTERVAL)
            {
                check_timeouts();
                timeout_counter = 0;
                // Log connection stats periodically
                if (g_conn_tracker)
                {
                    conn_limits_print_stats(g_conn_tracker);
                }
            }
            // Check for config reload
            if (should_reload())
            {
                LOG_INFO("Reloading configuration...");
                config_load_from_file(&g_config, "server.conf");
                config_load_from_env(&g_config);
                clear_reload_flag();
            }
            continue;
        } // Timeout - could do housekeeping here
        LOG_DEBUG("epoll_wait returned %d events", n_events);
        // Process each ready FD
        for (int i = 0; i < n_events; i++)
        {
            int fd = events[i].data.fd;
            uint32_t event_flags = events[i].events;

            if (fd == server_fd)
            {
                // New connections!
                LOG_INFO("Server socket ready - accepting...\n");
                accept_new_connections(server_fd, ssl);
            }
            else
            {
                // Existing client
                LOG_INFO("Client fd=%d ready (events: 0x%x)\n",
                         fd, event_flags);
                handle_client_event(fd, event_flags);
            }
        }
    }
    /* ========== GRACEFUL SHUTDOWN ========== */
    LOG_INFO("Shutting down server gracefully...");

    /* Close all client connections properly */
    epoll_client_t *client = epoll_clients_head;
    int client_count = 0;

    while (client)
    {
        epoll_client_t *next = client->next;
        client_count++;

        LOG_INFO("Closing client fd=%d (state=%d)", client->fd, client->state);

        /* Send WebSocket close frame if it's a WebSocket connection */
        if (client->is_websocket && client->ssl)
        {
            ws_send_frame(client->fd, client->ssl, WS_OPCODE_CLOSE, NULL, 0);
            LOG_DEBUG("Sent WebSocket CLOSE frame to fd=%d", client->fd);
        }

        /* Clean SSL shutdown */
        if (client->ssl)
        {
            SSL_shutdown(client->ssl);
            SSL_free(client->ssl);
        }

        /* Remove from epoll and close socket */
        if (client->fd >= 0)
        {
            epoll_ctl(epoll_fd, EPOLL_CTL_DEL, client->fd, NULL);
            close(client->fd);
        }

        /* Free client structure */
        free(client);
        client = next;
    }
    LOG_INFO("Closed %d client connections", client_count);

    /* Close epoll file descriptor */
    close(epoll_fd);

    LOG_INFO("Server shutdown complete");
}

void *thread_func(void *arg)
{
    socket_wrapper_t *wrapper = (socket_wrapper_t *)arg;
    int new_socket = wrapper->fd;
    SSL *ssl = wrapper->ssl;
    free(wrapper);

    /*SSL Handshake is here*/
    if (SSL_accept(ssl) <= 0)
    {
        ERR_print_errors_fp(stderr);
        SSL_free(ssl);
        close(new_socket);
        return NULL;
    }
    char Buffer[BUFFER_SIZE];
    ssize_t bytesRead = SSL_read(ssl, Buffer, BUFFER_SIZE - 1);
    if (bytesRead <= 0)
    {
        if (bytesRead < 0)
            fprintf(stderr, "error in reading bytes");
        SSL_shutdown(ssl);
SSL_free(ssl);
        close(new_socket);
        return NULL;
    }
    Buffer[bytesRead] = '\0'; // Null terminate the string
    puts(Buffer);
    // === Check for WebSocket upgrade ===
    if (strstr(Buffer, "Upgrade: websocket") != NULL)
    {
        printf("websocket connection detected on socket #%d", new_socket);

        if (ws_handshake(new_socket, ssl, Buffer) < 0)
        {
            fprintf(stderr, "WebSocket handshake failed\n");
            SSL_shutdown(ssl);
            SSL_free(ssl);
            close(new_socket);
            return NULL;
        }
        static int client_id_counter = 1;
        int client_id = client_id_counter++;
        add_client_for_websock(new_socket, client_id, ssl);

        printf("Client %d connected via WebSocket\n", client_id);

        char welcome[256];
        snprintf(welcome, sizeof(welcome),
                 "{\"type\":\"system\",\"message\":\"Welcome! You are client #%d\"}",
                 client_id);
        ws_send_frame(new_socket, ssl, WS_OPCODE_TEXT, welcome, strlen(welcome));
        char ws_buffer[BUFFER_SIZE];
        while (1)
        {
            memset(ws_buffer, 0, sizeof(ws_buffer));
            ssize_t bytes = SSL_read(ssl, ws_buffer, BUFFER_SIZE - 1);

            if (bytes <= 0)
            {
                printf("Client %d disconnected\n", client_id);
                break;
            }

            // Parse WebSocket frame
            ws_frame_t *frame = ws_parse_frame((uint8_t *)ws_buffer, bytes);
            if (!frame)
            {
                fprintf(stderr, "Failed to parse frame from client %d\n", client_id);
                continue;
            }

            // Handle different frame types
            switch (frame->opcode)
            {
            case WS_OPCODE_TEXT:
                printf("Client %d: %s\n", client_id, frame->payload);

                // Create JSON message
                cJSON *msg_obj = cJSON_CreateObject();
                cJSON_AddNumberToObject(msg_obj, "sender_id", client_id);
                cJSON_AddStringToObject(msg_obj, "type", "message");
                cJSON_AddStringToObject(msg_obj, "message", frame->payload);
                cJSON_AddNumberToObject(msg_obj, "timestamp", time(NULL));

                char *json_str = cJSON_PrintUnformatted(msg_obj);
                ws_broadcast_message(json_str, new_socket);

                free(json_str);
                cJSON_Delete(msg_obj);
                break;

            case WS_OPCODE_PING:
                ws_send_frame(new_socket, ssl, WS_OPCODE_PONG, frame->payload, frame->payload_len);
                break;

            case WS_OPCODE_CLOSE:
                printf("Client %d requested close\n", client_id);
                ws_send_frame(new_socket, ssl, WS_OPCODE_CLOSE, NULL, 0);
                ws_free_frame(frame);
                goto ws_cleanup;
            }

            ws_free_frame(frame);
        }

    ws_cleanup:
        remove_client_for_websock(new_socket);
        SSL_shutdown(ssl);
        SSL_free(ssl);
        close(new_socket);
        printf("Client %d handler thread exiting\n", client_id);
        return NULL;
    }
    struct httpRequest *request = NULL;
    request = parse_methods(Buffer);
    if (request != NULL)
    {
        fprintf(stdout, "requested string --> %s\n method = %s , uri = %s\n", Buffer, request->enum_of_method == GET ? "GET" : (request->enum_of_method == POST) ? "POST"
                                                                                                                           : (request->enum_of_method == PUT)    ? "PUT"
                                                                                                                           : (request->enum_of_method == DELETE) ? "DELETE"
                                                                                                                                                                 : "PATCH",
                request->uri);
        int method_found = 0;
        int route_matched = 0;
        for (int i = 0; i < no_of_routes; i++)
        {
            if (routes[i].method == request->enum_of_method)
            {
                method_found = 1;
                int j = 0;
                while (routes[i].enum_for_uri[j] != 0)
                {
                    if (routes[i].enum_for_uri[j] == request->enum_for_uri)
                    {
                        route_matched = 1;
                        routes[i].handler(new_socket, ssl, request);
                        goto done;
                    }
                    j++;
                }
            }
        }
        if (method_found && !route_matched)
        {
            send_json(new_socket, ssl, 404, "Not Found",
                      "{\"error\":\"Wrong endpoint for this method\"}");
        }
        else if (!method_found)
        {
            send_json(new_socket, ssl, 405, "Method Not Allowed",
                      "{\"error\":\"Method not supported\"}");
        }
    done:
        clean_things(request->uri, request->header_info->body, request->header_info->content_type, request, NULL);
    }
    else
        fprintf(stdout, "failed to parse reQuest...");
    SSL_shutdown(ssl);
    SSL_free(ssl);
    close(new_socket);
    return NULL;
}

void listening_to_client(socket_t server_fd)
{
    pthread_t my_thread;
    char Buffer[BUFFER_SIZE];
    while (1)
    {
        memset(Buffer, 0, sizeof(Buffer));
        printf("=== WAITING FOR CONNECTION === \n");
        struct sockaddr_in client_addr;
        socklen_t addrlen = sizeof(client_addr);
        int *new_socket = (int *)malloc(sizeof(int));
        if (!new_socket)
        {
            perror("mem alloc. failed..");
            continue;
        }
        *new_socket = accept(server_fd, (struct sockaddr *)&client_addr, &addrlen);
        if (*new_socket < 0)
        {
            perror("accept");
            free(new_socket);
            continue;
        }
        /*Creating SSL wrapper*/
        SSL *ssl = SSL_new(global_ssl_ctx);
        if (ssl == NULL)
        {
            fprintf(stderr, "Error: Failed to create SSL structure\n");
            ERR_print_errors_fp(stderr);
            close(*new_socket); // Close the plain socket since we can't secure it
            free(new_socket);
            continue; // Skip to the next client
        }
        SSL_set_fd(ssl, *new_socket);

        socket_wrapper_t *wrapper = malloc(sizeof(socket_wrapper_t));
        if (!wrapper)
        {
            perror("malloc failed");
            SSL_free(ssl);
            close(*new_socket);
            continue;
        }
        wrapper->fd = *new_socket;
        wrapper->ssl = ssl;

        if (pthread_create(&my_thread, NULL, thread_func, (void *)wrapper) != 0)
        {
            perror("Thread failure");
            SSL_free(ssl);
            close(*new_socket);
            free(new_socket);
            free(wrapper);
            continue;
        }
        fprintf(stdout, "received connection for socket : %d\n", *new_socket);
        pthread_detach(my_thread);
    }
}
struct httpRequest *parse_methods(char *response)
{
    char *method_string = NULL;
    struct httpRequest *request = (struct httpRequest *)malloc(sizeof(struct httpRequest));
    if (request == NULL)
    {
        LOG_ERRNO(LOG_ERROR, "request may contain invalid format...");
        exit(EXIT_FAILURE);
    }
    char *temp_response = strdup(response);

    if (!temp_response)
    {
        LOG_ERROR("Error in duplicating the response string...\n");
        free(request);
        return NULL;
    }
    char *first_line = strtok(temp_response, "\r\n");
    LOG_INFO("First Line is : %s\n", first_line);
    char *token = NULL;
    token = strtok(first_line, " ");
    if (token != NULL)
    {
        method_string = strdup(token);
    }
    else
    {
        LOG_ERROR("Error in tokenization of the the requested string...\n");
        clean_things(temp_response, request, NULL);
        return NULL;
    }
    token = strtok(NULL, " ");
    if (token != NULL)
        request->uri = strdup(token);
    else
    {
        LOG_ERROR("Error in tokenization\n");
        clean_things(method_string, temp_response, request, NULL);
        return NULL;
    }
    request->enum_for_uri = (strcmp(request->uri, "/") == 0) ? ROOT_URI : (strcmp(request->uri, "/users") == 0)    ? URI_USERS
                                                                      : (strcmp(request->uri, "/me") == 0)         ? URI_USER_INFO
                                                                      : strcmp(request->uri, "/profile") == 0      ? URI_FOR_PROFILE
                                                                      : (strncmp(request->uri, "/users/", 7) == 0) ? ((is_just_id(request->uri + 7)) ? URI_USERS_WITH_ID : URI_UNKNOWN)
                                                                      : (strcmp(request->uri, "/register") == 0)   ? URI_FOR_REGISTRATION
                                                                      : strcmp(request->uri, "/login") == 0        ? URI_FOR_LOGIN
                                                                      : strcmp(request->uri, "/chat") == 0         ? URI_FOR_CHAT
                                                                                                                   : URI_UNKNOWN;
    request->enum_of_method = strcmp(method_string, "GET") == 0 ? GET : (strcmp(method_string, "POST") == 0) ? POST
                                                                    : strcmp(method_string, "PUT") == 0      ? PUT
                                                                    : strcmp(method_string, "DELETE") == 0   ? DELETE
                                                                                                             : PATCH;
    request->header_info = malloc(sizeof(struct info_after_method_line));
    headers_request = get_header(response);
    if (request->header_info)
    {
        request->header_info->body = get_body(response);
        // request->header_info->content_length = get_content_len(response);
        request->header_info->content_type = get_content_type(response);
        if (request->header_info->content_type)
        {
        }
        else
            request->header_info->content_type = strdup(" ");
    }
    return request;
}
void get_func(socket_t fd, SSL *ssl, struct httpRequest *Request)
{
    if (strcmp(Request->uri, "/login") == 0)
        serve_file(fd, ssl, "public/login.html");
    else if (strcmp(Request->uri, "/register") == 0)
        serve_file(fd, ssl, "public/register.html");
    else if (strcmp(Request->uri, "/profile") == 0)
        serve_file(fd, ssl, "public/profile.html");
    else if (strcmp(Request->uri, "/chat") == 0)
        serve_file(fd, ssl, "public/chat.html");
    else
    {
        JSON_RESPONSE *json_body = (JSON_RESPONSE *)handle_get_uri(Request, Request->enum_for_uri);
        if (!json_body)
        {
            JSON_RESPONSE *json_body = (JSON_RESPONSE *)malloc(sizeof(JSON_RESPONSE));
            json_body->json_string = strdup("{\"message\":\"json is not having anything..endpoint entered might be wrong..\"}");
            json_body->Status = INTERNAL_SERVER_ERROR;
        }
        send_response_back(fd, ssl, json_body);
        close(fd);
        clean_things(json_body->json_string, json_body, NULL);
    }
}
void patch_func(socket_t fd, SSL *ssl, struct httpRequest *Request)
{
    JSON_RESPONSE *json_response = NULL;
    json_response = handle_patch_uri(Request->uri, Request->header_info->body);
    if (!json_response)
    {
        json_response = (JSON_RESPONSE *)malloc(sizeof(JSON_RESPONSE));
        json_response->json_string = strdup("\"Message\":\"Nothing received from the server\"");
        json_response->Status = NOT_FOUND;
    }
    send_response_back(fd, ssl, json_response);
    close(fd);
    clean_things(json_response->json_string, json_response, NULL);
}
char *get_content_type(char *buff)
{
    if (!buff)
    {
        LOG_ERROR("Buffer is empty..!\n");
        return NULL;
    }
    char *type = NULL;
    char *content = strstr(buff, "Content-Type:");
    if (content)
    {
        content += strlen("Content-Type:");
        while (*content == ' ')
            content++;
        char *end = strstr(content, "\r\n");
        size_t len = end - content;
        type = malloc(len + 1);
        if (!type)
            return NULL;
        strncpy(type, content, len);
        type[len] = '\0';
    }
    return type; // malloced variable
}

int get_content_len(char *buff)
{
    if (!buff)
    {
        LOG_ERROR("Buffer is empty..!\n");
        return -1;
    }
    char *content = strstr(buff, "Content-Length:");
    if (content)
    {
        content += strlen("Content-Length");
        while (*content == ' ')
            content++;
    }
    return atoi(content);
}

char *get_body(char *buff)
{
    if (!buff)
    {
        LOG_ERROR("Buffer is empty..!\n");
        return NULL;
    }
    char *body = strstr(buff, "\r\n\r\n");
    if (body)
        body += 4;
    return strdup(body);
}

char *get_header(char *buff)
{
    char *str = strdup(buff);
    char *end_of_header = strstr(str, "\r\n\r\n");
    if (end_of_header)
    {
        int header_len = end_of_header - str;
        int total_len = header_len + strlen("\r\n\r\n");
        char *string_to_be_returned = malloc(total_len + 1);
        if (string_to_be_returned)
        {
            memcpy(string_to_be_returned, str, total_len);
            string_to_be_returned[total_len] = '\0';
            return string_to_be_returned;
        }
    }
    return NULL;
}

void post_func(socket_t client_fd, SSL *ssl, struct httpRequest *post_request)
{
    JSON_RESPONSE *json_response = NULL;
    if (strcmp(post_request->header_info->content_type, "application/json") == 0)
    {
        if (strcmp(post_request->uri, "/users") == 0)
        {
            json_response = handle_post_data_via_json(post_request->header_info->body);
        }
        else if (strcmp(post_request->uri, "/register") == 0)
        {
            json_response = handle_post_json_for_register(post_request->header_info->body);
        }
        else if (strcmp(post_request->uri, "/login") == 0)
        {
            json_response = handle_post_json_for_login(post_request->header_info->body);
        }
        else
        {
            json_response->json_string = strdup("{\"error\" : \"This endpoint is not defined yet\"}");
            json_response->Status = BAD_REQUEST;
        }
    }
    else if (strcmp(post_request->header_info->content_type, "application/x-www-form-urlencoded") == 0)
    {
        json_response = handle_post_data_via_html_form(post_request->header_info->body); // name=Rehan&age=21&email=dewanrehan%40gmail.com -> name=Rehan&age=21&email=dewanrehan06@gmail.com
    }
    else
    {
        json_response = (JSON_RESPONSE *)malloc(sizeof(JSON_RESPONSE));
        json_response->json_string = strdup("{\"message\":\"SOmething wrong has happened\"}");
        json_response->Status = INTERNAL_SERVER_ERROR;
    }
    // Format HTTP response (just like get_func does)
    send_response_back(client_fd, ssl, json_response);
    close(client_fd);                                              // Close the connection
    clean_things(json_response->json_string, json_response, NULL); // Free the allocated JSON string
}
void put_func(socket_t fd, SSL *ssl, struct httpRequest *Request)
{
    JSON_RESPONSE *json = NULL;
    if (strncmp(Request->uri, "/me", 3) == 0)
    {
        // if (is_just_id(Request->uri + 7))
        // {
        //     json = handle_put_with_id(atoi(Request->uri + 7), Request->header_info->body);
        // }
        json = handle_update_current_user((const char *)Request->header_info->body);
    }
    if (!json)
    {
        json = (JSON_RESPONSE *)malloc(sizeof(JSON_RESPONSE));
        if (json)
        {
            json->json_string = strdup("\"message\" : \"invalid uri or endpoint being passed\"");
            json->Status = BAD_REQUEST;
        }
    }
    send_response_back(fd, ssl, json);
    close(fd);
    clean_things(json->json_string, json, NULL);
}

void delete_func(socket_t fd, SSL *ssl, struct httpRequest *Request)
{
    JSON_RESPONSE *json_response = NULL;
    if (strncmp(Request->uri, "/users/", 7) == 0 && is_just_id(Request->uri + 7))
    {
        json_response = handle_delete_with_id(atoi(Request->uri + 7));
    }
    if (!json_response)
    {
        json_response = (JSON_RESPONSE *)malloc(sizeof(JSON_RESPONSE));
        if (json_response)
        {
            json_response->json_string = strdup("\"Message\" : \"This endpoint is not defined yet\"");
            json_response->Status = BAD_REQUEST;
        }
        else
        {
            LOG_ERROR("Allocation error in delete_func()");
            return;
        }
    }
    send_response_back(fd, ssl, json_response);
    close(fd);
    clean_things(json_response->json_string, json_response, NULL);
}

int is_just_id(const char *data)
{
    const char *ptr = data;
    while (*ptr != '\0')
    {
        if (*ptr < '0' || *ptr > '9')
            return 0;
        ptr++;
    }
    return 1;
}
JSON_RESPONSE *handle_get_uri(struct httpRequest *Request, uri_t uri_enum)
{
    JSON_RESPONSE *json = NULL;
    switch (uri_enum)
    {
    case ROOT_URI:
        json = handle_get_info();
        break;
    case URI_USERS:
        json = handle_get_users();
        break;
    case URI_USERS_WITH_ID:
        json = handle_user_with_id(atoi(Request->uri + 7));
        break;
    case URI_USER_INFO:
        json = get_user_info();
        break;
    default:
        json = NULL;
    }
    return json;
}

JSON_RESPONSE *handle_patch_uri(const char *uri, const char *body)
{
    JSON_RESPONSE *json = NULL;
    if (strncmp(uri, "/users/", 7) == 0)
    {
        if (is_just_id(uri + 7))
        {
            json = handle_patch_with_id(atoi(uri + 7), body);
        }
    }
    if (!json)
    {
        json = (JSON_RESPONSE *)malloc(sizeof(JSON_RESPONSE));
        json->json_string = strdup("\"message\" : \"format is not /users/{id}\"");
        json->Status = BAD_REQUEST;
    }
    return json;
}

int make_hashed_password(char *original_pass, char *hashed_pass, const char *salt)
{
    if (*salt == 0)
    {
        if (!RAND_bytes((unsigned char *)salt, SALT_LEN))
            return -1;
    }
    if (PKCS5_PBKDF2_HMAC((const char *)original_pass,
                          strlen(original_pass),
                          (const unsigned char *)salt,
                          SALT_LEN, ITERATIONS, EVP_sha256(), HASH_LEN,
                          (unsigned char *)hashed_pass) != 1)
        return -1;
    return 0;
}

char *get_token(const char *body)
{
    const char *start = strstr(body, "Authorization: Bearer ");
    if (start)
    {
        start += strlen("Authorization: Bearer ");
        char *end = strstr(start, "\r\n");
        int len = end - start;
        char *token = (char *)malloc(len + 1);
        if (token)
        {
            strncpy(token, start, len);
            token[len] = '\0';
            return token;
        }
        else
            return NULL;
    }
    return NULL;
}

int is_expired(jwt_t *my_jwt, const char *exp)
{
    time_t expiry = jwt_get_grant_int(my_jwt, exp);
    if (expiry < time(NULL))
        return 0;
    return 1;
}

jwt_t *get_decoded_token(char *token)
{
    jwt_t *my_jwt;
    char *secret = getenv("SECRET_KEY");
    size_t sec_len = strlen(secret);
    return (!jwt_decode(&my_jwt, (const char *)token, (const unsigned char *)secret, (int)sec_len)) ? my_jwt : NULL;
}
void serve_file(socket_t fd, SSL *ssl, const char *path)
{
    int file_fd = open(path, O_RDONLY);
    if (file_fd < 0)
        return;

    struct stat st;
    fstat(file_fd, &st);
    off_t file_size = st.st_size;

    char header[256];
    int header_len = sprintf(header, "HTTP/1.1 200 OK\r\n"
                                     "Content-Length: %ld\r\n"
                                     "Content-Type: text/html\r\n\r\n",
                             file_size);
    SSL_write(ssl, header, header_len);

    // Read file in chunks and send via SSL
    char file_buffer[4096];
    ssize_t bytes_read;
    while ((bytes_read = read(file_fd, file_buffer, sizeof(file_buffer))) > 0)
    {
        SSL_write(ssl, file_buffer, bytes_read); // ← CHANGED from sendfile()
    }

    close(file_fd);
}

void add_client_for_websock(socket_t fd, int id, SSL *ssl)
{
    Client *new_client = (Client *)malloc(sizeof(Client));
    if (!new_client)
    {
        LOG_ERROR("memory allocation failed for Client structure...");
        return;
    }
    new_client->client_id = id;
    new_client->fd = fd;
    new_client->ssl = ssl;
    new_client->next = NULL;
    pthread_mutex_lock(&client_mutex);
    if (clients == NULL)
    {
        clients = new_client;
    }
    else
    {
        Client *temp = clients;
        while (temp->next != NULL)
        {
            temp = temp->next;
        }
        temp->next = new_client;
    }
    pthread_mutex_unlock(&client_mutex);
}

void remove_client_for_websock(socket_t fd)
{
    pthread_mutex_lock(&client_mutex);
    Client *curr = clients, *prev = NULL;
    while (curr != NULL)
    {
        if (curr->fd == fd)
        {
            if (prev == NULL)
                clients = curr->next;
            else
                prev->next = curr->next;
            if (curr->ssl)
            {
                SSL_shutdown(curr->ssl);
                SSL_free(curr->ssl);
            }
            free(curr);
            break;
        }
        prev = curr;
        curr->next = prev->next;
    }
    pthread_mutex_unlock(&client_mutex);
}
void init_openssl()
{
    SSL_load_error_strings();
    OpenSSL_add_ssl_algorithms();
}

void cleanup_openssl()
{
    EVP_cleanup();
}

SSL_CTX *create_ssl_context()
{
    const SSL_METHOD *method;
    SSL_CTX *ctx;

    method = TLS_server_method(); // Use TLS 1.2+
    ctx = SSL_CTX_new(method);
    if (!ctx)
    {
        LOG_FATAL("Unable to create SSL context");
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
    return ctx;
}

void configure_ssl_context(SSL_CTX *ctx)
{
    // Load certificate and private key
    if (SSL_CTX_use_certificate_file(ctx, "src/certs/cert.pem", SSL_FILETYPE_PEM) <= 0)
    {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    if (SSL_CTX_use_PrivateKey_file(ctx, "src/certs/key.pem", SSL_FILETYPE_PEM) <= 0)
    {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    // Verify private key
    if (!SSL_CTX_check_private_key(ctx))
    {
        LOG_FATAL("Private key does not match the certificate\n");
        exit(EXIT_FAILURE);
    }
}
