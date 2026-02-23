#include "../include/server.h"
#include "../include/json.h"
#include "../include/database.h"
#include "../include/websocket.h"
#include "../include/auth.h"
#include <stdio.h>
#include <jwt.h>
#include <string.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
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

// === Chat Application Global State ===
static online_user_t *online_users_head = NULL;
static pthread_mutex_t online_users_mutex = PTHREAD_MUTEX_INITIALIZER;

static chat_message_history_t *message_history_head = NULL;
static pthread_mutex_t history_mutex = PTHREAD_MUTEX_INITIALIZER;

static typing_indicator_t *typing_indicators_head = NULL;
static pthread_mutex_t typing_mutex = PTHREAD_MUTEX_INITIALIZER;

// Message history limit
#define MAX_HISTORY_MESSAGES 100

Route routes[] = {
    {.method = GET, .enum_for_uri = {ROOT_URI, URI_USER_INFO, URI_FOR_LOGIN, URI_FOR_REGISTRATION, URI_FOR_PROFILE, URI_FOR_CHAT, 0}, .handler = get_func},
    {.method = POST, .enum_for_uri = {URI_FOR_REGISTRATION, URI_FOR_LOGIN, 0}, .handler = post_func},
    {.method = PUT, .enum_for_uri = {URI_USER_INFO, 0}, .handler = put_func},
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

    client->username[0] = '\0'; // Initialize username as empty
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
 * find_client_by_username - Find WebSocket client by username
 *
 * When sending a private message, we need to find the actual client
 * structure to send the message to. This searches through all connected
 * WebSocket clients.
 */
epoll_client_t *find_client_by_username(const char *username)
{
    epoll_client_t *current = epoll_clients_head;
    while (current)
    {
        if (current->is_websocket && current->username[0] != '\0' && strcmp(current->username, username) == 0)
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

            // Clean up chat resources
            if (to_free->username[0] != '\0')
            {
                remove_online_user(fd);
                broadcast_leave_message(to_free->username);
                broadcast_user_list();
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

        // *** NEW: Validate WebSocket authentication ***
        auth_context_t auth_ctx;
        if (auth_validate_websocket_token(client->buffer, &auth_ctx) != 0)
        {
            LOG_WARN("[WS AUTH] Unauthorized WebSocket upgrade attempt from fd=%d", client->fd);
            const char *response =
                "HTTP/1.1 401 Unauthorized\r\n"
                "Content-Type: application/json\r\n"
                "Access-Control-Allow-Origin: *\r\n"
                "Access-Control-Allow-Methods: GET, POST, PUT, DELETE, PATCH, OPTIONS\r\n"
                "Access-Control-Allow-Headers: Content-Type, Authorization\r\n"
                "Connection: close\r\n"
                "\r\n"
                "{\"error\":\"Unauthorized: Invalid or missing token\"}";
            SSL_write(client->ssl, response, strlen(response));
            remove_epoll_client(client->fd);
            return;
        }

        // *** Store username from JWT (trusted, not from client message!) ***
        strncpy(client->username, auth_ctx.username, sizeof(client->username) - 1);
        client->username[sizeof(client->username) - 1] = '\0';
        client->user_id = auth_ctx.user_id;
        strncpy(client->role, auth_ctx.role, sizeof(client->role) - 1);
        client->role[sizeof(client->role) - 1] = '\0';

        LOG_INFO("[WS AUTH] WebSocket upgrade authorized for user: %s (ID: %d)",
                 client->username, client->user_id);

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

        timeout_tracker_request_complete(&client->timeout);
        ws_init_ping_tracking(client); // initialize the server ping mechanism
        timeout_tracker_enable_keepalive(&client->timeout);

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
    // Handle CORS preflight requests
    if (strncmp(client->buffer, "OPTIONS ", 8) == 0)
    {
        const char *cors_response =
            "HTTP/1.1 200 OK\r\n"
            "Content-Type: application/json\r\n"
            "Access-Control-Allow-Origin: *\r\n"
            "Access-Control-Allow-Methods: GET, POST, PUT, DELETE, PATCH, OPTIONS\r\n"
            "Access-Control-Allow-Headers: Content-Type, Authorization\r\n"
            "Content-Length: 0\r\n"
            "Connection: close\r\n"
            "\r\n";
        SSL_write(client->ssl, cors_response, strlen(cors_response));
        remove_epoll_client(client->fd);
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

    // *** NEW: Check if endpoint requires authentication ***
    if (auth_endpoint_requires_auth(request->uri, request->enum_of_method))
    {
        auth_context_t auth_ctx;
        if (auth_validate_token(client->buffer, &auth_ctx) != 0)
        {
            LOG_WARN("[HTTP AUTH] Unauthorized request: %s %s from fd=%d",
                     request->enum_of_method == GET ? "GET" : request->enum_of_method == POST ? "POST"
                                                          : request->enum_of_method == PUT    ? "PUT"
                                                          : request->enum_of_method == DELETE ? "DELETE"
                                                                                              : "PATCH",
                     request->uri, client->fd);

            const char *response =
                "HTTP/1.1 401 Unauthorized\r\n"
                "Content-Type: application/json\r\n"
                "Access-Control-Allow-Origin: *\r\n"
                "Access-Control-Allow-Methods: GET, POST, PUT, DELETE, PATCH, OPTIONS\r\n"
                "Access-Control-Allow-Headers: Content-Type, Authorization\r\n"
                "Connection: close\r\n"
                "\r\n"
                "{\"error\":\"Unauthorized: Invalid or missing token\"}";
            SSL_write(client->ssl, response, strlen(response));

            // Clean up and close
            clean_things(request->uri, request->header_info->body,
                         request->header_info->content_type, request, NULL);
            remove_epoll_client(client->fd);
            return;
        }

        LOG_INFO("[HTTP AUTH] Authorized: %s (ID: %d) accessing %s",
                 auth_ctx.username, auth_ctx.user_id, request->uri);
    }

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
    timeout_tracker_activity(&client->timeout);
    // Read all available frames (edge-triggered requirement)
    while (1)
    {
        int bytes = SSL_read(client->ssl, ws_buffer, sizeof(ws_buffer) - 1);

        if (bytes <= 0)
        {
            ERR_clear_error();
            int err = SSL_get_error(client->ssl, bytes);
            if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE)
            {
                return 0; // Normal - no more frames
            }

            if (err == SSL_ERROR_ZERO_RETURN || bytes < 0)
            {
                LOG_INFO("WebSocket client #%d disconnected\n", client->client_id);
                // Broadcast leave message if user was logged in
                if (client->username[0] != '\0')
                {
                    broadcast_leave_message(client->username);
                    remove_online_user(client->fd);
                    broadcast_user_list();
                }
                return -1;
            }
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

            // parse json message
            cJSON *json = cJSON_Parse(frame->payload);
            if (!json)
            {
                LOG_ERROR("Failed to parse JSON from client #%d", client->client_id);
                break;
            }
            cJSON *type = cJSON_GetObjectItem(json, "type");
            if (!type)
            {
                LOG_ERROR("No type field in JSON from client #%d", client->client_id);
                cJSON_Delete(json);
                break;
            }
            // Handle different message types
            if (strcmp(type->valuestring, "join") == 0)
            {
                // *** Username already set during WebSocket upgrade (from JWT) ***
                // We NO LONGER trust client-provided username
                const char *username = client->username;

                if (!username || username[0] == '\0')
                {
                    LOG_ERROR("[WS] Client fd=%d attempted join without authentication", client->fd);
                    cJSON_Delete(json);
                    break;
                }

                // add to online users
                add_online_user(username, client->fd);

                // broadcast join message
                broadcast_join_message(username);

                // send user list
                broadcast_user_list();

                // send message history
                //    send_history_to_client(client);
                LOG_INFO("User '%s' joined chat (fd=%d)",
                         username, client->fd);
            }

            else if (strcmp(type->valuestring, "message") == 0)
            {
                cJSON *message_json = cJSON_GetObjectItem(json, "message");
                cJSON *id_json = cJSON_GetObjectItem(json, "id");
                const char *msg_id = id_json ? id_json->valuestring : NULL;
                cJSON *mentions_json = cJSON_GetObjectItem(json, "mentions"); // Get mentions array
                if (message_json && client->username[0] != '\0')
                {
                    const char *message = message_json->valuestring;
                    const char *id = msg_id ? msg_id : "unknown_id"; // Use provided ID or fallback

                    // Add to history with ID
                    add_chat_message(client->username, message, id);
                    if (mentions_json && cJSON_IsArray(mentions_json))
                        send_notifications_to_mentioned_users(client->username, mentions_json, message);
                    // Broadcast to all
                    broadcast_chat_message(client->username, message, mentions_json, id);
                }
            }
            else if (strcmp(type->valuestring, "typing") == 0)
            {
                // Typing indicator
                if (client->username[0] != '\0')
                {
                    broadcast_typing_indicator(client->username);
                }
            }
            else if (strcmp(type->valuestring, "private_message") == 0)
            {
                cJSON *to_json = cJSON_GetObjectItem(json, "to");
                cJSON *message_json = cJSON_GetObjectItem(json, "message");
                if (to_json && message_json && client->username[0] != '\0')
                {
                    const char *to_username = to_json->valuestring;
                    const char *message = message_json->valuestring;
                    ws_send_private_message(client->username, to_username, message);
                    LOG_INFO("Private message from '%s' to '%s'",
                             client->username, to_username);
                }
            }
            else if (strcmp(type->valuestring, "private_typing") == 0)
            {
                cJSON *to_json = cJSON_GetObjectItem(json, "to");
                if (to_json && client->username[0] != '\0')
                {
                    const char *to_username = to_json->valuestring;
                    ws_send_private_typing(client->username, to_username);
                }
            }
            /// adding the reaction feature
            else if (strcmp(type->valuestring, "reaction") == 0)
            {
                cJSON *messageId = cJSON_GetObjectItem(json, "messageId");
                cJSON *emoji = cJSON_GetObjectItem(json, "emoji");
                cJSON *action = cJSON_GetObjectItem(json, "action");
                cJSON *location = cJSON_GetObjectItem(json, "location");
                if (messageId && emoji && action && client->username[0] != '\0')
                {
                    const char *loc = location ? location->valuestring : "group:General";
                    // broadcast reaction with actio type
                    broadcast_reaction(client->username, messageId->valuestring, emoji->valuestring, action->valuestring,
                                       loc);
                    // Log it for debugging
                    LOG_INFO("User '%s'  %s reaction %s to message %s",
                             client->username, strcmp(action->valuestring, "add") == 0 ? "added" : "removed", emoji->valuestring, messageId->valuestring);
                }
            }
            cJSON_Delete(json);
            break;

        case WS_OPCODE_PING:
            ws_send_frame(client->fd, client->ssl, WS_OPCODE_PONG,
                          frame->payload, frame->payload_len);
            break;
        case WS_OPCODE_PONG:
            handle_pong_response(client);
            return 0;
        case WS_OPCODE_CLOSE:
            LOG_INFO("WebSocket client #%d requested close\n",
                     client->client_id);
            // Broadcast leave message if user was logged in
            if (client->username[0] != '\0')
            {
                broadcast_leave_message(client->username);
                remove_online_user(client->fd);
                broadcast_user_list();
            }
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
        break;
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
            if (current->is_websocket)
                continue;
            else
            {
                LOG_INFO("Connection fd=%d timed out: %s", current->fd, reason);
                remove_epoll_client(current->fd);
            }
            free((void *)reason);
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
    int ping_check_counter = 0;
    const int TIMEOUT_CHECK_INTERVAL = 10; // Check timeout every 10 iterations
    const int PING_CHECK_INTERVAL = 5;

    time_t last_cleanup = time(NULL);
    while (!should_shutdown()) // Check shutdown flag from signals
    {
        // Wait for events - THIS IS THE ONLY BLOCKING POINT
        int n_events = epoll_wait(epoll_fd, events, MAX_EPOLL_EVENTS, EPOLL_TIMEOUT_MS);

        if (n_events < 0)
        {
            if (errno == EINTR)
            {
                if (should_shutdown())
                {
                    fprintf(stderr, "[DEBUG] EINTR received and shutdown requested. Breaking loop.\n");
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
            ping_check_counter++;
            if (timeout_counter >= TIMEOUT_CHECK_INTERVAL)
            {
                check_timeouts();
                timeout_counter = 0;
                // Log connection stats periodically
                if (g_conn_tracker)
                    conn_limits_print_stats(g_conn_tracker);
            }

            /** Check connection health for web sockets **/
            if (ping_check_counter >= PING_CHECK_INTERVAL)
            {
                ws_check_connection_health(epoll_clients_head);
                ping_check_counter = 0;
            }

            // Clean old typing indicators every 10 seconds
            time_t now = time(NULL);
            if (now - last_cleanup > 10)
            {
                cleanup_old_typing_indicators();
                last_cleanup = now;
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

        fprintf(stderr, "[DEBUG] Closing client fd=%d\n", client->fd);
        fflush(stderr);
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
    return;
}

void add_online_user(const char *username, socket_t client_fd)
{
    online_user_t *new_user = calloc(1, sizeof(online_user_t));
    if (!new_user)
    {
        LOG_ERROR("Failed to allocate online user structure..");
        return;
    }
    strncpy(new_user->username, username, sizeof(new_user->username) - 1);
    new_user->username[sizeof(new_user->username) - 1] = '\0';
    new_user->client_fd = client_fd;
    new_user->last_active = time(NULL);

    pthread_mutex_lock(&online_users_mutex);
    new_user->next = online_users_head;
    online_users_head = new_user;
    pthread_mutex_unlock(&online_users_mutex);

    LOG_INFO("User '%s' added to online list (fd=%d)", username, client_fd);
}

void remove_online_user(socket_t client_fd)
{
    pthread_mutex_lock(&online_users_mutex);

    online_user_t **current = &online_users_head;
    while (*current)
    {
        if ((*current)->client_fd == client_fd)
        {
            online_user_t *to_free = *current;
            *current = (*current)->next;
            free(to_free);
            LOG_INFO("Removed user (fd = %d) from online list", client_fd);
            break;
        }
        current = &(*current)->next;
    }
    pthread_mutex_unlock(&online_users_mutex);
}

int get_online_user_count(void)
{
    int count = 0;
    pthread_mutex_lock(&online_users_mutex);
    online_user_t *current = online_users_head;
    while (current)
    {
        count++;
        current = current->next;
    }
    pthread_mutex_unlock(&online_users_mutex);
    return count;
}

void add_chat_message(const char *username, const char *message, const char *id)
{
    chat_message_history_t *new_msg = malloc(sizeof(chat_message_history_t));
    if (!new_msg)
    {
        LOG_ERROR("Failed to allocate chat message");
        return;
    }
    strncpy(new_msg->username, username, sizeof(new_msg->username) - 1);
    new_msg->username[sizeof(new_msg->username) - 1] = '\0';
    strncpy(new_msg->message, message, sizeof(new_msg->message) - 1);
    new_msg->message[sizeof(new_msg->message) - 1] = '\0';
    if (id)
    {
        strncpy(new_msg->id, id, sizeof(new_msg->id) - 1);
        new_msg->id[sizeof(new_msg->id) - 1] = '\0';
    }
    else
    {
        new_msg->id[0] = '\0';
    }
    new_msg->timestamp = time(NULL);

    pthread_mutex_lock(&history_mutex);

    // add to beginning of the list
    new_msg->next = message_history_head;
    message_history_head = new_msg;
    // keep only last MAX_HISTORY_MESSAGES
    int count = 0;
    chat_message_history_t *current = message_history_head;
    chat_message_history_t *prev = NULL;

    while (current && count < MAX_HISTORY_MESSAGES)
    {
        prev = current;
        current = current->next;
        count++;
    }
    if (count)
    {
        prev->next = NULL;
        while (current)
        {
            chat_message_history_t *to_free = current;
            current = current->next;
            free(to_free);
        }
    }
    pthread_mutex_unlock(&history_mutex);
}

/**
 * is_user_mentioned - Check if a username is in the mentions array
 *  The username to check
 *  JSON array of mentioned usernames
 * Returns: 1 if mentioned, 0 if not
 */

int is_user_mentioned(const char *username, cJSON *mentions)
{
    if (!mentions || !cJSON_IsArray(mentions))
        return 0;

    // Get how many mentions are in the array
    int mention_count = cJSON_GetArraySize(mentions);

    // loop through each mention in the array
    for (int i = 0; i < mention_count; i++)
    {
        // Get mention at position i
        cJSON *item = cJSON_GetArrayItem(mentions, i);
        // check if it's a string and matches the username we are looking for
        if (cJSON_IsString(item) && strcmp(item->valuestring, username) == 0)
            return 1;
    }
    return 0;
}

/**
 * send_mention_notification - Send a special notification to a mentioned user
 * Who mentioned them (sender's username)
 * The user being mentioned (recipient's username)
 * The original message content
 * Returns: 1 if sent successfully, 0 if user offline or error
 * This creates a special notification that triggers a toast/sound
 * on the frontend for mentioned users.
 */

int send_mention_notification(const char *from, const char *to, const char *message)
{
    cJSON *root = cJSON_CreateObject();
    cJSON_AddStringToObject(root, "type", "mention_notification"); // Special type
    cJSON_AddStringToObject(root, "from", from);                   // Who mentioned
    cJSON_AddStringToObject(root, "message", message);             // The message
    cJSON_AddNumberToObject(root, "timestamp", time(NULL));        // When

    // Convert JSON to string for sending
    char *json_str = cJSON_PrintUnformatted(root);
    // Find the mentioned user connection
    epoll_client_t *recipient = find_client_by_username(to);
    int sent = 0;
    // If user is online, send the notification
    if (recipient)
    {
        if (ws_send_frame(recipient->fd, recipient->ssl, WS_OPCODE_TEXT, json_str, strlen(json_str)) == 0)
        {
            sent = 1;
            LOG_INFO("Mention notification sent to %s from %s", to, from);
        }
        else
        {
            LOG_ERROR("Failed to send mention notification to %s", to);
        }
    }
    cJSON_Delete(root);
    free(json_str);

    return sent;
}

/**
 * send_notifications_to_mentioned_users - Send notifications to ALL mentioned users
 *  Who sent the original message
 *  JSON array of mentioned usernames (already deduplicated)
 *  The original message content
 *
 * This ensures EVERY mentioned user gets a notification, but only ONE
 *      notification per user (no duplicates).
 */

void send_notifications_to_mentioned_users(const char *sender, cJSON *mentions, const char *message)
{
    if (!mentions || !cJSON_IsArray(mentions))
        return;

    int mention_count = cJSON_GetArraySize(mentions);
    LOG_INFO("Sending notifications to %d mentioned users", mention_count);
    // Track who we've already notified (to avoid duplicates)
    char *notified[32] = {0}; // Simple array to track notified users
    int notified_count = 0;
    for (int i = 0; i < mention_count; i++)
    {
        cJSON *item = cJSON_GetArrayItem(mentions, i);
        if (!cJSON_IsString(item))
            continue;

        const char *mentioned_user = item->valuestring;

        // Skip if user mentioned themselves
        if (strcmp(sender, mentioned_user) == 0)
        {
            LOG_DEBUG("User %s mentioned themselves, skipping notification", sender);
            continue;
        }
        // Check if we already notified this user (duplicate prevention)
        int already_notified = 0;
        for (int j = 0; j < notified_count; j++)
        {
            if (strcmp(notified[j], mentioned_user) == 0)
            {
                already_notified = 1;
                break;
            }
        }
        // If not notified yet, send notification
        if (!already_notified)
        {
            if (send_mention_notification(sender, mentioned_user, message))
            {
                notified[notified_count++] = (char *)mentioned_user;
                LOG_INFO("Notification sent to %s", mentioned_user);
            }
            else
            {
                LOG_WARN("Failed to send notification to %s", mentioned_user);
            }
        }
    }
}

void send_history_to_client(epoll_client_t *client)
{
    pthread_mutex_lock(&history_mutex);
    // first, count how many messages we have
    int count = 0;
    chat_message_history_t *current = message_history_head;
    while (current && count < MAX_HISTORY_MESSAGES)
    {
        count++;
        current = current->next;
    }
    if (count == 0)
    {
        pthread_mutex_unlock(&history_mutex);
        return;
    }
    // create an array of message pointers
    chat_message_history_t *messages[count];

    // fill array in reverse(newest to oldest)
    current = message_history_head;
    for (int i = count - 1; i >= 0; i--)
    {
        messages[i] = current; // store oldest at index 0
        current = current->next;
    }
    // Now send in chronological order (oldest at index 0 first)
    for (int i = 0; i < count; i++)
    {
        cJSON *msg_json = cJSON_CreateObject();
        cJSON_AddStringToObject(msg_json, "type", "message");
        if (messages[i]->id[0] != '\0')
        {
            cJSON_AddStringToObject(msg_json, "id", messages[i]->id);
        }
        cJSON_AddStringToObject(msg_json, "username", messages[i]->username);
        cJSON_AddStringToObject(msg_json, "message", messages[i]->message);
        cJSON_AddNumberToObject(msg_json, "timestamp", messages[i]->timestamp);

        char *json_str = cJSON_PrintUnformatted(msg_json);
        ws_send_frame(client->fd, client->ssl, WS_OPCODE_TEXT, json_str, strlen(json_str));
        cJSON_Delete(msg_json);
        free(json_str);
    }
    pthread_mutex_unlock(&history_mutex);
}

void broadcast_user_list(void)
{
    cJSON *root = cJSON_CreateObject();
    cJSON_AddStringToObject(root, "type", "users");
    cJSON *users_array = cJSON_CreateArray();

    pthread_mutex_lock(&online_users_mutex);
    online_user_t *current = online_users_head;
    while (current)
    {
        cJSON *user_obj = cJSON_CreateObject();
        cJSON_AddStringToObject(user_obj, "username", current->username);
        cJSON_AddBoolToObject(user_obj, "isOnline", 1);
        cJSON_AddItemToArray(users_array, user_obj);
        current = current->next;
    }
    pthread_mutex_unlock(&online_users_mutex);
    cJSON_AddItemToObject(root, "users", users_array);
    char *json_str = cJSON_PrintUnformatted(root);

    // send to all websocket clients
    epoll_client_t *client = epoll_clients_head;
    while (client)
    {
        if (client->is_websocket && client->username[0] != '\0')
        {
            ws_send_frame(client->fd, client->ssl, WS_OPCODE_TEXT, json_str, strlen(json_str));
        }
        client = client->next;
    }
    cJSON_Delete(root);
    free(json_str);
}

void broadcast_join_message(const char *username)
{
    cJSON *root = cJSON_CreateObject();
    cJSON_AddStringToObject(root, "type", "join");
    cJSON_AddStringToObject(root, "username", username);
    cJSON_AddNumberToObject(root, "timestamp", time(NULL));

    char *json_str = cJSON_PrintUnformatted(root);

    epoll_client_t *client = epoll_clients_head;
    while (client)
    {
        if (client->is_websocket && strcmp(client->username, username) != 0)
        {
            ws_send_frame(client->fd, client->ssl, WS_OPCODE_TEXT,
                          json_str, strlen(json_str));
        }
        client = client->next;
    }

    cJSON_Delete(root);
    free(json_str);
}

void broadcast_leave_message(const char *username)
{
    cJSON *root = cJSON_CreateObject();
    cJSON_AddStringToObject(root, "type", "leave");
    cJSON_AddStringToObject(root, "username", username);
    cJSON_AddNumberToObject(root, "timestamp", time(NULL));

    char *json_str = cJSON_PrintUnformatted(root);

    epoll_client_t *client = epoll_clients_head;
    while (client)
    {
        if (client->is_websocket && client->username[0] != '\0')
        {
            ws_send_frame(client->fd, client->ssl, WS_OPCODE_TEXT,
                          json_str, strlen(json_str));
        }
        client = client->next;
    }

    cJSON_Delete(root);
    free(json_str);
}

void broadcast_chat_message(const char *username, const char *message, cJSON *mentions, const char *msg_id)
{
    cJSON *root = cJSON_CreateObject();
    cJSON_AddStringToObject(root, "type", "message");
    if (msg_id)
        cJSON_AddStringToObject(root, "id", msg_id);
    cJSON_AddStringToObject(root, "username", username);
    cJSON_AddStringToObject(root, "message", message);
    cJSON_AddNumberToObject(root, "timestamp", time(NULL));

    if (mentions && cJSON_IsArray(mentions))
    {
        cJSON *mentions_copy = cJSON_Duplicate(mentions, 1);
        cJSON_AddItemToObject(root, "mentions", mentions_copy);
    }
    else
    {
        cJSON_AddArrayToObject(root, "mentions"); // Empty array
    }

    char *json_str = cJSON_PrintUnformatted(root);

    epoll_client_t *client = epoll_clients_head;
    while (client)
    {
        if (client->is_websocket && client->username[0] != '\0')
        {
            ws_send_frame(client->fd, client->ssl, WS_OPCODE_TEXT,
                          json_str, strlen(json_str));
        }
        client = client->next;
    }

    cJSON_Delete(root);
    free(json_str);
}

void broadcast_reaction(const char *username, const char *messageId, const char *emoji, const char *action, const char *location)
{
    // create a json object to send to all the clients
    cJSON *root = cJSON_CreateObject();
    cJSON_AddStringToObject(root, "type", "reaction");
    cJSON_AddStringToObject(root, "username", username);
    cJSON_AddStringToObject(root, "messageId", messageId);
    cJSON_AddStringToObject(root, "emoji", emoji);
    cJSON_AddStringToObject(root, "action", action);
    cJSON_AddNumberToObject(root, "timestamp", time(NULL));
    cJSON_AddStringToObject(root, "location", location);

    char *json_str = cJSON_PrintUnformatted(root);

    // loop through all connected clients
    epoll_client_t *client = epoll_clients_head;
    while (client)
    {
        if (client->is_websocket && client->username[0] != '\0')
        {
            if (strncmp(location, "group:", 6) == 0)
            {
                if (ws_send_frame(client->fd, client->ssl, WS_OPCODE_TEXT, json_str, strlen(json_str)) == 0)
                {
                    LOG_INFO("reaction '%s' sent to client", emoji);
                }
            }
            else if (strncmp(location, "private:", 8) == 0)
            {
                const char *peer = location + 8;
                if (strcmp(client->username, username) == 0 || strcmp(client->username, peer) == 0)
                    ws_send_frame(client->fd, client->ssl, WS_OPCODE_TEXT, json_str, strlen(json_str));
            }
        }
        client = client->next;
    }
    cJSON_Delete(root);
    free(json_str);
}

void broadcast_typing_indicator(const char *username)
{
    cJSON *root = cJSON_CreateObject();
    cJSON_AddStringToObject(root, "type", "typing");
    cJSON_AddStringToObject(root, "username", username);

    char *json_str = cJSON_PrintUnformatted(root);

    epoll_client_t *client = epoll_clients_head;
    while (client)
    {
        if (client->is_websocket && client->username[0] != '\0' &&
            strcmp(client->username, username) != 0)
        {
            ws_send_frame(client->fd, client->ssl, WS_OPCODE_TEXT,
                          json_str, strlen(json_str));
        }
        client = client->next;
    }

    cJSON_Delete(root);
    free(json_str);
}

void cleanup_old_typing_indicators(void)
{
    time_t now = time(NULL);
    pthread_mutex_lock(&typing_mutex);

    typing_indicator_t **current = &typing_indicators_head;
    while (*current)
    {
        if (now - (*current)->last_typing > 3)
        {
            // Remove old indicator
            typing_indicator_t *to_free = *current;
            *current = (*current)->next;
            free(to_free);
        }
        else
        {
            current = &(*current)->next;
        }
    }

    pthread_mutex_unlock(&typing_mutex);
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

                // Check rate limit BEFORE processing message
                int user_id = client_id; // Should be populated from auth context
                if (!rate_limit_check(user_id))
                {
                    LOG_WARN("Rate limit exceeded for user_id=%d", user_id);
                    // Send error message to client
                    cJSON *error_obj = cJSON_CreateObject();
                    cJSON_AddStringToObject(error_obj, "error", "Rate limit exceeded");
                    cJSON_AddNumberToObject(error_obj, "remaining", rate_limit_remaining(user_id));
                    char *error_json = cJSON_PrintUnformatted(error_obj);
                    ws_send_frame(new_socket, ssl, WS_OPCODE_TEXT, error_json, -1);
                    free(error_json);
                    cJSON_Delete(error_obj);
                    ws_free_frame(frame);
                    break;
                }

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
    request->enum_for_uri = (strcmp(request->uri, "/") == 0) ? ROOT_URI : (strcmp(request->uri, "/me") == 0)         ? URI_USER_INFO
                                                                       : strcmp(request->uri, "/profile") == 0      ? URI_FOR_PROFILE
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
        JSON_RESPONSE *json_body = NULL;
        if (Request->enum_for_uri == URI_USER_INFO) {
            json_body = get_user_info();
        } else {
            json_body = (JSON_RESPONSE *)malloc(sizeof(JSON_RESPONSE));
            json_body->json_string = strdup("{\"error\":\"Endpoint not found or invalid\"}");
            json_body->Status = NOT_FOUND;
        }
        send_response_back(fd, ssl, json_body);
        close(fd);
        if (json_body->json_string) free(json_body->json_string);
        free(json_body);
    }
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
        if (strcmp(post_request->uri, "/register") == 0)
        {
            json_response = handle_post_json_for_register(post_request->header_info->body);
        }
        else if (strcmp(post_request->uri, "/login") == 0)
        {
            json_response = handle_post_json_for_login(post_request->header_info->body);
        }
        else
        {
            json_response = (JSON_RESPONSE *)malloc(sizeof(JSON_RESPONSE));
            json_response->json_string = strdup("{\"error\" : \"This endpoint is not defined yet\"}");
            json_response->Status = BAD_REQUEST;
        }
    }
    else
    {
        json_response = (JSON_RESPONSE *)malloc(sizeof(JSON_RESPONSE));
        json_response->json_string = strdup("{\"message\":\"Unsupported content type or invalid request\"}");
        json_response->Status = BAD_REQUEST;
    }

    // Format HTTP response (just like get_func does)
    send_response_back(client_fd, ssl, json_response);
    close(client_fd);
    if (json_response && json_response->json_string)                   // Close the connection
        clean_things(json_response->json_string, json_response, NULL); // Free the allocated JSON string
}
void put_func(socket_t fd, SSL *ssl, struct httpRequest *Request)
{
    JSON_RESPONSE *json = NULL;
    if (strcmp(Request->uri, "/me") == 0)
    {
        json = handle_update_current_user((const char *)Request->header_info->body);
    }
    
    if (!json)
    {
        json = (JSON_RESPONSE *)malloc(sizeof(JSON_RESPONSE));
        if (json)
        {
            json->json_string = strdup("{\"error\" : \"invalid uri or endpoint being passed\"}");
            json->Status = BAD_REQUEST;
        }
    }
    send_response_back(fd, ssl, json);
    close(fd);
    if (json && json->json_string) 
        clean_things(json->json_string, json, NULL);
}

int make_hashed_password(char *original_pass, char *hashed_pass, const char *salt)
{
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
    (void)fd;
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
        SSL_write(ssl, file_buffer, bytes_read);
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
        curr = curr->next;
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
    if (SSL_CTX_use_certificate_file(ctx, g_config.ssl_cert_path, SSL_FILETYPE_PEM) <= 0)
    {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    if (SSL_CTX_use_PrivateKey_file(ctx, g_config.ssl_key_path, SSL_FILETYPE_PEM) <= 0)
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
