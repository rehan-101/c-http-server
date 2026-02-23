#ifndef SERVER_H
#define SERVER_H

#include <jwt.h>
#include <netinet/in.h>
#include <sqlite3.h>
#include <openssl/rand.h>
#include <openssl/evp.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <stdbool.h>
#include "json.h"
#include "config.h"
#include "logger.h"
#include "timeout.h"
#include "conn_limits.h"
#include "signals.h"
#include "validation.h"
#include "rate_limiter.h"

extern sqlite3 *db;
typedef int socket_t;
#define BUFFER_SIZE 16000
struct Server;
extern SSL_CTX *global_ssl_ctx;
typedef void (*launch)(struct Server *);
void clean_things(void *, ...);

// Password hashing: PBKDF2 with 10,000 iterations for compatibility
// TODO: After all users reset passwords, increase to 600,000 (NIST recommended)
#define ITERATIONS 10000
#define SALT_LEN 16
#define HASH_LEN 32

extern const char *headers_request;       // global pointer for collecting the headers of the request
extern ConnLimitsTracker *g_conn_tracker; // Global connection limits tracker

struct Server
{
    int domain, port, service, protocol, backlog;
    u_long interface;
    socket_t socket_fd;
    struct sockaddr_in address;
    launch Launch_function;
    SSL_CTX *ssl_ctx;
};
typedef enum Methods
{
    GET,
    POST,
    PUT,
    DELETE,
    PATCH,
    HEAD,
    OPTIONS,
} Methods;

struct httpRequest;
typedef enum
{
    URI_USER_INFO = 1,
    URI_UNKNOWN,
    ROOT_URI,
    URI_FOR_REGISTRATION,
    URI_FOR_LOGIN,
    URI_FOR_PROFILE,
    URI_FOR_CHAT,
} uri_t;
typedef struct
{
    Methods method;
    uri_t enum_for_uri[10];
    void (*handler)(socket_t file_descriptor, SSL *ssl, struct httpRequest *Request);
} Route;
struct info_after_method_line
{
    char *content_type, *body;
    int content_length;
};
struct httpRequest
{
    Methods enum_of_method;
    char *uri;
    uri_t enum_for_uri;
    struct info_after_method_line *header_info;
};

typedef struct client
{
    socket_t fd;
    int client_id;
    SSL *ssl;
    struct client *next;
} Client;

typedef struct
{
    int fd;
    SSL *ssl;
} socket_wrapper_t;

/* Epoll specific additions */
// state machine : tracks where each connection is in its lifecycle
typedef enum
{
    CONN_STATE_SSL_HANDSHAKE,   // performing SSL/TLS handshake
    CONN_STATE_READING_REQUEST, // Reading HTTP/Websockets request
    CONN_STATE_WEBSOCKET,       // active websockets connection
    CONN_STATE_CLOSING,         // Connection being closed
} conn_state_t;

// Message structure for chat history
typedef struct chat_message
{
    char username[32];
    char message[1024];
    char id[64];
    time_t timestamp;
    struct chat_message *next;
} chat_message_history_t;

// Typing indicator structure
typedef struct typing_indicator
{
    char username[32];
    time_t last_typing;
    struct typing_indicator *next;
} typing_indicator_t;

// User presence tracking
typedef struct online_user
{
    char username[32];
    int client_fd;
    time_t last_active;
    struct online_user *next;
} online_user_t;

typedef struct
{
    time_t last_ping_sent, last_pong_received;
    uint8_t missed_pongs;
    bool ping_in_flight;
} ping_pong_state_t;

// Epoll client structure (replaces thread stack for tracking state)
typedef struct epoll_client
{
    socket_t fd;
    SSL *ssl;           // SSL connection
    conn_state_t state; // current state of the connected client

    int is_websocket;             // 1 if upgraded to websocket
    int client_id;                // websocket client id
    ping_pong_state_t *ping_pong; // track for ping pong requests

    char username[32]; // Username for chat (from JWT during WebSocket auth)
    int user_id;       // User ID from JWT 'sub' claim
    char role[16];     // Role from JWT (for future RBAC)

    char buffer[BUFFER_SIZE]; // Request buffer
    size_t buffer_used;       // bytes in buffer
    // SSL state
    int want_ssl_read;
    int want_ssl_write;

    // Timeout tracking - prevents slow clients from holding resources
    TimeoutTracker timeout;

    // Client IP address - for connection limits enforcement
    uint32_t client_ip; // IP in network byte order (for conn_limits)

    // Linked list
    struct epoll_client *next;
} epoll_client_t;

// Epoll configuration
#define MAX_EPOLL_EVENTS 1024
#define EPOLL_TIMEOUT_MS 1000

extern Client *clients;
extern pthread_mutex_t client_mutex;
struct Server
server_constructor(int domain, int port, int service, int protocol, int backlog, u_long interface);
void get_func(socket_t, SSL *ssl, struct httpRequest *);
void post_func(socket_t client_fd, SSL *ssl, struct httpRequest *);
void put_func(socket_t client_fd, SSL *ssl, struct httpRequest *);
void delete_func(socket_t fd, SSL *ssl, struct httpRequest *);
void patch_func(socket_t fd, SSL *ssl, struct httpRequest *);
struct httpRequest *parse_methods(char *response);
JSON_RESPONSE *handle_get_uri(struct httpRequest *Request, uri_t uri_enum);
JSON_RESPONSE *handle_patch_uri(const char *uri, const char *body);
void listening_to_client(socket_t server_fd);
char *get_content_type(char *buffer);
int get_content_len(char *buffer);
char *get_body(char *buffer);
char *get_header(char *buffer);
int is_just_id(const char *uri);
int make_hashed_password(char *original_pass, char *hashed_pass, const char *salt);

void serve_file(socket_t fd, SSL *ssl, const char *filepath);
int is_expired(jwt_t *my_jwt, const char *exp);
char *get_token(const char *body);
jwt_t *get_decoded_token(char *token);

/*supporting functions for https secured layer*/
SSL_CTX *create_ssl_context();
void configure_ssl_context(SSL_CTX *ctx);
void init_openssl();
void cleanup_openssl();

void add_client_for_websock(socket_t fd, int id, SSL *ssl);
void remove_client_for_websock(socket_t fd);

/* ====== EPOLL Functions declarations ====== */
void listening_to_client_epoll(socket_t server_fd, SSL_CTX *ssl_ctx);

// helper functions
int set_nonblocking(int fd);
epoll_client_t *create_epoll_client(socket_t fd, SSL *ssl, uint32_t client_ip);
void free_epoll_client(epoll_client_t *client);
epoll_client_t *find_epoll_client(socket_t fd);
void remove_epoll_client(socket_t fd);
epoll_client_t *find_client_by_username(const char *username);

// Function declarations for chat features
void broadcast_user_list(void);
void broadcast_join_message(const char *username);
void broadcast_leave_message(const char *username);
void broadcast_chat_message(const char *username, const char *message, cJSON *mentions, const char *msg_id);
void broadcast_typing_indicator(const char *username);
void cleanup_old_typing_indicators(void);

void add_online_user(const char *username, socket_t client_fd);
void remove_online_user(socket_t client_fd);
int get_online_user_count(void);
void add_chat_message(const char *username, const char *message,const char * id);
void send_history_to_client(epoll_client_t *client);

int is_user_mentioned(const char *username, cJSON *mentions);
int send_mention_notification(const char *from, const char *to, const char *message);
void send_notifications_to_mentioned_users(const char *sender, cJSON *mentions, const char *message);
void broadcast_reaction(const char *username, const char *messageId, const char *emoji, const char *type, const char *location);
#endif
