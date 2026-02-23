#ifndef WEBSOCKET_H
#define WEBSOCKET_H

#include <stdint.h>
#include <time.h>
#include "server.h"

typedef struct epoll_client epoll_client_t;
typedef enum
{
    WS_OPCODE_CONTINUATION = 0x0,
    WS_OPCODE_TEXT = 0x1,
    WS_OPCODE_BINARY = 0X2,
    WS_OPCODE_CLOSE = 0X8,
    WS_OPCODE_PING = 0x9,
    WS_OPCODE_PONG = 0xA,
} ws_opcode_t;

typedef struct
{
    uint8_t fin : 1;
    uint8_t rsv1 : 1, rsv2 : 1, rsv3 : 1;
    uint8_t opcode : 4;
    uint8_t mask : 1;
    uint64_t payload_len;
    uint8_t masking_key[4];
    char *payload;
} ws_frame_t;

#define PING_INTERVAL 30   // Send ping every 30 seconds
#define PONG_TIMEOUT 10    // Wait 10 seconds for pong
#define MAX_MISSED_PINGS 3 // Disconnect after 3 missed

typedef struct
{
    int sender_id;
    char *username;
    char *message;
    long timestamp;
} chat_message_t;

int ws_handshake(socket_t client_fd, SSL *ssl, const char *response);
ws_frame_t *ws_parse_frame(const uint8_t *data, size_t len);
int ws_send_frame(socket_t fd, SSL *ssl, ws_opcode_t opcode, const char *payload, size_t len);
void ws_free_frame(ws_frame_t *frame);
void ws_broadcast_message(const char *message, socket_t sender_fd);
void ws_send_private_message(const char *from, const char *to, const char *msg);
void ws_send_private_typing(const char*from,const char*to);
void *ws_handle_client(void *arg);
char *base64_encode(const unsigned char *input, int length);
void sha1(const char *input, unsigned char output[20]);
static inline void ws_init_ping_tracking(epoll_client_t *client)
{
    client->ping_pong = calloc(1, sizeof(ping_pong_state_t));
    if (!client->ping_pong)
    {
        LOG_ERRNO(LOG_ERROR, "calloc");
        return;
    }
    time_t now = time(NULL);
    client->ping_pong->last_ping_sent = now;
    client->ping_pong->last_pong_received = now;
    client->ping_pong->missed_pongs = 0;
    client->ping_pong->ping_in_flight = 0;
}
void handle_pong_response(epoll_client_t *client);
int ws_send_ping(epoll_client_t *client);
void ws_check_connection_health(epoll_client_t *clients_head);
#endif