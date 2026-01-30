#ifndef WEBSOCKET_H
#define WEBSOCKET_H

#include <stdint.h>
#include <time.h>
#include "server.h"

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
    uint8_t fin;
    uint8_t opcode;
    uint8_t mask;
    uint64_t payload_len;
    uint8_t masking_key[4];
    char *payload;
} ws_frame_t;

typedef struct
{
    int sender_id;
    char *username;
    char *message;
    long timestamp;
} chat_message_t;

int ws_handshake(socket_t client_fd, SSL *ssl, const char *response);
ws_frame_t *ws_parse_frame(const uint8_t *data, size_t len);
int ws_send_frame(socket_t fd,SSL*ssl, ws_opcode_t opcode, const char *payload, size_t len);
void ws_free_frame(ws_frame_t *frame);
void ws_broadcast_message(const char *message, socket_t sender_fd);
void *ws_handle_client(void *arg);
char *base64_encode(const unsigned char *input, int length);
void sha1(const char *input, unsigned char output[20]);

#endif