#include "../include/websocket.h"
#include "../include/server.h"
#include "../include/json.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <openssl/sha.h>
#include <cjson/cJSON.h>

#define WS_GUID "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

// Base64 encoding table
static const char base64_table[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

char *base64_encode(const unsigned char *input, int length)
{
    int output_length = 4 * ((length + 2) / 3);
    char *encoded = malloc(output_length + 1);
    if (!encoded)
        return NULL;

    int i, j;
    for (i = 0, j = 0; i < length;)
    {
        uint32_t octet_a = i < length ? input[i++] : 0;
        uint32_t octet_b = i < length ? input[i++] : 0;
        uint32_t octet_c = i < length ? input[i++] : 0;
        uint32_t triple = (octet_a << 16) + (octet_b << 8) + octet_c;

        encoded[j++] = base64_table[(triple >> 18) & 0x3F];
        encoded[j++] = base64_table[(triple >> 12) & 0x3F];
        encoded[j++] = base64_table[(triple >> 6) & 0x3F];
        encoded[j++] = base64_table[triple & 0x3F];
    }

    int padding = length % 3;
    if (padding > 0)
    {
        for (i = 0; i < 3 - padding; i++)
        {
            encoded[output_length - 1 - i] = '=';
        }
    }
    encoded[output_length] = '\0';
    return encoded;
}

void sha1(const char *input, unsigned char output[20])
{
    SHA1((unsigned char *)input, strlen(input), output);
}

int ws_handshake(socket_t client_fd, SSL *ssl, const char *request)
{
    const char *key_header = "Sec-WebSocket-Key: ";
    char *key_start = strstr(request, key_header);

    if (!key_start)
    {
        fprintf(stderr, "No websocket key found");
        return -1;
    }
    key_start += strlen(key_header);
    char *key_end = strstr(key_start, "\r\n");
    if (!key_end)
    {
        fprintf(stderr, "Malformed WebSocket key\n");
        return -1;
    }
    size_t key_len = key_end - key_start;
    char *client_key = malloc(key_len + 1);
    if (!client_key)
        return -1;

    strncpy(client_key, key_start, key_len);
    client_key[key_len] = '\0';
    char *concatenated = malloc(strlen(client_key) + strlen(WS_GUID) + 1);
    if (!concatenated)
    {
        free(client_key);
        return -1;
    }

    sprintf(concatenated, "%s%s", client_key, WS_GUID);
    free(client_key);

    // SHA1 hash
    unsigned char hash[20];
    sha1(concatenated, hash);
    free(concatenated);

    // Base64 encode
    char *accept_key = base64_encode(hash, 20);
    if (!accept_key)
        return -1;

    // *** NEW: Check if client sent Sec-WebSocket-Protocol header ***
    char response[1024];  // Increased size to fit full token
    const char *protocol_header = strstr(request, "Sec-WebSocket-Protocol:");
    if (protocol_header && strstr(protocol_header, "Bearer"))
    {
        // *** FIX: Extract the FULL protocol value to echo back ***
        // Client sends: "Sec-WebSocket-Protocol: Bearer.<JWT_TOKEN>"
        // We must respond with EXACT same value (RFC 6455)
        
        const char *proto_start = protocol_header + strlen("Sec-WebSocket-Protocol:");
        // Skip whitespace
        while (*proto_start == ' ' || *proto_start == '\t') proto_start++;
        
        // Find end of line
        const char *proto_end = strstr(proto_start, "\r\n");
        if (!proto_end) {
            proto_end = proto_start + strlen(proto_start);
        }
        
        int proto_len = proto_end - proto_start;
        char protocol_value[1024];
        if (proto_len >= (int)sizeof(protocol_value)) {
            proto_len = sizeof(protocol_value) - 1;
        }
        strncpy(protocol_value, proto_start, proto_len);
        protocol_value[proto_len] = '\0';
        
        // Trim trailing whitespace
        while (proto_len > 0 && (protocol_value[proto_len-1] == ' ' || protocol_value[proto_len-1] == '\t')) {
            protocol_value[--proto_len] = '\0';
        }
        
        // Client requested Bearer protocol - must echo EXACT value back
        int len = snprintf(response, sizeof(response),
                           "HTTP/1.1 101 Switching Protocols\r\n"
                           "Upgrade: websocket\r\n"
                           "Connection: Upgrade\r\n"
                           "Sec-WebSocket-Accept: %s\r\n"
                           "Sec-WebSocket-Protocol: %s\r\n"
                           "\r\n",
                           accept_key, protocol_value);
        free(accept_key);
        if (SSL_write(ssl, response, len) < 0)
        {
            perror("Failed to send handshake response");
            return -1;
        }
        
        LOG_DEBUG("[WS] Handshake with protocol: %s", protocol_value);
    }
    else
    {
        // No protocol requested - standard handshake
        int len = snprintf(response, sizeof(response),
                           "HTTP/1.1 101 Switching Protocols\r\n"
                           "Upgrade: websocket\r\n"
                           "Connection: Upgrade\r\n"
                           "Sec-WebSocket-Accept: %s\r\n"
                           "\r\n",
                           accept_key);
        free(accept_key);
        if (SSL_write(ssl, response, len) < 0)
        {
            perror("Failed to send handshake response");
            return -1;
        }
    }

    printf("WebSocket handshake successful for fd %d\n", client_fd);
    return 0;
}

ws_frame_t *ws_parse_frame(const uint8_t *data, size_t len)
{
    if (len < 2)
        return NULL;
    ws_frame_t *frame = calloc(1, sizeof(ws_frame_t));
    if (!frame)
        return NULL;
    frame->fin = (data[0] >> 7) & 0x1;
    frame->rsv1 = (data[0] & 0x40) ? 1 : 0;
    frame->rsv2 = (data[0] & 0x20) ? 1 : 0;
    frame->rsv3 = (data[0] & 0x10) ? 1 : 0;

    frame->opcode = data[0] & 0x0F;

    frame->mask = (data[1] >> 7) & 0x01;
    frame->payload_len = data[1] & 0x7F;

    size_t pos = 2;
    if (frame->payload_len == 126)
    {
        if (len < pos + 2)
        {
            free(frame);
            return NULL;
        }
        frame->payload_len = (data[pos] << 8 | data[pos + 1]);
        pos += 2;
    }
    else if (frame->payload_len == 127)
    {
        if (len < pos + 8)
        {
            free(frame);
            return NULL;
        }
        frame->payload_len = 0;
        for (int i = 0; i < 8; i++)
            frame->payload_len = (frame->payload_len << 8) | data[pos + i];
        pos += 8;
    }
    if (frame->mask)
    {
        if (len < pos + 4)
        {
            free(frame);
            return NULL;
        }
        memcpy(frame->masking_key, data + pos, 4);
        pos += 4;
    }
    if (len < pos + frame->payload_len)
    {
        free(frame);
        return NULL;
    }

    frame->payload = malloc(frame->payload_len + 1);
    if (!frame->payload)
    {
        free(frame);
        return NULL;
    }

    // Unmask payload if masked
    if (frame->mask)
    {
        for (uint64_t i = 0; i < frame->payload_len; i++)
            frame->payload[i] = data[pos + i] ^ frame->masking_key[i % 4];
    }
    else
    {
        memcpy(frame->payload, data + pos, frame->payload_len);
    }

    frame->payload[frame->payload_len] = '\0';

    return frame;
}
int ws_send_frame(socket_t fd, SSL *ssl, ws_opcode_t opcode, const char *payload, size_t len)
{
    (void)fd;
    uint8_t header[10];
    size_t header_len = 0;

    // First byte: FIN=1, RSV=0, Opcode
    header[0] = 0x80 | opcode;
    header_len++;

    // Second byte: MASK=0 (server to client), Payload length
    if (len < 126)
    {
        header[1] = len;
        header_len++;
    }
    else if (len < 65536)
    {
        header[1] = 126;
        header[2] = (len >> 8) & 0xFF;
        header[3] = len & 0xFF;
        header_len += 3;
    }
    else
    {
        header[1] = 127;
        for (int i = 7; i >= 0; i--)
        {
            header[2 + (7 - i)] = (len >> (i * 8)) & 0xFF;
        }
        header_len += 9;
    }

    // Send header
    if (SSL_write(ssl, header, header_len) < 0)
        return -1;

    // Send payload
    if (len > 0 && SSL_write(ssl, payload, len) < 0)
        return -1;

    return 0;
}
void ws_free_frame(ws_frame_t *frame)
{
    if (frame)
    {
        if (frame->payload)
            free(frame->payload);
        free(frame);
    }
}
void ws_broadcast_message(const char *message, socket_t sender_fd)
{
    pthread_mutex_lock(&client_mutex);

    Client *current = clients;
    while (current != NULL)
    {
        // Don't send back to sender
        if (current->fd != sender_fd)
        {
            if (ws_send_frame(current->fd, current->ssl, WS_OPCODE_TEXT, message, strlen(message)) < 0)
            {
                fprintf(stderr, "Failed to send message to client %d\n", current->fd);
            }
        }
        current = current->next;
    }

    pthread_mutex_unlock(&client_mutex);
}

void *ws_handle_client(void *arg)
{
    socket_wrapper_t *wrapper = (socket_wrapper_t *)arg;
    socket_t client_fd = wrapper->fd;
    SSL *ssl = wrapper->ssl;
    free(wrapper);

    char buffer[BUFFER_SIZE];
    ssize_t bytes_read;

    // Read initial handshake request
    bytes_read = SSL_read(ssl, buffer, BUFFER_SIZE - 1);
    if (bytes_read <= 0)
    {
        fprintf(stderr, "Failed to read handshake from client %d\n", client_fd);
        SSL_shutdown(ssl);
        SSL_free(ssl);
        close(client_fd);
        return NULL;
    }
    buffer[bytes_read] = '\0';

    // Check if it's a WebSocket upgrade request
    if (strstr(buffer, "Upgrade: websocket") == NULL)
    {
        fprintf(stderr, "Not a WebSocket upgrade request\n");
        close(client_fd);
        return NULL;
    }

    // Perform handshake
    if (ws_handshake(client_fd, ssl, buffer) < 0)
    {
        fprintf(stderr, "WebSocket handshake failed for client %d\n", client_fd);
        close(client_fd);
        return NULL;
    }

    // Add client to global list
    static int client_id_counter = 1;
    int client_id = client_id_counter++;
    add_client_for_websock(client_fd, client_id, ssl);

    printf("Client %d connected (fd: %d)\n", client_id, client_fd);

    // Send welcome message
    char welcome[256];
    snprintf(welcome, sizeof(welcome),
             "{\"type\":\"system\",\"message\":\"Welcome! You are client #%d\"}",
             client_id);
    ws_send_frame(client_fd, ssl, WS_OPCODE_TEXT, welcome, strlen(welcome));

    char ws_buffer[BUFFER_SIZE];
    // Main message loop
    while (1)
    {
        memset(ws_buffer, 0, sizeof(ws_buffer));
        bytes_read = SSL_read(ssl, buffer, BUFFER_SIZE - 1);

        if (bytes_read <= 0)
        {
            printf("Client %d disconnected\n", client_id);
            break;
        }

        // Parse the frame
        ws_frame_t *frame = ws_parse_frame((uint8_t *)ws_buffer, bytes_read);
        if (!frame)
        {
            fprintf(stderr, "Failed to parse frame from client %d\n", client_id);
            continue;
        }

        // Handle different opcodes
        switch (frame->opcode)
        {
        case WS_OPCODE_TEXT:
            printf("Client %d: %s\n", client_id, frame->payload);

            // Create JSON response with sender info
            cJSON *msg_obj = cJSON_CreateObject();
            cJSON_AddNumberToObject(msg_obj, "sender_id", client_id);
            cJSON_AddStringToObject(msg_obj, "type", "message");
            cJSON_AddStringToObject(msg_obj, "message", frame->payload);
            cJSON_AddNumberToObject(msg_obj, "timestamp", time(NULL));

            char *json_str = cJSON_PrintUnformatted(msg_obj);
            ws_broadcast_message(json_str, client_fd);
            free(json_str);
            cJSON_Delete(msg_obj);
            break;

        case WS_OPCODE_PING:
            // Respond with pong
            ws_send_frame(client_fd, ssl, WS_OPCODE_PONG, frame->payload, frame->payload_len);
            break;

        case WS_OPCODE_CLOSE:
            printf("Client %d requested close\n", client_id);
            ws_send_frame(client_fd, ssl, WS_OPCODE_CLOSE, NULL, 0);
            ws_free_frame(frame);
            goto cleanup;

        default:
            fprintf(stderr, "Unknown opcode %d from client %d\n", frame->opcode, client_id);
        }

        ws_free_frame(frame);
    }

cleanup:
    remove_client_for_websock(client_fd);
    SSL_shutdown(ssl);
    SSL_free(ssl);
    close(client_fd);
    printf("Client %d handler thread exiting\n", client_id);
    return NULL;
}
void handle_pong_response(epoll_client_t *client)
{
    if (!client)
        return;
    time_t now = time(NULL);
    LOG_INFO("received pong from client : %s\n", client->username);
    int rtt_ms = (now - client->ping_pong->last_ping_sent) * 1000;
    // Reset tracking on successful pong
    client->ping_pong->ping_in_flight = 0;
    client->ping_pong->missed_pongs = 0;
    client->ping_pong->last_pong_received = now;

    // Log connection quality
    if (rtt_ms < 50)
        LOG_DEBUG("PONG from %s - Excellent RTT: %dms",
                  client->username, rtt_ms);
    else if (rtt_ms < 200)
        LOG_DEBUG("PONG from %s - Good RTT: %dms",
                  client->username, rtt_ms);
    else if (rtt_ms < 500)
        LOG_WARN("PONG from %s - High latency: %dms",
                 client->username, rtt_ms);
    else
        LOG_WARN("PONG from %s - Very high latency: %dms",
                 client->username, rtt_ms);
    // Update activity for timeout tracker
    timeout_tracker_activity(&client->timeout);
}

int ws_send_ping(epoll_client_t *client)
{
    if (!client || !client->is_websocket || !client->ssl)
        return -1;
    // Don't send if already waiting for a pong
    if (client->ping_pong->ping_in_flight)
    {
        return 0;
    }
    LOG_DEBUG("Sending PING to %s (fd=%d)",
              client->username, client->fd);
    time_t now = time(NULL);
    int ret = ws_send_frame(client->fd, client->ssl, WS_OPCODE_PING, NULL, 0);
    if (ret == 0)
    {
        client->ping_pong->last_ping_sent = now;
        client->ping_pong->missed_pongs++;
        client->ping_pong->ping_in_flight = 1;

        LOG_DEBUG("PING sent to %s (missed: %d/%d)", client->username, client->ping_pong->missed_pongs, MAX_MISSED_PINGS);
    }
    return ret;
}

void ws_check_connection_health(epoll_client_t *clients_list_head)
{
    time_t now = time(NULL);
    epoll_client_t *client = clients_list_head;
    while (client)
    {
        epoll_client_t *next = client->next;
        if (client->is_websocket && client->state == CONN_STATE_WEBSOCKET)
        {
            // -------------------------------------------------
            // DECISION 1: Should we send a ping?
            // -------------------------------------------------
            if (!client->ping_pong->ping_in_flight && (now - client->ping_pong->last_ping_sent) >= PING_INTERVAL)
            {
                if (!ws_send_ping(client))
                {
                    LOG_INFO("Ping request sent to fd = %d , username = %s", client->fd, *(client->username) ? client->username : "Anonymous");
                }
            }
            // -------------------------------------------------
            // DECISION 2: Ping timeout - no pong received?
            // -------------------------------------------------
            else if (client->ping_pong->ping_in_flight && (now - client->ping_pong->last_ping_sent) >= PONG_TIMEOUT)
            {
                LOG_WARN("PONG timeout for %s - missed %d/%d",
                         client->username,
                         client->ping_pong->missed_pongs,
                         MAX_MISSED_PINGS);
                client->ping_pong->ping_in_flight = false;
                // -------------------------------------------------
                // DECISION 3: Too many missed pongs?
                // -------------------------------------------------
                if (client->ping_pong->missed_pongs >= MAX_MISSED_PINGS)
                {
                    LOG_INFO("Client %s DISCONNECTED - missed %d pongs",
                             client->username,
                             client->ping_pong->missed_pongs);
                    // Clean up chat resources
                    remove_epoll_client(client->fd);
                }
            }
            // -------------------------------------------------
            // DECISION 4: Is connection healthy?
            // -------------------------------------------------
            if ((now - client->ping_pong->last_pong_received) < PING_INTERVAL * 2)
            {
                // Got pong in last 60 seconds - healthy
                client->timeout.keepalive_enabled = 1;
            }
        }
        client = next;
    }
}

void ws_send_private_message(const char *from, const char *to, const char *message)
{
    cJSON *root = cJSON_CreateObject();
    cJSON_AddStringToObject(root, "type", "private_message");
    cJSON_AddStringToObject(root, "from", from);
    cJSON_AddStringToObject(root, "message", message);
    cJSON_AddNumberToObject(root, "timestamp", time(NULL));

    char *json_str = cJSON_PrintUnformatted(root);

    epoll_client_t *recipient = find_client_by_username(to);
    if (recipient)
        ws_send_frame(recipient->fd, recipient->ssl, WS_OPCODE_TEXT, json_str, strlen(json_str));
    cJSON_Delete(root);
    free(json_str);
}
void ws_send_private_typing(const char *from, const char *to)
{
    cJSON *root = cJSON_CreateObject();
    cJSON_AddStringToObject(root, "type", "private_typing");
    cJSON_AddStringToObject(root, "from", from);
    char *json_str = cJSON_PrintUnformatted(root);
    epoll_client_t *recipient = find_client_by_username(to);
    if (recipient)
    {
        ws_send_frame(recipient->fd, recipient->ssl, WS_OPCODE_TEXT,
                      json_str, strlen(json_str));
    }

    cJSON_Delete(root);
    free(json_str);
}