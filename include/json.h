#ifndef JSON_H
#define JSON_H

#include <cjson/cJSON.h>
#include <sqlite3.h>
#include <openssl/ssl.h>
typedef int socket_t;
extern sqlite3 *db;

typedef enum
{
    OK,
    CREATED,
    NOT_FOUND,
    NO_CONTENT,
    BAD_REQUEST,
    INTERNAL_SERVER_ERROR,
    UNAUTHORIZED,
    CONFLICT,
} status;

typedef struct
{
    char *json_string;
    status Status;
} JSON_RESPONSE;

JSON_RESPONSE *get_user_info();
JSON_RESPONSE *handle_post_json_for_register(char *buff);
JSON_RESPONSE *handle_post_json_for_login(char *buff);
JSON_RESPONSE *handle_update_current_user(const char*body);
void send_response_back(socket_t fd, SSL *ssl,JSON_RESPONSE *json);
void send_json(socket_t fd,SSL *ssl, int status, const char *status_text, const char *json);
#endif