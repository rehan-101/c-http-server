#ifndef JSON_H
#define JSON_H

#include <cjson/cJSON.h>
#include <sqlite3.h>
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
} status;

typedef struct
{
    char *json_string;
    status Status;
} JSON_RESPONSE;

JSON_RESPONSE *handle_get_info();
JSON_RESPONSE *handle_get_users();
JSON_RESPONSE *handle_user_with_id(int id);
JSON_RESPONSE *handle_post_data_via_json(char *buff);
JSON_RESPONSE *handle_post_data_via_html_form(char *buff);
JSON_RESPONSE *handle_put_with_id(int id, const char *body);
char *handle_delete_with_id(int id);
char *handle_patch_with_id(int id, const char *body);
void print_all_the_users();
void send_response_back(socket_t fd, JSON_RESPONSE *json);
void send_json(socket_t fd, int status, const char *status_text, const char *json);
#endif