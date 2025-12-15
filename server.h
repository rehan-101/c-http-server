#ifndef SERVER_H
#define SERVER_H

#include <netinet/in.h>
#include <sqlite3.h>
#include "json.h"
extern sqlite3 *db;
typedef int socket_t;
#define BUFFER_SIZE 16000
struct Server;
typedef void (*launch)(struct Server *);
void clean_things(void *, ...);
struct Server
{
    int domain, port, service, protocol, backlog;
    u_long interface;
    socket_t socket_fd;
    struct sockaddr_in address;
    launch Launch_function;
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
    URI_UNKNOWN,
    URI_USERS,
    URI_USERS_WITH_ID,
    ROOT_URI,
} uri_t;
typedef struct
{
    Methods method;
    uri_t enum_for_uri[5];
    void (*handler)(socket_t file_descriptor, struct httpRequest *Request);
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
struct Server
server_constructor(int domain, int port, int service, int protocol, int backlog, u_long interface);
void get_func(socket_t, struct httpRequest *);
void post_func(socket_t client_fd, struct httpRequest *);
void put_func(socket_t client_fd, struct httpRequest *);
void delete_func(socket_t fd, struct httpRequest *);
void patch_func(socket_t fd, struct httpRequest *);
struct httpRequest *parse_methods(char *response);
JSON_RESPONSE *handle_get_uri(const char *uri, uri_t uri_enum);
const char *handle_patch_uri(const char *uri, const char *body);
void listening_to_client(socket_t server_fd);
char *get_content_type(char *buffer);
int get_content_len(char *buffer);
char *get_body(char *buffer);
int is_just_id(const char *uri);
#endif