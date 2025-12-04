#ifndef SERVER_H
#define SERVER_H

#include <netinet/in.h>
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

typedef struct Method_pointers
{
    void (*GET)(struct Server *);
} method_func_pointers;

struct httpRequest
{
    char *method_string, *uri;
    Methods enum_of_method;
    method_func_pointers func;
};

struct Server
server_constructor(int domain, int port, int service, int protocol, int backlog, u_long interface, launch LaunchFunc);
void get_func(struct Server *);
struct httpRequest *parse_methods(char *response);

#endif