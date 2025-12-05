#include "server.h"
#include "json.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <unistd.h>

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
    return server_obj;
}

struct httpRequest *parse_methods(char *response)
{
    struct httpRequest *request = (struct httpRequest *)malloc(sizeof(struct httpRequest));
    if (request == NULL)
    {
        perror("request may contain invalid format...");
        exit(EXIT_FAILURE);
    }
    char *temp_response = strdup(response);
    if (!temp_response)
    {
        fprintf(stderr, "Error in duplicating the response string...\n");
        free(request);
        return NULL;
    }
    char *token = NULL;
    token = strtok(temp_response, " ");
    if (token != NULL)
    {
        request->method_string = strdup(token);
    }
    else
    {
        fprintf(stderr, "Error in tokenization of the the requested string...\n");
        clean_things(temp_response, request);
        return NULL;
    }
    token = strtok(NULL, " ");
    if (token != NULL)
        request->uri = strdup(token);
    else
    {
        fprintf(stderr, "Error in tokenization\n");
        clean_things(request->method_string, temp_response, request);
        return NULL;
    }
    if (strcmp(request->method_string, "GET") == 0)
    {
        request->enum_of_method = GET;
        request->func.GET = get_func;
    }
    free(temp_response);
    return request;
}

void get_func(struct Server *server, const char *uri)
{
    char Buffer[BUFFER_SIZE];
    while (1)
    {
        printf("=== WAITING FOR CONNECTION === \n");
        struct sockaddr_in client_addr;
        socklen_t addrlen = sizeof(client_addr);
        int new_socket = accept(server->socket_fd, (struct sockaddr *)&client_addr, &addrlen);
        if (new_socket < 0)
        {
            perror("accept");
            continue;
        }
        ssize_t bytesRead = read(new_socket, Buffer, BUFFER_SIZE - 1);
        if (bytesRead >= 0)
        {
            Buffer[bytesRead] = '\0'; // Null terminate the string
            puts(Buffer);
        }
        else
        {
            perror("Error reading buffer...\n");
        }
        char buffer_2[BUFFER_SIZE];

        const char *json_body = handle_uri(uri);

        int len = snprintf(buffer_2, sizeof(buffer_2), "HTTP/1.1 200 OK\r\n"
                                                       "Content-Type: application/json\r\n"
                                                       "Content-Length: %zu\r\n\r\n"
                                                       "%s",
                           strlen(json_body), json_body);
        write(new_socket, buffer_2, strlen(buffer_2));
        close(new_socket);
        free((void *)json_body);
    }
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
const char *handle_uri(const char *uri)
{
    const char *json = NULL;
    if (strcmp(uri, "/") == 0)
        json = handle_get_info();
    else if (strcmp(uri, "/users") == 0)
        json = handle_get_users();
    else if (strncmp(uri, "/users/", 7) == 0)
    {
        if (is_just_id(uri + 7))
            json = handle_user_with_id(atoi(uri + 7));
    }
    return json;
}