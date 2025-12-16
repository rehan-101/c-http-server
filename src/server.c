#include "../include/server.h"
#include "../include/json.h"
#include "../include/database.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <sqlite3.h>

Route routes[] = {
    {.method = GET, .enum_for_uri = {ROOT_URI, URI_USERS, URI_USERS_WITH_ID, 0}, .handler = get_func},
    {.method = POST, .enum_for_uri = {URI_USERS, 0}, .handler = post_func},
    {.method = PUT, .enum_for_uri = {URI_USERS_WITH_ID, 0}, .handler = put_func},
    {.method = DELETE, .enum_for_uri = {URI_USERS_WITH_ID, 0}, .handler = delete_func},
    {.method = PATCH, .enum_for_uri = {URI_USERS_WITH_ID, 0}, .handler = patch_func},
};
int no_of_routes = sizeof(routes) / sizeof(routes[0]);

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
    db = start_db();
    return server_obj;
}
void listening_to_client(socket_t server_fd)
{
    char Buffer[BUFFER_SIZE];
    while (1)
    {
        memset(Buffer, 0, sizeof(Buffer));
        printf("=== WAITING FOR CONNECTION === \n");
        struct sockaddr_in client_addr;
        socklen_t addrlen = sizeof(client_addr);
        int new_socket = accept(server_fd, (struct sockaddr *)&client_addr, &addrlen);
        if (new_socket < 0)
        {
            perror("accept");
            continue;
        }
        ssize_t bytesRead = read(new_socket, Buffer, BUFFER_SIZE - 1);
        if (bytesRead <= 0)
        {
            if (bytesRead < 0)
                fprintf(stderr, "error in reading bytes");
            close(new_socket);
            continue;
        }
        Buffer[bytesRead] = '\0'; // Null terminate the string
        puts(Buffer);
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
                            routes[i].handler(new_socket, request);
                            goto done;
                        }
                        j++;
                    }
                }
            }
            if (method_found && !route_matched)
            {
                send_json(new_socket, 404, "Not Found",
                          "{\"error\":\"Wrong endpoint for this method\"}");
            }
            else if (!method_found)
            {
                send_json(new_socket, 405, "Method Not Allowed",
                          "{\"error\":\"Method not supported\"}");
            }
        done:
            clean_things(request->uri, request->header_info->body, request->header_info->content_type, request, NULL);
        }
        else
        {
            fprintf(stdout, "failed to parse reQuest...");
            close(new_socket);
        }
    }
}
struct httpRequest *parse_methods(char *response)
{
    char *method_string = NULL;
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
    char *first_line = strtok(temp_response, "\r\n");
    printf("First Line is : %s\n", first_line);
    char *token = NULL;
    token = strtok(first_line, " ");
    if (token != NULL)
    {
        method_string = strdup(token);
    }
    else
    {
        fprintf(stderr, "Error in tokenization of the the requested string...\n");
        clean_things(temp_response, request, NULL);
        return NULL;
    }
    token = strtok(NULL, " ");
    if (token != NULL)
        request->uri = strdup(token);
    else
    {
        fprintf(stderr, "Error in tokenization\n");
        clean_things(method_string, temp_response, request, NULL);
        return NULL;
    }
    request->enum_for_uri = strcmp(request->uri, "/") == 0 ? ROOT_URI : strcmp(request->uri, "/users") == 0      ? URI_USERS
                                                                    : (strncmp(request->uri, "/users/", 7) == 0) ? (is_just_id(request->uri + 7)) ? URI_USERS_WITH_ID : URI_UNKNOWN
                                                                                                                 : URI_UNKNOWN;
    request->enum_of_method = strcmp(method_string, "GET") == 0 ? GET : (strcmp(method_string, "POST") == 0) ? POST
                                                                    : strcmp(method_string, "PUT") == 0      ? PUT
                                                                    : strcmp(method_string, "DELETE") == 0   ? DELETE
                                                                                                             : PATCH;
    request->header_info = malloc(sizeof(struct info_after_method_line));
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
void get_func(socket_t fd, struct httpRequest *Request)
{
    JSON_RESPONSE *json_body = (JSON_RESPONSE *)handle_get_uri(Request->uri, Request->enum_for_uri);
    send_response_back(fd, json_body);
    if (!json_body)
    {
        JSON_RESPONSE *json_body = (JSON_RESPONSE *)malloc(sizeof(JSON_RESPONSE));
        json_body->json_string = strdup("{\"message\":\"json is not having anything..endpoint entered might be wrong..\"}");
        json_body->Status = INTERNAL_SERVER_ERROR;
        send_response_back(fd, json_body);
    }
    close(fd);
    clean_things(json_body->json_string, json_body, NULL);
}
void patch_func(socket_t fd, struct httpRequest *Request)
{
    JSON_RESPONSE *json_response = NULL;
    json_response = handle_patch_uri(Request->uri, Request->header_info->body);
    if (!json_response)
    {
        json_response = (JSON_RESPONSE *)malloc(sizeof(JSON_RESPONSE));
        json_response->json_string = strdup("\"Message\":\"Nothing received from the server\"");
        json_response->Status = NOT_FOUND;
    }
    send_response_back(fd, json_response);
    close(fd);
    clean_things(json_response->json_string, json_response, NULL);
}
char *get_content_type(char *buff)
{
    if (!buff)
    {
        fprintf(stderr, "Buffer is empty..!\n");
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
        fprintf(stderr, "Buffer is empty..!\n");
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
        fprintf(stderr, "Buffer is empty..!\n");
        return NULL;
    }
    char *body = strstr(buff, "\r\n\r\n");
    if (body)
        body += 4;
    return strdup(body);
}

void post_func(socket_t client_fd, struct httpRequest *post_request)
{
    JSON_RESPONSE *json_response = NULL;
    if (strcmp(post_request->header_info->content_type, "application/json") == 0)
    {
        if (strcmp(post_request->uri, "/users") == 0)
        {
            json_response = handle_post_data_via_json(post_request->header_info->body);
        }
        else
            json_response->json_string = strdup("{\"error\" : \"This endpoint is not defined yet\"}");
        json_response->Status = BAD_REQUEST;
    }
    else if (strcmp(post_request->header_info->content_type, "application/x-www-form-urlencoded") == 0)
    {
        json_response = handle_post_data_via_html_form(post_request->header_info->body); // name=Rehan&age=21&email=dewanrehan%40gmail.com -> name=Rehan&age=21&email=dewanrehan06@gmail.com
    }
    else
    {
        json_response->json_string = strdup("{\"message\":\"SOmething wrong has happened\"}");
        json_response->Status = INTERNAL_SERVER_ERROR;
    }
    // Format HTTP response (just like get_func does)
    send_response_back(client_fd, json_response);
    close(client_fd);                                              // Close the connection
    clean_things(json_response->json_string, json_response, NULL); // Free the allocated JSON string
}
void put_func(socket_t fd, struct httpRequest *Request)
{
    JSON_RESPONSE *json = NULL;
    if (strncmp(Request->uri, "/users/", 7) == 0)
    {
        if (is_just_id(Request->uri + 7))
        {
            json = handle_put_with_id(atoi(Request->uri + 7), Request->header_info->body);
        }
        else
        {
            json = (JSON_RESPONSE *)malloc(sizeof(JSON_RESPONSE));
            if (json)
            {
                json->json_string = strdup("\"message\" : \"invalid uri or endpoint being passed\"");
                json->Status = BAD_REQUEST;
            }
        }
    }
    if (!json)
    {
        json = (JSON_RESPONSE *)malloc(sizeof(JSON_RESPONSE));
        if (json)
        {
            json->json_string = strdup("\"message\" : \"invalid uri or endpoint being passed\"");
            json->Status = BAD_REQUEST;
        }
    }
    send_response_back(fd, json);
    close(fd);
    clean_things(json->json_string, json, NULL);
}

void delete_func(socket_t fd, struct httpRequest *Request)
{
    JSON_RESPONSE *json_response = NULL;
    if (strncmp(Request->uri, "/users/", 7) == 0 && is_just_id(Request->uri + 7))
    {
        json_response = handle_delete_with_id(atoi(Request->uri + 7));
    }
    if (!json_response)
    {
        json_response = (JSON_RESPONSE *)malloc(sizeof(JSON_RESPONSE));
        if (json_response)
        {
            json_response->json_string = strdup("\"Message\" : \"This endpoint is not defined yet\"");
            json_response->Status = BAD_REQUEST;
        }
        else
        {
            fprintf(stderr, "Allocation error in delete_func()");
            return;
        }
    }
    send_response_back(fd, json_response);
    close(fd);
    clean_things(json_response->json_string, json_response, NULL);
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
JSON_RESPONSE *handle_get_uri(const char *uri, uri_t uri_enum)
{
    JSON_RESPONSE *json = NULL;
    switch (uri_enum)
    {
    case ROOT_URI:
        json = handle_get_info();
        break;
    case URI_USERS:
        json = handle_get_users();
        break;
    case URI_USERS_WITH_ID:
        json = handle_user_with_id(atoi(uri + 7));
        break;
    default:
        json = NULL;
    }
    return json;
}

JSON_RESPONSE *handle_patch_uri(const char *uri, const char *body)
{
    JSON_RESPONSE *json = NULL;
    if (strncmp(uri, "/users/", 7) == 0)
    {
        if (is_just_id(uri + 7))
        {
            json = handle_patch_with_id(atoi(uri + 7), body);
        }
    }
    if (!json)
    {
        json = (JSON_RESPONSE *)malloc(sizeof(JSON_RESPONSE));
        json->json_string = strdup("\"message\" : \"format is not /users/{id}\"");
        json->Status = BAD_REQUEST;
    }
    return json;
}