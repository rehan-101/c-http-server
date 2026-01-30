#include "../include/server.h"
#include "../include/json.h"
#include "../include/database.h"
#include "../include/websocket.h"
#include <stdio.h>
#include <jwt.h>
#include <string.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/sendfile.h>
#include <sqlite3.h>
#include <pthread.h>

Client *clients = NULL;
pthread_mutex_t client_mutex = PTHREAD_MUTEX_INITIALIZER;
Route routes[] = {
    {.method = GET, .enum_for_uri = {ROOT_URI, URI_USER_INFO, URI_USERS, URI_USERS_WITH_ID, URI_FOR_LOGIN, URI_FOR_REGISTRATION, URI_FOR_PROFILE, URI_FOR_CHAT, 0}, .handler = get_func},
    {.method = POST, .enum_for_uri = {URI_USERS, URI_FOR_REGISTRATION, URI_FOR_LOGIN, 0}, .handler = post_func},
    {.method = PUT, .enum_for_uri = {URI_USERS_WITH_ID, URI_USER_INFO, 0}, .handler = put_func},
    {.method = DELETE, .enum_for_uri = {URI_USERS_WITH_ID, 0}, .handler = delete_func},
    {.method = PATCH, .enum_for_uri = {URI_USERS_WITH_ID, 0}, .handler = patch_func},
};
int no_of_routes = sizeof(routes) / sizeof(routes[0]);
const char *headers_request = NULL; // global pointer for collecting the headers of the request

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

    int opt = 1;
    setsockopt(server_obj.socket_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

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

    /*SSL Initialization*/
    init_openssl();
    server_obj.ssl_ctx = create_ssl_context();
    configure_ssl_context(server_obj.ssl_ctx);

    db = start_db();
    return server_obj;
}

void *thread_func(void *arg)
{
    socket_wrapper_t *wrapper = (socket_wrapper_t *)arg;
    int new_socket = wrapper->fd;
    SSL *ssl = wrapper->ssl;
    free(wrapper);

    /*SSL Handshake is here*/
    if (SSL_accept(ssl) <= 0)
    {
        ERR_print_errors_fp(stderr);
        SSL_free(ssl);
        close(new_socket);
        return NULL;
    }
    char Buffer[BUFFER_SIZE];
    ssize_t bytesRead = SSL_read(ssl, Buffer, BUFFER_SIZE - 1);
    if (bytesRead <= 0)
    {
        if (bytesRead < 0)
            fprintf(stderr, "error in reading bytes");
        SSL_shutdown(ssl);
        SSL_free(ssl);
        close(new_socket);
        return NULL;
    }
    Buffer[bytesRead] = '\0'; // Null terminate the string
    puts(Buffer);
    // === Check for WebSocket upgrade ===
    if (strstr(Buffer, "Upgrade: websocket") != NULL)
    {
        printf("websocket connection detected on socket #%d", new_socket);

        if (ws_handshake(new_socket, ssl, Buffer) < 0)
        {
            fprintf(stderr, "WebSocket handshake failed\n");
            SSL_shutdown(ssl);
            SSL_free(ssl);
            close(new_socket);
            return NULL;
        }
        static int client_id_counter = 1;
        int client_id = client_id_counter++;
        add_client_for_websock(new_socket, client_id, ssl);

        printf("Client %d connected via WebSocket\n", client_id);

        char welcome[256];
        snprintf(welcome, sizeof(welcome),
                 "{\"type\":\"system\",\"message\":\"Welcome! You are client #%d\"}",
                 client_id);
        ws_send_frame(new_socket, ssl, WS_OPCODE_TEXT, welcome, strlen(welcome));
        char ws_buffer[BUFFER_SIZE];
        while (1)
        {
            memset(ws_buffer, 0, sizeof(ws_buffer));
            ssize_t bytes = SSL_read(ssl, ws_buffer, BUFFER_SIZE - 1);

            if (bytes <= 0)
            {
                printf("Client %d disconnected\n", client_id);
                break;
            }

            // Parse WebSocket frame
            ws_frame_t *frame = ws_parse_frame((uint8_t *)ws_buffer, bytes);
            if (!frame)
            {
                fprintf(stderr, "Failed to parse frame from client %d\n", client_id);
                continue;
            }

            // Handle different frame types
            switch (frame->opcode)
            {
            case WS_OPCODE_TEXT:
                printf("Client %d: %s\n", client_id, frame->payload);

                // Create JSON message
                cJSON *msg_obj = cJSON_CreateObject();
                cJSON_AddNumberToObject(msg_obj, "sender_id", client_id);
                cJSON_AddStringToObject(msg_obj, "type", "message");
                cJSON_AddStringToObject(msg_obj, "message", frame->payload);
                cJSON_AddNumberToObject(msg_obj, "timestamp", time(NULL));

                char *json_str = cJSON_PrintUnformatted(msg_obj);
                ws_broadcast_message(json_str, new_socket);

                free(json_str);
                cJSON_Delete(msg_obj);
                break;

            case WS_OPCODE_PING:
                ws_send_frame(new_socket, ssl, WS_OPCODE_PONG, frame->payload, frame->payload_len);
                break;

            case WS_OPCODE_CLOSE:
                printf("Client %d requested close\n", client_id);
                ws_send_frame(new_socket, ssl, WS_OPCODE_CLOSE, NULL, 0);
                ws_free_frame(frame);
                goto ws_cleanup;
            }

            ws_free_frame(frame);
        }

    ws_cleanup:
        remove_client_for_websock(new_socket);
        SSL_shutdown(ssl);
        SSL_free(ssl);
        close(new_socket);
        printf("Client %d handler thread exiting\n", client_id);
        return NULL;
    }
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
                        routes[i].handler(new_socket, ssl, request);
                        goto done;
                    }
                    j++;
                }
            }
        }
        if (method_found && !route_matched)
        {
            send_json(new_socket, ssl, 404, "Not Found",
                      "{\"error\":\"Wrong endpoint for this method\"}");
        }
        else if (!method_found)
        {
            send_json(new_socket, ssl, 405, "Method Not Allowed",
                      "{\"error\":\"Method not supported\"}");
        }
    done:
        clean_things(request->uri, request->header_info->body, request->header_info->content_type, request, NULL);
    }
    else
        fprintf(stdout, "failed to parse reQuest...");
    SSL_shutdown(ssl);
    SSL_free(ssl);
    close(new_socket);
    return NULL;
}

void listening_to_client(socket_t server_fd)
{
    pthread_t my_thread;
    char Buffer[BUFFER_SIZE];
    while (1)
    {
        memset(Buffer, 0, sizeof(Buffer));
        printf("=== WAITING FOR CONNECTION === \n");
        struct sockaddr_in client_addr;
        socklen_t addrlen = sizeof(client_addr);
        int *new_socket = (int *)malloc(sizeof(int));
        if (!new_socket)
        {
            perror("mem alloc. failed..");
            continue;
        }
        *new_socket = accept(server_fd, (struct sockaddr *)&client_addr, &addrlen);
        if (*new_socket < 0)
        {
            perror("accept");
            free(new_socket);
            continue;
        }
        /*Creating SSL wrapper*/
        SSL *ssl = SSL_new(global_ssl_ctx);
        if (ssl == NULL)
        {
            fprintf(stderr, "Error: Failed to create SSL structure\n");
            ERR_print_errors_fp(stderr);
            close(*new_socket); // Close the plain socket since we can't secure it
            free(new_socket);
            continue; // Skip to the next client
        }
        SSL_set_fd(ssl, *new_socket);

        socket_wrapper_t *wrapper = malloc(sizeof(socket_wrapper_t));
        if (!wrapper)
        {
            perror("malloc failed");
            SSL_free(ssl);
            close(*new_socket);
            continue;
        }
        wrapper->fd = *new_socket;
        wrapper->ssl = ssl;

        if (pthread_create(&my_thread, NULL, thread_func, (void *)wrapper) != 0)
        {
            perror("Thread failure");
            SSL_free(ssl);
            close(*new_socket);
            free(new_socket);
            free(wrapper);
            continue;
        }
        fprintf(stdout, "received connection for socket : %d\n", *new_socket);
        pthread_detach(my_thread);
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
    request->enum_for_uri = (strcmp(request->uri, "/") == 0) ? ROOT_URI : (strcmp(request->uri, "/users") == 0)    ? URI_USERS
                                                                      : (strcmp(request->uri, "/me") == 0)         ? URI_USER_INFO
                                                                      : strcmp(request->uri, "/profile") == 0      ? URI_FOR_PROFILE
                                                                      : (strncmp(request->uri, "/users/", 7) == 0) ? ((is_just_id(request->uri + 7)) ? URI_USERS_WITH_ID : URI_UNKNOWN)
                                                                      : (strcmp(request->uri, "/register") == 0)   ? URI_FOR_REGISTRATION
                                                                      : strcmp(request->uri, "/login") == 0        ? URI_FOR_LOGIN
                                                                      : strcmp(request->uri, "/chat") == 0         ? URI_FOR_CHAT
                                                                                                                   : URI_UNKNOWN;
    request->enum_of_method = strcmp(method_string, "GET") == 0 ? GET : (strcmp(method_string, "POST") == 0) ? POST
                                                                    : strcmp(method_string, "PUT") == 0      ? PUT
                                                                    : strcmp(method_string, "DELETE") == 0   ? DELETE
                                                                                                             : PATCH;
    request->header_info = malloc(sizeof(struct info_after_method_line));
    headers_request = get_header(response);
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
void get_func(socket_t fd, SSL *ssl, struct httpRequest *Request)
{
    if (strcmp(Request->uri, "/login") == 0)
        serve_file(fd, ssl, "public/login.html");
    else if (strcmp(Request->uri, "/register") == 0)
        serve_file(fd, ssl, "public/register.html");
    else if (strcmp(Request->uri, "/profile") == 0)
        serve_file(fd, ssl, "public/profile.html");
    else if (strcmp(Request->uri, "/chat") == 0)
        serve_file(fd, ssl, "public/chat.html");
    else
    {
        JSON_RESPONSE *json_body = (JSON_RESPONSE *)handle_get_uri(Request, Request->enum_for_uri);
        if (!json_body)
        {
            JSON_RESPONSE *json_body = (JSON_RESPONSE *)malloc(sizeof(JSON_RESPONSE));
            json_body->json_string = strdup("{\"message\":\"json is not having anything..endpoint entered might be wrong..\"}");
            json_body->Status = INTERNAL_SERVER_ERROR;
        }
        send_response_back(fd, ssl, json_body);
        close(fd);
        clean_things(json_body->json_string, json_body, NULL);
    }
}
void patch_func(socket_t fd, SSL *ssl, struct httpRequest *Request)
{
    JSON_RESPONSE *json_response = NULL;
    json_response = handle_patch_uri(Request->uri, Request->header_info->body);
    if (!json_response)
    {
        json_response = (JSON_RESPONSE *)malloc(sizeof(JSON_RESPONSE));
        json_response->json_string = strdup("\"Message\":\"Nothing received from the server\"");
        json_response->Status = NOT_FOUND;
    }
    send_response_back(fd, ssl, json_response);
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

char *get_header(char *buff)
{
    char *str = strdup(buff);
    char *end_of_header = strstr(str, "\r\n\r\n");
    if (end_of_header)
    {
        int header_len = end_of_header - str;
        int total_len = header_len + strlen("\r\n\r\n");
        char *string_to_be_returned = malloc(total_len + 1);
        if (string_to_be_returned)
        {
            memcpy(string_to_be_returned, str, total_len);
            string_to_be_returned[total_len] = '\0';
            return string_to_be_returned;
        }
    }
    return NULL;
}

void post_func(socket_t client_fd, SSL *ssl, struct httpRequest *post_request)
{
    JSON_RESPONSE *json_response = NULL;
    if (strcmp(post_request->header_info->content_type, "application/json") == 0)
    {
        if (strcmp(post_request->uri, "/users") == 0)
        {
            json_response = handle_post_data_via_json(post_request->header_info->body);
        }
        else if (strcmp(post_request->uri, "/register") == 0)
        {
            json_response = handle_post_json_for_register(post_request->header_info->body);
        }
        else if (strcmp(post_request->uri, "/login") == 0)
        {
            json_response = handle_post_json_for_login(post_request->header_info->body);
        }
        else
        {
            json_response->json_string = strdup("{\"error\" : \"This endpoint is not defined yet\"}");
            json_response->Status = BAD_REQUEST;
        }
    }
    else if (strcmp(post_request->header_info->content_type, "application/x-www-form-urlencoded") == 0)
    {
        json_response = handle_post_data_via_html_form(post_request->header_info->body); // name=Rehan&age=21&email=dewanrehan%40gmail.com -> name=Rehan&age=21&email=dewanrehan06@gmail.com
    }
    else
    {
        json_response = (JSON_RESPONSE *)malloc(sizeof(JSON_RESPONSE));
        json_response->json_string = strdup("{\"message\":\"SOmething wrong has happened\"}");
        json_response->Status = INTERNAL_SERVER_ERROR;
    }
    // Format HTTP response (just like get_func does)
    send_response_back(client_fd, ssl, json_response);
    close(client_fd);                                              // Close the connection
    clean_things(json_response->json_string, json_response, NULL); // Free the allocated JSON string
}
void put_func(socket_t fd, SSL *ssl, struct httpRequest *Request)
{
    JSON_RESPONSE *json = NULL;
    if (strncmp(Request->uri, "/me", 3) == 0)
    {
        // if (is_just_id(Request->uri + 7))
        // {
        //     json = handle_put_with_id(atoi(Request->uri + 7), Request->header_info->body);
        // }
        json = handle_update_current_user((const char *)Request->header_info->body);
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
    send_response_back(fd, ssl, json);
    close(fd);
    clean_things(json->json_string, json, NULL);
}

void delete_func(socket_t fd, SSL *ssl, struct httpRequest *Request)
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
    send_response_back(fd, ssl, json_response);
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
JSON_RESPONSE *handle_get_uri(struct httpRequest *Request, uri_t uri_enum)
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
        json = handle_user_with_id(atoi(Request->uri + 7));
        break;
    case URI_USER_INFO:
        json = get_user_info();
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

int make_hashed_password(char *original_pass, char *hashed_pass, const char *salt)
{
    if (*salt == 0)
    {
        if (!RAND_bytes((unsigned char *)salt, SALT_LEN))
            return -1;
    }
    if (PKCS5_PBKDF2_HMAC((const char *)original_pass,
                          strlen(original_pass),
                          (const unsigned char *)salt,
                          SALT_LEN, ITERATIONS, EVP_sha256(), HASH_LEN,
                          (unsigned char *)hashed_pass) != 1)
        return -1;
    return 0;
}

char *get_token(const char *body)
{
    const char *start = strstr(body, "Authorization: Bearer ");
    if (start)
    {
        start += strlen("Authorization: Bearer ");
        char *end = strstr(start, "\r\n");
        int len = end - start;
        char *token = (char *)malloc(len + 1);
        if (token)
        {
            strncpy(token, start, len);
            token[len] = '\0';
            return token;
        }
        else
            return NULL;
    }
    return NULL;
}

int is_expired(jwt_t *my_jwt, const char *exp)
{
    time_t expiry = jwt_get_grant_int(my_jwt, exp);
    if (expiry < time(NULL))
        return 0;
    return 1;
}

jwt_t *get_decoded_token(char *token)
{
    jwt_t *my_jwt;
    char *secret = getenv("SECRET_KEY");
    size_t sec_len = strlen(secret);
    return (!jwt_decode(&my_jwt, (const char *)token, (const unsigned char *)secret, (int)sec_len)) ? my_jwt : NULL;
}
void serve_file(socket_t fd, SSL *ssl, const char *path)
{
    int file_fd = open(path, O_RDONLY);
    if (file_fd < 0)
        return;

    struct stat st;
    fstat(file_fd, &st);
    off_t file_size = st.st_size;

    char header[256];
    int header_len = sprintf(header, "HTTP/1.1 200 OK\r\n"
                                     "Content-Length: %ld\r\n"
                                     "Content-Type: text/html\r\n\r\n",
                             file_size);
    SSL_write(ssl, header, header_len);

    // Read file in chunks and send via SSL
    char file_buffer[4096];
    ssize_t bytes_read;
    while ((bytes_read = read(file_fd, file_buffer, sizeof(file_buffer))) > 0)
    {
        SSL_write(ssl, file_buffer, bytes_read); // ← CHANGED from sendfile()
    }

    close(file_fd);
}

void add_client_for_websock(socket_t fd, int id, SSL *ssl)
{
    Client *new_client = (Client *)malloc(sizeof(Client));
    if (!new_client)
    {
        fprintf(stderr, "memory allocation failed for Client structure...");
        return;
    }
    new_client->client_id = id;
    new_client->fd = fd;
    new_client->ssl = ssl;
    new_client->next = NULL;
    pthread_mutex_lock(&client_mutex);
    if (clients == NULL)
    {
        clients = new_client;
    }
    else
    {
        Client *temp = clients;
        while (temp->next != NULL)
        {
            temp = temp->next;
        }
        temp->next = new_client;
    }
    pthread_mutex_unlock(&client_mutex);
}

void remove_client_for_websock(socket_t fd)
{
    pthread_mutex_lock(&client_mutex);
    Client *curr = clients, *prev = NULL;
    while (curr != NULL)
    {
        if (curr->fd == fd)
        {
            if (prev == NULL)
                clients = curr->next;
            else
                prev->next = curr->next;
            if (curr->ssl)
            {
                SSL_shutdown(curr->ssl);
                SSL_free(curr->ssl);
            }
            free(curr);
            break;
        }
        prev = curr;
        curr->next = prev->next;
    }
    pthread_mutex_unlock(&client_mutex);
}
void init_openssl()
{
    SSL_load_error_strings();
    OpenSSL_add_ssl_algorithms();
}

void cleanup_openssl()
{
    EVP_cleanup();
}

SSL_CTX *create_ssl_context()
{
    const SSL_METHOD *method;
    SSL_CTX *ctx;

    method = TLS_server_method(); // Use TLS 1.2+
    ctx = SSL_CTX_new(method);
    if (!ctx)
    {
        perror("Unable to create SSL context");
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
    return ctx;
}

void configure_ssl_context(SSL_CTX *ctx)
{
    // Load certificate and private key
    if (SSL_CTX_use_certificate_file(ctx, "src/certs/cert.pem", SSL_FILETYPE_PEM) <= 0)
    {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    if (SSL_CTX_use_PrivateKey_file(ctx, "src/certs/key.pem", SSL_FILETYPE_PEM) <= 0)
    {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    // Verify private key
    if (!SSL_CTX_check_private_key(ctx))
    {
        fprintf(stderr, "Private key does not match the certificate\n");
        exit(EXIT_FAILURE);
    }
}