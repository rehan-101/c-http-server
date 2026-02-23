#include "../include/json.h"
#include "../include/database.h"
#include "../include/server.h"
#include "../include/auth.h"
#include "../include/validation.h"
#include <time.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <unistd.h>
#include <jwt.h>
#include <openssl/rand.h>

void send_response_back(socket_t fd, SSL *ssl, JSON_RESPONSE *json)
{
    switch (json->Status)
    {
    case OK:
        send_json(fd, ssl, 200, "OK", json->json_string);
        break;
    case CREATED:
        send_json(fd, ssl, 201, "CREATED", json->json_string);
        break;
    case NO_CONTENT:
        send_json(fd, ssl, 204, "No content", json->json_string);
        break;
    case NOT_FOUND:
        send_json(fd, ssl, 404, "Not Found", json->json_string);
        break;
    case BAD_REQUEST:
        send_json(fd, ssl, 400, "Bad Request", json->json_string);
        break;
    case UNAUTHORIZED:
        send_json(fd, ssl, 401, "Unauthorized", json->json_string);
        break;
    case CONFLICT:
        send_json(fd, ssl, 409, "CONFLICT", json->json_string);
        break;
    case INTERNAL_SERVER_ERROR:
        send_json(fd, ssl, 500, "server error", json->json_string);
        break;
    }
}

void send_json(socket_t fd, SSL *ssl, int status, const char *status_text, const char *json)
{
    (void)fd;
    char buffer[4096];
    int body_len = strlen(json);

    int len = snprintf(
        buffer, sizeof(buffer),
        "HTTP/1.1 %d %s\r\n"
        "Content-Type: application/json\r\n"
        "Access-Control-Allow-Origin: *\r\n"
        "Access-Control-Allow-Methods: GET, POST, PUT, DELETE, PATCH, OPTIONS\r\n"
        "Access-Control-Allow-Headers: Content-Type, Authorization\r\n"
        "Content-Length: %d\r\n"
        "Connection: close\r\n"
        "\r\n"
        "%s",
        status, status_text, body_len, json);

    if (SSL_write(ssl, buffer, len) < 0)
    {
        perror("SSL_write");
        ERR_print_errors_fp(stderr);
        return;
    }
}

JSON_RESPONSE *get_user_info()
{
    int id = 0;
    char *name, *username, *email;
    name = username = email = NULL;
    JSON_RESPONSE *json_response = (JSON_RESPONSE *)malloc(sizeof(JSON_RESPONSE));
    if (headers_request)
    {
        char *token = get_token(headers_request);
        jwt_t *my_jwt = get_decoded_token(token);
        if (!my_jwt || is_expired(my_jwt, "exp") == 0)
        {
            json_response->json_string = strdup("{\"success\":false,\"message\":\"Session timeout or invalid token. Login again\"}");
            json_response->Status = UNAUTHORIZED;
            if (my_jwt) jwt_free(my_jwt);
            return json_response;
        }
        id = jwt_get_grant_int(my_jwt, "sub");
        sqlite3_stmt *statement = get_query(db, GET_USER_WITH_ID);
        if (!statement)
        {
            fprintf(stderr, "Nothing assigned to sqlite statement...\n");
            json_response->json_string = strdup("{\"success\":false,\"message\": \"Error occurred in database\"}");
            json_response->Status = INTERNAL_SERVER_ERROR;
            jwt_free(my_jwt);
            return json_response;
        }
        else if (sqlite3_bind_int(statement, 1, id) == SQLITE_OK)
        {
            if (sqlite3_step(statement) == SQLITE_ROW)
            {
                id = (int)sqlite3_column_int(statement, 0);
                name = (char *)sqlite3_column_text(statement, 1);
                username = (char *)sqlite3_column_text(statement, 2);
                email = (char *)sqlite3_column_text(statement, 3);
            }
            else
            {
                json_response->json_string = strdup("{\"success\":false,\"message\" : \"No record with the specified id found\"}");
                json_response->Status = NOT_FOUND;
                sqlite3_finalize(statement);
                jwt_free(my_jwt);
                return json_response;
            }
        }
        else
        {
            json_response->json_string = strdup("{\"success\":false,\"message\": \"Error occurred in database\"}");
            json_response->Status = INTERNAL_SERVER_ERROR;
            sqlite3_finalize(statement);
            jwt_free(my_jwt);
            return json_response;
        }
        cJSON *obj = cJSON_CreateObject();
        cJSON_AddNumberToObject(obj, "id", id);
        cJSON_AddStringToObject(obj, "name", name);
        cJSON_AddStringToObject(obj, "username", username);
        cJSON_AddStringToObject(obj, "email", email);

        json_response->json_string = cJSON_PrintUnformatted(obj);
        json_response->Status = OK;
        sqlite3_finalize(statement);
        cJSON_Delete(obj);
        jwt_free(my_jwt);
    }
    return json_response;
}

JSON_RESPONSE *handle_post_json_for_register(char *buff)
{
    JSON_RESPONSE *json = (JSON_RESPONSE *)malloc(sizeof(JSON_RESPONSE));
    if (!json)
    {
        fprintf(stderr, "Failed to allocate JSON_RESPONSE structure..Quitting");
        return NULL;
    }
    sqlite3_stmt *statement = get_query(db, QUERY_FOR_POST_REGISTER);
    if (!statement)
    {
        fprintf(stderr, "Nothing assigned to sqlite statement...\n");
        json->json_string = strdup("{\"success\":false,\"error\":\"Internal Server error\"}");
        json->Status = INTERNAL_SERVER_ERROR;
        return json;
    }
    cJSON *data = cJSON_Parse(buff);
    if (!data)
    {
        json->json_string = strdup("{\"success\":false,\"error\":\"Invalid JSON\"}");
        json->Status = BAD_REQUEST;
        sqlite3_finalize(statement);
        return json;
    }

    cJSON *item_name = cJSON_GetObjectItemCaseSensitive(data, "name");
    cJSON *item_username = cJSON_GetObjectItemCaseSensitive(data, "username");
    cJSON *item_email = cJSON_GetObjectItemCaseSensitive(data, "email");
    cJSON *item_password = cJSON_GetObjectItemCaseSensitive(data, "password");

    if (!cJSON_IsString(item_name) || !cJSON_IsString(item_email) || !cJSON_IsString(item_password) || !cJSON_IsString(item_username))
    {
        json->json_string = strdup("{\"success\":false,\"error\":\"Missing or invalid fields\"}");
        json->Status = BAD_REQUEST;
        cJSON_Delete(data);
        sqlite3_finalize(statement);
        return json;
    }

    char *name = item_name->valuestring;
    char *username = item_username->valuestring;
    char *email = item_email->valuestring;
    char *password = item_password->valuestring;

    if (!validate_username(username))
    {
        json->json_string = strdup("{\"success\":false,\"error\":\"Invalid username format (3-32 chars, alphanumeric + underscore)\"}");
        json->Status = BAD_REQUEST;
        cJSON_Delete(data);
        sqlite3_finalize(statement);
        return json;
    }

    if (!validate_email(email))
    {
        json->json_string = strdup("{\"success\":false,\"error\":\"Invalid email format\"}");
        json->Status = BAD_REQUEST;
        cJSON_Delete(data);
        sqlite3_finalize(statement);
        return json;
    }

    if (!validate_password(password))
    {
        json->json_string = strdup("{\"success\":false,\"error\":\"Password must be 8-128 chars with uppercase, lowercase, digit, and special char\"}");
        json->Status = BAD_REQUEST;
        cJSON_Delete(data);
        sqlite3_finalize(statement);
        return json;
    }

    char salt[SALT_LEN];
    char new_hashed_password[HASH_LEN];

    if (!RAND_bytes((unsigned char *)salt, SALT_LEN))
    {
        fprintf(stderr, "Failed to generate salt\n");
        cJSON_Delete(data);
        json->json_string = strdup("{\"success\":false,\"error\":\"Internal Server Error\"}");
        json->Status = INTERNAL_SERVER_ERROR;
        sqlite3_finalize(statement);
        return json;
    }

    if (make_hashed_password(password, new_hashed_password, salt) != 0)
    {
        fprintf(stderr, "Password hashing failed");
        cJSON_Delete(data);
        json->json_string = strdup("{\"success\":false,\"error\":\"Internal Server error\"}");
        json->Status = INTERNAL_SERVER_ERROR;
        sqlite3_finalize(statement);
        return json;
    }

    if (sqlite3_bind_text(statement, 1, name, -1, SQLITE_STATIC) == SQLITE_OK &&
        sqlite3_bind_text(statement, 2, username, -1, SQLITE_STATIC) == SQLITE_OK &&
        sqlite3_bind_text(statement, 3, email, -1, SQLITE_STATIC) == SQLITE_OK &&
        sqlite3_bind_blob(statement, 4, new_hashed_password, HASH_LEN, SQLITE_STATIC) == SQLITE_OK &&
        sqlite3_bind_blob(statement, 5, salt, SALT_LEN, SQLITE_STATIC) == SQLITE_OK)
    {
        int result = sqlite3_step(statement);
        if (result == SQLITE_DONE)
        {
            json->json_string = strdup("{\"success\":true,\"message\":\"User created successfully\"}");
            json->Status = CREATED;
        }
        else if (result == SQLITE_CONSTRAINT)
        {
            const char *errmsg = sqlite3_errmsg(db);
            if (strstr(errmsg, "User.email"))
            {
                json->json_string = strdup("{\"success\":false,\"error\":\"Email already exists\"}");
                json->Status = CONFLICT;
            }
            else if (strstr(errmsg, "User.username"))
            {
                json->json_string = strdup("{\"success\":false,\"error\":\"Username already exists\"}");
                json->Status = CONFLICT;
            }
            else
            {
                json->json_string = strdup("{\"success\":false,\"error\":\"Constraint violation\"}");
                json->Status = CONFLICT;
            }
        }
    }
    else
    {
        json->json_string = strdup("{\"success\":false,\"error\":\"Internal Server error\"}");
        json->Status = INTERNAL_SERVER_ERROR;
    }

    sqlite3_finalize(statement);
    cJSON_Delete(data);
    return json;
}

static int constant_time_memcmp(const void *a, const void *b, size_t len)
{
    const unsigned char *x = (const unsigned char *)a;
    const unsigned char *y = (const unsigned char *)b;
    int result = 0;
    for (size_t i = 0; i < len; i++)
    {
        result |= x[i] ^ y[i];
    }
    return result;
}

JSON_RESPONSE *handle_post_json_for_login(char *body)
{
    JSON_RESPONSE *json = (JSON_RESPONSE *)malloc(sizeof(JSON_RESPONSE));
    sqlite3_stmt *statement = get_query(db, GET_USER_WITH_NAME);
    if (!statement)
    {
        json->json_string = strdup("{\"success\":false,\"error\":\"Internal Server error\"}");
        json->Status = INTERNAL_SERVER_ERROR;
        return json;
    }
    cJSON *data = cJSON_Parse(body);
    if (!data)
    {
        json->json_string = strdup("{\"success\":false,\"error\":\"Invalid JSON body\"}");
        json->Status = BAD_REQUEST;
        sqlite3_finalize(statement);
        return json;
    }
    cJSON *item_username = cJSON_GetObjectItemCaseSensitive(data, "username");
    cJSON *item_password = cJSON_GetObjectItemCaseSensitive(data, "password");

    if (!item_username || !item_password || !cJSON_IsString(item_username) || !cJSON_IsString(item_password))
    {
        json->json_string = strdup("{\"success\":false,\"error\":\"Missing or invalid fields\"}");
        json->Status = BAD_REQUEST;
        cJSON_Delete(data);
        sqlite3_finalize(statement);
        return json;
    }

    int id = 0;
    const void *stored_password = NULL, *stored_salt = NULL;
    char hashed_password[HASH_LEN];

    if (sqlite3_bind_text(statement, 1, item_username->valuestring, -1, SQLITE_STATIC) == SQLITE_OK)
    {
        if (sqlite3_step(statement) == SQLITE_ROW)
        {
            id = sqlite3_column_int(statement, 0);
            stored_password = sqlite3_column_blob(statement, 1);
            stored_salt = sqlite3_column_blob(statement, 2);

            if (stored_salt && make_hashed_password(item_password->valuestring, hashed_password, stored_salt) == 0)
            {
                if (constant_time_memcmp(hashed_password, stored_password, HASH_LEN) == 0)
                {
                    const char *jwt_secret = getenv("SECRET_KEY");
                    if (!jwt_secret) jwt_secret = "default_secret_key_change_me_in_prod";
                    
                    jwt_t *my_jwt;
                    jwt_new(&my_jwt);
                    jwt_set_alg(my_jwt, JWT_ALG_HS256, (const unsigned char *)jwt_secret, strlen(jwt_secret));
                    jwt_add_grant_int(my_jwt, "sub", id);
                    jwt_add_grant(my_jwt, "username", item_username->valuestring);
                    time_t NOW = time(NULL);
                    jwt_add_grant_int(my_jwt, "iat", NOW);
                    jwt_add_grant_int(my_jwt, "exp", NOW + 3600);

                    char *token = jwt_encode_str(my_jwt);
                    char json_message[1024];
                    snprintf(json_message, sizeof(json_message), "{\"success\":true,\"message\":\"Login successful\",\"data\":{\"token\":\"%s\"}}", token);
                    json->json_string = strdup(json_message);
                    json->Status = OK;
                    
                    jwt_free(my_jwt);
                    free(token);
                    cJSON_Delete(data);
                    sqlite3_finalize(statement);
                    return json;
                }
            }
        }
    }

    json->json_string = strdup("{\"success\":false,\"error\":\"Invalid username or password\"}");
    json->Status = UNAUTHORIZED;
    cJSON_Delete(data);
    sqlite3_finalize(statement);
    return json;
}

JSON_RESPONSE *handle_update_current_user(const char *body)
{
    JSON_RESPONSE *json_response = (JSON_RESPONSE *)malloc(sizeof(JSON_RESPONSE));
    if (headers_request)
    {
        char *token = get_token(headers_request);
        jwt_t *my_jwt = get_decoded_token(token);
        if (!my_jwt || is_expired(my_jwt, "exp") == 0)
        {
            json_response->json_string = strdup("{\"success\":false,\"message\":\"Session timeout or invalid token\"}");
            json_response->Status = UNAUTHORIZED;
            if (my_jwt) jwt_free(my_jwt);
            return json_response;
        }
        int id = jwt_get_grant_int(my_jwt, "sub");
        cJSON *data = cJSON_Parse(body);
        if (!data)
        {
            json_response->json_string = strdup("{\"success\":false,\"error\":\"Invalid JSON\"}");
            json_response->Status = BAD_REQUEST;
            jwt_free(my_jwt);
            return json_response;
        }
        
        cJSON *item_name = cJSON_GetObjectItemCaseSensitive(data, "name");
        cJSON *item_email = cJSON_GetObjectItemCaseSensitive(data, "email");
        
        if (!item_name && !item_email)
        {
            json_response->json_string = strdup("{\"success\":false,\"error\":\"No fields to update\"}");
            json_response->Status = BAD_REQUEST;
            cJSON_Delete(data);
            jwt_free(my_jwt);
            return json_response;
        }

        sqlite3_stmt *statement = get_query(db, PUT_USER_WITH_ID);
        if (statement)
        {
            sqlite3_bind_text(statement, 1, item_name ? item_name->valuestring : NULL, -1, SQLITE_STATIC);
            sqlite3_bind_text(statement, 2, item_email ? item_email->valuestring : NULL, -1, SQLITE_STATIC);
            sqlite3_bind_int(statement, 3, id);
            
            if (sqlite3_step(statement) == SQLITE_DONE)
            {
                json_response->json_string = strdup("{\"success\":true,\"message\":\"Profile updated successfully\"}");
                json_response->Status = OK;
            }
            else
            {
                json_response->json_string = strdup("{\"success\":false,\"error\":\"Database update failed\"}");
                json_response->Status = INTERNAL_SERVER_ERROR;
            }
            sqlite3_finalize(statement);
        }
        cJSON_Delete(data);
        jwt_free(my_jwt);
        return json_response;
    }
    
    json_response->json_string = strdup("{\"success\":false,\"message\":\"Unauthorized\"}");
    json_response->Status = UNAUTHORIZED;
    return json_response;
}