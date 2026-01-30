#include "../include/json.h"
#include "../include/database.h"
#include "../include/server.h"
#include <time.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <unistd.h>
#include <jwt.h>
int number_of_users = 0;
void send_response_back(socket_t fd, SSL *ssl, JSON_RESPONSE *json) // ← ADDED SSL parameter
{
    switch (json->Status)
    {
    case OK:
        send_json(fd, ssl, 200, "OK", json->json_string); // ← ADDED ssl
        break;
    case CREATED:
        send_json(fd, ssl, 201, "CREATED", json->json_string); // ← ADDED ssl
        break;
    case NO_CONTENT:
        send_json(fd, ssl, 204, "No content", json->json_string); // ← ADDED ssl
        break;
    case NOT_FOUND:
        send_json(fd, ssl, 404, "Not Found", json->json_string); // ← ADDED ssl
        break;
    case BAD_REQUEST:
        send_json(fd, ssl, 400, "Bad Request", json->json_string); // ← ADDED ssl
        break;
    case UNAUTHORIZED:
        send_json(fd, ssl, 401, "Unauthorized", json->json_string); // ← ADDED ssl
        break;
    case CONFLICT:
        send_json(fd, ssl, 409, "CONFLICT", json->json_string); // ← ADDED ssl
        break;
    case INTERNAL_SERVER_ERROR:
        send_json(fd, ssl, 500, "server error", json->json_string); // ← ADDED ssl
        break;
    }
}
void send_json(socket_t fd, SSL *ssl, int status, const char *status_text, const char *json)
{
    char buffer[4096];
    int body_len = strlen(json);

    int len = snprintf(
        buffer, sizeof(buffer),
        "HTTP/1.1 %d %s\r\n"
        "Content-Type: application/json\r\n"
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
        if (is_expired(my_jwt, "exp") == 0)
        {
            json_response->json_string = strdup("{\"success\":false,\"message\":session timeout Login again\"}");
            json_response->Status = UNAUTHORIZED;
        }
        id = jwt_get_grant_int(my_jwt, "sub");
        sqlite3_stmt *statement = get_query(db, GET_USER_WITH_ID);
        if (!statement)
        {
            fprintf(stderr, "Nothing assigned to sqlite statement...\n");
            json_response->json_string = strdup("{\"success\":false,\"message\": \"Error occured in database\"}");
            json_response->Status = INTERNAL_SERVER_ERROR;
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
                return json_response;
            }
        }
        else
        {
            json_response->json_string = strdup("{\"success\":false,\"message\": \"Error occured in database\"}");
            json_response->Status = INTERNAL_SERVER_ERROR;
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

JSON_RESPONSE *handle_get_info()
{
    sqlite3_stmt *stmt = NULL;
    cJSON *root = cJSON_CreateObject();
    int id = 0;
    char *name = NULL, *email = NULL;
    JSON_RESPONSE *json = malloc(sizeof(JSON_RESPONSE));

    cJSON_AddStringToObject(root, "status", "ok");
    cJSON_AddStringToObject(root, "server", "HTTP");
    cJSON_AddNumberToObject(root, "time", time(NULL));

    cJSON *client = cJSON_CreateObject();
    cJSON_AddStringToObject(client, "ip", "localhost:8000");
    cJSON_AddStringToObject(client, "Host", "Postman");
    cJSON_AddItemToObject(root, "client", client);

    cJSON *list = cJSON_CreateArray();
    stmt = get_query(db, GET_ALL_USERS);
    if (!stmt)
    {
        cJSON_Delete(root);
        cJSON_Delete(client);
        cJSON_Delete(list);
        fprintf(stderr, "Nothing assigned to sqlite statement...\n");
        json->json_string = strdup("{\"message\": \"Nothing assigned to sqlite statement...\"}");
        json->Status = INTERNAL_SERVER_ERROR;
        return json;
    }
    while (sqlite3_step(stmt) == SQLITE_ROW)
    {
        id = sqlite3_column_int(stmt, 0);
        name = (char *)sqlite3_column_text(stmt, 1);
        email = (char *)sqlite3_column_text(stmt, 2);
        cJSON *obj = cJSON_CreateObject();
        cJSON_AddNumberToObject(obj, "id", id);
        cJSON_AddStringToObject(obj, "Name", name);
        cJSON_AddStringToObject(obj, "email", email);
        cJSON_AddItemToArray(list, obj);
    }
    cJSON_AddItemToObject(root, "users", list);
    cJSON *data = cJSON_CreateObject();
    cJSON_AddStringToObject(data, "messaege", "Hello from GET endpoint");
    cJSON_AddNumberToObject(data, "uptime_seconds", 120);
    cJSON_AddItemToObject(root, "data", data);

    json->json_string = cJSON_PrintUnformatted(root);
    json->Status = OK;
    sqlite3_finalize(stmt);
    cJSON_Delete(root);
    return json;
}

JSON_RESPONSE *handle_get_users()
{
    int id = 0;
    char *name = NULL, *email = NULL;
    JSON_RESPONSE *json = (JSON_RESPONSE *)malloc(sizeof(JSON_RESPONSE));
    sqlite3_stmt *statement = NULL;
    statement = get_query(db, GET_ALL_USERS);
    cJSON *root = cJSON_CreateObject();
    cJSON *list = cJSON_CreateArray();
    if (!statement)
    {
        cJSON_Delete(root);
        cJSON_Delete(list);
        fprintf(stderr, "Nothing assigned to sqlite statement...\n");
        json->json_string = strdup("{\"message\": \"Nothing assigned to sqlite statement...\"}");
        json->Status = INTERNAL_SERVER_ERROR;
        return json;
    }
    while (sqlite3_step(statement) == SQLITE_ROW)
    {
        id = (int)sqlite3_column_int(statement, 0);
        name = (char *)sqlite3_column_text(statement, 1);
        email = (char *)sqlite3_column_text(statement, 2);
        cJSON *obj = cJSON_CreateObject();
        cJSON_AddNumberToObject(obj, "id", id);
        cJSON_AddStringToObject(obj, "Name", name);
        cJSON_AddStringToObject(obj, "email", email);
        cJSON_AddItemToArray(list, obj);
    }
    cJSON_AddItemToObject(root, "users", list);
    json->json_string = cJSON_PrintUnformatted(root);
    json->Status = OK;
    sqlite3_finalize(statement);
    cJSON_Delete(root);
    return json;
}
JSON_RESPONSE *handle_user_with_id(int id)
{
    char *name = NULL, *email = NULL;
    sqlite3_stmt *statement = get_query(db, GET_USER_WITH_ID);
    JSON_RESPONSE *json = (JSON_RESPONSE *)malloc(sizeof(JSON_RESPONSE));
    if (!statement)
    {
        fprintf(stderr, "Nothing assigned to sqlite statement...\n");
        json->json_string = strdup("{\"message\": \"Nothing assigned to sqlite statement...\"}");
        json->Status = INTERNAL_SERVER_ERROR;
    }
    else if (sqlite3_bind_int(statement, 1, id) == SQLITE_OK)
    {
        if (sqlite3_step(statement) == SQLITE_ROW)
        {
            name = (char *)sqlite3_column_text(statement, 1);
            email = (char *)sqlite3_column_text(statement, 2);
        }
        else
        {
            json->json_string = strdup("{\"message\" : \"No record with the specified id found\"}");
            json->Status = NOT_FOUND;
            return json;
        }
    }
    cJSON *obj = cJSON_CreateObject();
    cJSON_AddNumberToObject(obj, "id", id);
    cJSON_AddStringToObject(obj, "name", name);
    cJSON_AddStringToObject(obj, "email", email);

    json->json_string = cJSON_PrintUnformatted(obj);
    json->Status = OK;
    sqlite3_finalize(statement);
    cJSON_Delete(obj);
    return json;
}

JSON_RESPONSE *handle_post_data_via_json(char *buff)
{
    JSON_RESPONSE *json = (JSON_RESPONSE *)malloc(sizeof(JSON_RESPONSE));
    if (!json)
    {
        fprintf(stderr, "Failed to allocate JSON_RESPONSE structure..Quiting");
        return NULL;
    }
    sqlite3_stmt *statement = get_query(db, QUERY_FOR_POST);
    if (!statement)
    {
        fprintf(stderr, "Nothing assigned to sqlite statement...\n");
        json->json_string = strdup("{\"message\": \"Nothing assigned to sqlite statement...\"}");
        json->Status = INTERNAL_SERVER_ERROR;
        return json;
    }
    cJSON *data = cJSON_Parse(buff);
    cJSON *item_name = cJSON_GetObjectItemCaseSensitive(data, "name");
    cJSON *item_email = cJSON_GetObjectItemCaseSensitive(data, "email");
    if (!cJSON_IsString(item_name) || !cJSON_IsString(item_email))
    {
        cJSON_AddNumberToObject(data, "Status", 400);
        cJSON_AddStringToObject(data, "Error", "Bad Request");
        cJSON_AddStringToObject(data, "message", "fields are missin or data enetered in inconsistent");
        json->json_string = cJSON_PrintUnformatted(data);
        json->Status = BAD_REQUEST;
        cJSON_Delete(data);
        return json;
    }
    char *name = item_name->valuestring;
    char *email = item_email->valuestring;
    int result, specific_error = 0;
    if (sqlite3_bind_text(statement, 1, name, -1, SQLITE_STATIC) == SQLITE_OK && sqlite3_bind_text(statement, 2, email, -1, SQLITE_STATIC) == SQLITE_OK)
    {
        result = sqlite3_step(statement);
        if (result == SQLITE_DONE)
        {
            sqlite3_finalize(statement);
            cJSON_Delete(data);
            json->json_string = strdup("{\"status\":\"ok\",\"message\":\"user created/updated\"}");
            json->Status = CREATED;
        }
        else if (result == SQLITE_CONSTRAINT)
        {
            specific_error = sqlite3_extended_errcode(db);
            if (specific_error == SQLITE_CONSTRAINT_UNIQUE)
            {
                sqlite3_finalize(statement);
                cJSON_Delete(data);
                json->json_string = strdup("{\"Error\":\"Email field must be unique\"}");
                json->Status = BAD_REQUEST;
            }
        }
    }
    else
    {
        cJSON_Delete(data);
        json->json_string = strdup("{\"success\":false,\"message\":internal Server error\"}");
        json->Status = INTERNAL_SERVER_ERROR;
    }

    return json;
}
JSON_RESPONSE *handle_post_json_for_register(char *buff)
{
    JSON_RESPONSE *json = (JSON_RESPONSE *)malloc(sizeof(JSON_RESPONSE));
    if (!json)
    {
        fprintf(stderr, "Failed to allocate JSON_RESPONSE structure..Quiting");
        return NULL;
    }
    sqlite3_stmt *statement = get_query(db, QUERY_FOR_POST_REGISTER);
    if (!statement)
    {
        fprintf(stderr, "Nothing assigned to sqlite statement...\n");
        json->json_string = strdup("{\"success\":false,\"error\":internal Server error\"}");
        json->Status = INTERNAL_SERVER_ERROR;
        return json;
    }
    cJSON *data = cJSON_Parse(buff);
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
    char salt[SALT_LEN];
    char new_hashed_password[HASH_LEN];
    int status = make_hashed_password(password, new_hashed_password, salt);
    if (status == 0)
        fprintf(stdout, "Password hashed successflly..Continuing");
    else
    {
        fprintf(stderr, "pass did not bn hashed");
        cJSON_Delete(data);
        json->json_string = strdup("{\"success\":false,\"error\":internal Server error\"}");
        json->Status = INTERNAL_SERVER_ERROR;
        return json;
    }
    int result, specific_error = 0;
    if (sqlite3_bind_text(statement, 1, name, -1, SQLITE_STATIC) == SQLITE_OK &&
        sqlite3_bind_text(statement, 2, username, -1, SQLITE_STATIC) == SQLITE_OK &&
        sqlite3_bind_text(statement, 3, email, -1, SQLITE_STATIC) == SQLITE_OK &&
        sqlite3_bind_blob(statement, 4, new_hashed_password, -1, SQLITE_STATIC) == SQLITE_OK &&
        sqlite3_bind_blob(statement, 5, salt, -1, SQLITE_STATIC) == SQLITE_OK)
    {
        result = sqlite3_step(statement);
        if (result == SQLITE_DONE)
        {
            sqlite3_finalize(statement);
            cJSON_Delete(data);
            json->json_string = strdup("{\"success\":true,\"message\":\"User created successfully\"}");
            json->Status = CREATED;
        }
        else if (result == SQLITE_CONSTRAINT)
        {
            const char *errmsg = sqlite3_errmsg(db);
            specific_error = sqlite3_extended_errcode(db);
            if (specific_error == SQLITE_CONSTRAINT_UNIQUE)
            {
                if (strstr(errmsg, "User.email"))
                {
                    sqlite3_finalize(statement);
                    cJSON_Delete(data);
                    json->json_string = strdup("{\"success\":false,\"error\":\"Email already exists\"}");
                    json->Status = CONFLICT;
                }
                else if (strstr(errmsg, "User.username"))
                {
                    sqlite3_finalize(statement);
                    cJSON_Delete(data);
                    json->json_string = strdup("{\"success\":false,\"error\":\"username already exists\"}");
                    json->Status = CONFLICT;
                }
                else
                {
                    sqlite3_finalize(statement);
                    cJSON_Delete(data);
                    json->json_string = strdup("{\"success\":false,\"error\":\"contraint violation happened\"}");
                    json->Status = CONFLICT;
                }
            }
        }
    }
    else
    {
        sqlite3_finalize(statement);
        cJSON_Delete(data);
        json->json_string = strdup("{\"success\":false,\"error\":internal Server error\"}");
        json->Status = INTERNAL_SERVER_ERROR;
    }
    return json;
}

JSON_RESPONSE *handle_post_json_for_login(char *body)
{
    JSON_RESPONSE *json = (JSON_RESPONSE *)malloc(sizeof(JSON_RESPONSE));
    sqlite3_stmt *statement = get_query(db, GET_USER_WITH_NAME);
    if (!statement)
    {
        json->json_string = strdup("{\"success\":false,\"error\":\"internal Server error\"}");
        json->Status = INTERNAL_SERVER_ERROR;
        return json;
    }
    cJSON *data = cJSON_Parse(body);
    if (!data)
    {
        json->json_string = strdup("{\"success\":false,\"error\":\"Invalid JSON body\"}");
        json->Status = BAD_REQUEST;
        return json;
    }
    cJSON *item_name = cJSON_GetObjectItemCaseSensitive(data, "username");
    cJSON *item_email = cJSON_GetObjectItemCaseSensitive(data, "email");
    cJSON *item_password = cJSON_GetObjectItemCaseSensitive(data, "password");
    int id = 0;
    const void *stored_password, *stored_salt = (void *)0;
    char *password_from_user = item_password->valuestring, hashed_password[HASH_LEN];
    memset(hashed_password, 0, sizeof(hashed_password));
    if ((!cJSON_IsString(item_name) || !cJSON_IsString(item_email)) && !cJSON_IsString(item_password))
    {
        json->json_string = strdup("{\"success\":false,\"error\":\"Fields are incomplete\"}");
        json->Status = BAD_REQUEST;
        return json;
    }
    if (sqlite3_bind_text(statement, 1, item_name->valuestring, -1, SQLITE_STATIC) == SQLITE_OK)
    {
        if (sqlite3_step(statement) == SQLITE_ROW)
        {
            id = sqlite3_column_int(statement, 0);
            stored_password = sqlite3_column_blob(statement, 1);
            stored_salt = sqlite3_column_blob(statement, 2);
        }
        if (stored_salt && make_hashed_password(password_from_user, hashed_password, stored_salt) == 0)
        {
            if (memcmp(hashed_password, stored_password, HASH_LEN) == 0)
            {
                const char *jwt_secret = getenv("SECRET_KEY");
                size_t jwt_secret_len = strlen(jwt_secret);
                jwt_t *my_jwt;
                if (-1 == jwt_new(&my_jwt))
                {
                    fprintf(stderr, "Failed to make jwt instance");
                    json->json_string = strdup("{\"success\":false,\"message\":\"Server error\"}");
                    json->Status = INTERNAL_SERVER_ERROR;
                    return json;
                }
                // header for the JWT
                jwt_set_alg(my_jwt, JWT_ALG_HS256, (const unsigned char *)jwt_secret, jwt_secret_len);
                // payload for the jwt
                jwt_add_grant_int(my_jwt, "sub", id);
                jwt_add_grant(my_jwt, "role", "user");
                time_t NOW = time(NULL);
                jwt_add_grant_int(my_jwt, "iat", NOW);
                jwt_add_grant_int(my_jwt, "exp", NOW + 3600);
                // Generating the final jwt token
                char *token = jwt_encode_str(my_jwt);
                char json_message[1024];
                snprintf(json_message, sizeof(json_message), "{\"success\":true,\"message\":\"Login successful\",\"data\":{\"token\":\"%s\"}}", token);
                json->json_string = strdup(json_message);
                json->Status = OK;
                jwt_free(my_jwt);
                jwt_free_str(token);
            }
        }
        else
        {
            json->json_string = strdup("{\"success\":false,\"error\":\"Invalid email or password\"}");
            json->Status = UNAUTHORIZED;
            cJSON_Delete(data);
            return json;
        }
    }
    return json;
}

char *url_encoded_field(char *val)
{
    char *new_string = val;
    char *string_to_be_returned = new_string;
    while (*val)
    {
        if (*val == '+')
        {
            *new_string++ = ' ';
            val++;
        }
        else if (*val == '%' && isxdigit(val[1]) && isxdigit(val[2]))
        {
            char hex[3] = {val[1], val[2], 0};
            *new_string++ = (char)strtol(hex, NULL, 16);
            val += 3;
        }
        else
            *new_string++ = *val++;
    }
    *new_string = '\0';
    return strdup(string_to_be_returned);
}

// name=Rehan&age=21&email=dewanrehan%40gmail.com
JSON_RESPONSE *handle_post_data_via_html_form(char *buff)
{
    JSON_RESPONSE *json = (JSON_RESPONSE *)malloc(sizeof(JSON_RESPONSE));
    if (!json)
    {
        fprintf(stderr, "JSON_RESPONSE struct was not allocated..Quiting");
        return NULL;
    }
    sqlite3_stmt *statement = get_query(db, POST_VIA_FORM_FIELD);
    char *name = NULL, *email = NULL;
    char *temp = strdup(buff);
    if (!temp)
    {
        if (!statement)
            sqlite3_finalize(statement);
        fprintf(stderr, "error in duplicating the buffer...");
        return NULL;
    }
    char *saveptr1;
    char *pair = strtok_r(temp, "&", &saveptr1);
    while (pair != NULL)
    {
        char *saveptr2;
        char *key = NULL, *value = NULL;
        key = strtok_r(pair, "=", &saveptr2);
        value = strtok_r(NULL, "=", &saveptr2);
        char *decoded_value = url_encoded_field(value);
        if (strcmp(key, "name") == 0)
        {
            name = decoded_value;
        }
        else if (strcmp(key, "email") == 0)
        {
            email = decoded_value;
        }
        pair = strtok_r(NULL, "&", &saveptr1);
    }
    if (sqlite3_bind_text(statement, 1, name, -1, SQLITE_STATIC) == SQLITE_OK && sqlite3_bind_text(statement, 2, email, -1, SQLITE_STATIC) == SQLITE_OK)
    {
        if (sqlite3_step(statement) == SQLITE_DONE)
        {
            json->json_string = strdup("{\"status\":\"ok\",\"message\":\"user created/updated\"}\n");
            json->Status = CREATED;
        }
    }
    else
    {
        json->json_string = strdup("{\"status\":\"not ok\",\"message\":\"user not cretaed in the database\"}\n");
        json->Status = INTERNAL_SERVER_ERROR;
    }
    return json;
}
void print_all_the_users()
{
    sqlite3_stmt *statement = get_query(db, GET_ALL_USERS);
    if (!statement)
    {
        fprintf(stderr, "statement had no wuery inside...");
        return;
    }
    cJSON *root = cJSON_CreateObject();
    cJSON *list = cJSON_CreateArray();

    if (!root || !list)
    {
        fprintf(stderr, "some error occured in print...");
        cJSON_Delete(root);
        cJSON_Delete(list);
    }
    while (sqlite3_step(statement) == SQLITE_ROW)
    {
        cJSON *student = cJSON_CreateObject();

        cJSON_AddNumberToObject(student, "id", (int)sqlite3_column_int(statement, 0));
        cJSON_AddStringToObject(student, "name", (char *)sqlite3_column_text(statement, 1));
        cJSON_AddStringToObject(student, "email", (char *)sqlite3_column_text(statement, 2));

        cJSON_AddItemToArray(list, student);
        number_of_users += 1;
    }
    cJSON_AddItemToObject(root, "students", list);
    cJSON_AddStringToObject(root, "status", "success");
    cJSON_AddNumberToObject(root, "count", number_of_users);
    printf("%s\n", cJSON_PrintUnformatted(root));
}

JSON_RESPONSE *handle_put_with_id(int id, const char *body)
{
    JSON_RESPONSE *json = (JSON_RESPONSE *)malloc(sizeof(JSON_RESPONSE));
    if (!json)
    {
        fprintf(stderr, "JSON_RESPONSE allocation failed..Quiting");
        return NULL;
    }
    sqlite3_stmt *statement = get_query(db, PUT_USER_WITH_ID);
    if (!statement)
    {
        fprintf(stderr, "statement was not populated..");
        json->json_string = strdup("\"message\":\"Something wrong happened in server..statement not executed for put query");
        json->Status = INTERNAL_SERVER_ERROR;
        return json;
    }
    cJSON *data = cJSON_Parse(body);
    cJSON *item_name = cJSON_GetObjectItemCaseSensitive(data, "name");
    cJSON *item_email = cJSON_GetObjectItemCaseSensitive(data, "email");
    if (!item_name && !item_email)
    {
        json->json_string = strdup("\"Error\":\"No field is specified\"");
        json->Status = BAD_REQUEST;
        sqlite3_finalize(statement);
        return json;
    }
    char *name = NULL, *email = NULL;
    name = item_name ? item_name->valuestring : " ";
    email = item_email ? item_email->valuestring : " ";
    sqlite3_bind_text(statement, 1, name, -1, SQLITE_STATIC);
    sqlite3_bind_text(statement, 2, email, -1, SQLITE_STATIC);
    sqlite3_bind_int(statement, 3, id);
    int val = sqlite3_step(statement);
    sqlite3_finalize(statement);
    cJSON_Delete(data);
    if (val != SQLITE_DONE)
    {
        json->json_string = strdup("{\"Error\" : \"SQlite statement for put method never executed\"}");
        json->Status = INTERNAL_SERVER_ERROR;
    }
    else if (sqlite3_changes(db) == 0)
    {
        json->json_string = strdup("{\"Error\" : \"User not found\"}");
        json->Status = NOT_FOUND;
    }
    else
    {
        json->json_string = strdup("{\"message\":\"User updated successfully\"}");
        json->Status = OK;
    }
    return json;
}

JSON_RESPONSE *handle_update_current_user(const char *body)
{
    int id = 0;
    JSON_RESPONSE *json_response = (JSON_RESPONSE *)malloc(sizeof(JSON_RESPONSE));
    if (headers_request)
    {
        char *token = get_token(headers_request);
        jwt_t *my_jwt = get_decoded_token(token);
        if (is_expired(my_jwt, "exp") == 0)
        {
            json_response->json_string = strdup("{\"success\":false,\"message\":session timeout Login again\"}");
            json_response->Status = UNAUTHORIZED;
            return json_response;
        }
        id = jwt_get_grant_int(my_jwt, "sub");
        cJSON *data = cJSON_Parse(body);
        cJSON *item_name = cJSON_GetObjectItemCaseSensitive(data, "name");
        cJSON *item_username = cJSON_GetObjectItemCaseSensitive(data, "username");
        cJSON *item_email = cJSON_GetObjectItemCaseSensitive(data, "email");
        cJSON *item_password = cJSON_GetObjectItemCaseSensitive(data, "password");
        if (!cJSON_IsString(item_name) || !cJSON_IsString(item_email) || !cJSON_IsString(item_password))
        {
            cJSON_AddNumberToObject(data, "Status", 400);
            cJSON_AddStringToObject(data, "Error", "Bad Request");
            cJSON_AddStringToObject(data, "message", "fields are missin or data enetered in inconsistent");
            json_response->json_string = cJSON_PrintUnformatted(data);
            json_response->Status = BAD_REQUEST;
            cJSON_Delete(data);
            return json_response;
        }
        const char *query = NULL;
        sqlite3_stmt *statement = NULL;
        int password_given = 0;
        if (item_password)
        {
            query = "UPDATE User SET name=?,username=?,email=?,password=? WHERE id = ?;";
            password_given = 1;
        }
        else
        {
            query = "UPDATE User SET name=?,username=?,email=? WHERE id = ?;";
        }
        if (sqlite3_prepare_v2(db, query, -1, &statement, NULL) != SQLITE_OK)
        {
            fprintf(stderr, "Nothing assigned to sqlite statement...\n");
            json_response->json_string = strdup("{\"success\":false,\"message\": \"Error occured in database\"}");
            json_response->Status = INTERNAL_SERVER_ERROR;
            return json_response;
        }
        char *name = item_name->valuestring;
        char *username = item_username->valuestring;
        char *email = item_email->valuestring;
        char *password = item_password->valuestring;
        int result, specific_error = 0;
        char salt[SALT_LEN];
        char new_hashed_password[HASH_LEN];
        int status = make_hashed_password(password, new_hashed_password, salt);
        if (status == 0)
            fprintf(stdout, "Password hashed successflly..Continuing");
        else
        {
            fprintf(stderr, "pass did not bn hashed");
            cJSON_Delete(data);
            json_response->json_string = strdup("{\"success\":false,\"error\":internal Server error\"}");
            json_response->Status = INTERNAL_SERVER_ERROR;
            return json_response;
        }
        char *fields[] = {
            name, username, email, "password"};
        for (int i = 1; i < 5; i++)
        {
            if (strcmp(fields[i - 1], "password") == 0)
                result = sqlite3_bind_blob(statement, i, new_hashed_password, -1, SQLITE_STATIC);
            else
                result = (sqlite3_bind_text(statement, i, fields[i - 1], -1, SQLITE_STATIC));
            if (result != SQLITE_OK)
            {
                cJSON_Delete(data);
                json_response->json_string = strdup("{\"success\":false,\"message\":internal Server error\"}");
                json_response->Status = INTERNAL_SERVER_ERROR;
                sqlite3_finalize(statement);
                return json_response;
            }
        }
        sqlite3_bind_int(statement, 5, id);
        if (sqlite3_step(statement) == SQLITE_DONE)
        {
            json_response->json_string = strdup("{\"success\":true,\"message\":\"Updated successfully\"}");
            json_response->Status = CREATED;
        }
        cJSON_Delete(data);
        jwt_free(my_jwt);
        return json_response;
    }
}

JSON_RESPONSE *handle_delete_with_id(int id)
{

    JSON_RESPONSE *json = (JSON_RESPONSE *)malloc(sizeof(JSON_RESPONSE));
    memset(json, 0, sizeof(JSON_RESPONSE));
    if (!json)
    {
        fprintf(stderr, "Memory allocation failed for JSON_RESPONSE in PUT handling function");
        return NULL;
    }
    int count = 0;
    sqlite3_stmt *check_id_stmt;
    if (sqlite3_prepare_v2(db, "SELECT COUNT(id) FROM STUDENTS WHERE id = ?;", -1, &check_id_stmt, NULL) == SQLITE_OK)
    {
        sqlite3_bind_int(check_id_stmt, 1, id);
        if (sqlite3_step(check_id_stmt) == SQLITE_ROW)
        {
            count = sqlite3_column_int(check_id_stmt, 0);
        }
    }
    sqlite3_finalize(check_id_stmt);
    if (count == 0)
    {
        json->json_string = strdup("{\"error\": \"Resource with specified ID not found.\"}");
        json->Status = NOT_FOUND;
        return json;
    }
    sqlite3_stmt *statement = get_query(db, DELETE_WITH_ID);
    if (!statement)
    {
        fprintf(stderr, "Query statement not returned..");
        return NULL;
    }
    cJSON *data = cJSON_CreateObject();
    if (!data)
    {
        sqlite3_finalize(statement);
        fprintf(stderr, "Error in creating data object..\n");
        json->json_string = strdup("\"Error\" : \"Some error in server\"");
        json->Status = INTERNAL_SERVER_ERROR;
        return json;
    }
    if (sqlite3_bind_int(statement, 1, id) == SQLITE_OK)
    {
        if (sqlite3_step(statement) == SQLITE_ROW)
        {
            cJSON_AddNumberToObject(data, "id", (int)sqlite3_column_int(statement, 0));
            cJSON_AddStringToObject(data, "Name", (char *)sqlite3_column_text(statement, 1));
            cJSON_AddStringToObject(data, "Email", (char *)sqlite3_column_text(statement, 2));
            cJSON_AddStringToObject(data, "message", "Deleted_Successfully");
        }
    }
    json->json_string = cJSON_PrintUnformatted(data);
    json->Status = OK;
    sqlite3_finalize(statement);
    cJSON_Delete(data);
    return json;
}
JSON_RESPONSE *handle_patch_with_id(int id, const char *body)
{
    JSON_RESPONSE *json = (JSON_RESPONSE *)malloc(sizeof(JSON_RESPONSE));
    memset(json, 0, sizeof(JSON_RESPONSE));
    if (!json)
    {
        fprintf(stderr, "Memory allocation failed for JSON_RESPONSE in PUT handling function");
        return NULL;
    }
    int count = 0;
    sqlite3_stmt *check_id_stmt;
    if (sqlite3_prepare_v2(db, "SELECT COUNT(id) FROM STUDENTS WHERE id = ?;", -1, &check_id_stmt, NULL) == SQLITE_OK)
    {
        sqlite3_bind_int(check_id_stmt, 1, id);
        if (sqlite3_step(check_id_stmt) == SQLITE_ROW)
        {
            count = sqlite3_column_int(check_id_stmt, 0);
        }
    }
    sqlite3_finalize(check_id_stmt);
    if (count == 0)
    {
        json->json_string = strdup("{\"error\": \"Resource with specified ID not found.\"}");
        json->Status = NOT_FOUND;
        return json;
    }
    sqlite3_stmt *statement;

    cJSON *data = cJSON_Parse(body);
    if (!data)
    {
        json->json_string = strdup("{\"error\":\"Invalid JSON body\"}");
        json->Status = INTERNAL_SERVER_ERROR;
        return json;
    }
    cJSON *item_name = cJSON_GetObjectItemCaseSensitive(data, "name");
    cJSON *item_email = cJSON_GetObjectItemCaseSensitive(data, "email");
    if (!item_name && !item_email)
    {
        json->json_string = strdup("\"error\":\"PUT not allowed for empty fields\"");
        json->Status = INTERNAL_SERVER_ERROR;
        cJSON_Delete(data);
        return json;
    }
    char BUFFER[200] = "UPDATE STUDENTS SET ";
    int found = 0, pos = 1, result;
    if (item_name)
    {
        strcat(BUFFER, "name = ?");
        found = 1;
    }
    if (item_email)
    {
        if (found)
            strcat(BUFFER, ", ");
        strcat(BUFFER, "email = ? ");
    }
    strcat(BUFFER, "WHERE id = ?;");
    result = sqlite3_prepare_v2(db, BUFFER, -1, &statement, NULL);
    if (result != SQLITE_OK)
    {
        cJSON_Delete(data);
        json->json_string = strdup("\"Error\":\"Server faced some internal error\"");
        json->Status = INTERNAL_SERVER_ERROR;
        return json;
    }
    if (item_name)
        sqlite3_bind_text(statement, pos++, item_name->valuestring, -1, SQLITE_STATIC);
    if (item_email)
        sqlite3_bind_text(statement, pos++, item_email->valuestring, -1, SQLITE_STATIC);
    sqlite3_bind_int(statement, pos, id);

    result = sqlite3_step(statement);
    if (result != SQLITE_DONE)
    {
        json->json_string = strdup("{\"Message\":\"Update failed\"}");
        json->Status = INTERNAL_SERVER_ERROR;
    }
    else if (sqlite3_changes(db) > 0)
    {
        json->json_string = strdup("{\"Message\":\"UPDATED the record\"}");
        json->Status = NO_CONTENT;
    }
    sqlite3_finalize(statement);
    cJSON_Delete(data);
    return json;
}