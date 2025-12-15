#include "json.h"
#include "database.h"
#include "server.h"
#include <time.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <unistd.h>
int number_of_users = 0;

void send_response_back(socket_t fd, JSON_RESPONSE *json)
{
    switch (json->Status)
    {
    case OK:
        send_json(fd, 200, "OK", json->json_string);
        break;
    case CREATED:
        send_json(fd, 201, "Created", json->json_string);
        break;
    case NOT_FOUND:
        send_json(fd, 404, "Not Found", json->json_string);
        break;
    case BAD_REQUEST:
        send_json(fd, 400, "Bad Request", json->json_string);
        break;
    case INTERNAL_SERVER_ERROR:
        send_json(fd, 500, "server error", json->json_string);
        break;
    }
}

void send_json(socket_t fd, int status, const char *status_text, const char *json)
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
    if (write(fd, buffer, len) < 0)
    {
        perror("write");
        return;
    }
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
    int new_id;
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
            new_id = (int)sqlite3_column_int(statement, 0);
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
    cJSON *item_id = cJSON_GetObjectItemCaseSensitive(data, "id");
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
    if (sqlite3_bind_text(statement, 1, name, -1, SQLITE_STATIC) == SQLITE_OK && sqlite3_bind_text(statement, 2, email, -1, SQLITE_STATIC) == SQLITE_OK)
    {
        if (sqlite3_step(statement) == SQLITE_DONE)
        {
            cJSON_Delete(data);
            json->json_string = strdup("{\"status\":\"ok\",\"message\":\"user created/updated\"}");
            json->Status = CREATED;
            return json;
        }
    }
    cJSON_Delete(data);
    json->json_string = strdup("\"message\" : \"POST operation failed due to some server issues\"");
    json->Status = INTERNAL_SERVER_ERROR;
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
    int id_number;
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

char *handle_delete_with_id(int id)
{
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
        return strdup("\"Error\" : \"Some error in server\"");
    }
    if (sqlite3_bind_int(statement, 1, id) == SQLITE_OK)
    {
        if (sqlite3_step(statement) == SQLITE_ROW)
        {
            cJSON_AddNumberToObject(data, "id", (int)sqlite3_column_int(statement, 0));
            cJSON_AddStringToObject(data, "Name", (char *)sqlite3_column_text(statement, 1));
            cJSON_AddStringToObject(data, "Email", (char *)sqlite3_column_text(statement, 2));
        }
    }
    cJSON_AddStringToObject(data, "message", "Deleted_Successfully");
    char *str = cJSON_PrintUnformatted(data);
    sqlite3_finalize(statement);
    cJSON_Delete(data);
    return strdup(str);
}
char *handle_patch_with_id(int id, const char *body)
{
    sqlite3_stmt *statement;
    cJSON *data = cJSON_Parse(body);
    cJSON *item_id = cJSON_GetObjectItemCaseSensitive(data, "id");
    cJSON *item_name = cJSON_GetObjectItemCaseSensitive(data, "name");
    cJSON *item_email = cJSON_GetObjectItemCaseSensitive(data, "email");
    char *name, *email;
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
        return strdup("{\"error\":\"Failed to prepare statement\"}");
    }
    if (item_name)
        sqlite3_bind_text(statement, pos++, item_name->valuestring, -1, SQLITE_STATIC);
    if (item_email)
        sqlite3_bind_text(statement, pos++, item_email->valuestring, -1, SQLITE_STATIC);
    sqlite3_bind_int(statement, pos, id);

    result = sqlite3_step(statement);
    sqlite3_finalize(statement);
    cJSON_Delete(data);
    if (result != SQLITE_DONE)
        return strdup("{\"Message\":\"Update failed\"}");
    if (sqlite3_changes(db) > 0)
        return strdup("{\"Message\":\"UPDATED the record\"}");

    return strdup("\"Message\": \"no record with the specified id found\"");
}