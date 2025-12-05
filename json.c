#include "json.h"
#include <time.h>

User User_[] = {
    {.id = 1, .name = "Rehan", .email = "abc@gmail.com"},
    {2, "Talha", "Talha@gmail.com"},
    {3, "Tayyab", ""},
};
int number_of_users = sizeof(User_) / sizeof(User_[0]);

char *handle_get_info()
{
    cJSON *root = cJSON_CreateObject();

    cJSON_AddStringToObject(root, "status", "ok");
    cJSON_AddStringToObject(root, "server", "HTTP");
    cJSON_AddNumberToObject(root, "time", time(NULL));

    cJSON *client = cJSON_CreateObject();
    cJSON_AddStringToObject(client, "ip", "localhost:8000");
    cJSON_AddStringToObject(client, "Host", "Postman");
    cJSON_AddItemToObject(root, "client", client);

    cJSON *list = cJSON_CreateArray();
    for (int i = 0; i < 3; i++)
    {
        cJSON *obj = cJSON_CreateObject();
        cJSON_AddNumberToObject(obj, "id", User_[i].id);
        cJSON_AddStringToObject(obj, "Name", User_[i].name);
        cJSON_AddStringToObject(obj, "email", User_[i].email);
        cJSON_AddItemToArray(list, obj);
    }
    cJSON_AddItemToObject(root, "users", list);
    cJSON *data = cJSON_CreateObject();
    cJSON_AddStringToObject(data, "messaege", "Hello from GET endpoint");
    cJSON_AddNumberToObject(data, "uptime_seconds", 120);
    cJSON_AddItemToObject(root, "data", data);

    char *json = cJSON_PrintUnformatted(root);
    cJSON_Delete(root);
    return json;
}

char *handle_get_users()
{
    cJSON *root = cJSON_CreateObject();
    cJSON *list = cJSON_CreateArray();
    for (int i = 0; i < 3; i++)
    {
        cJSON *obj = cJSON_CreateObject();
        cJSON_AddNumberToObject(obj, "id", User_[i].id);
        cJSON_AddStringToObject(obj, "Name", User_[i].name);
        cJSON_AddStringToObject(obj, "email", User_[i].email);
        cJSON_AddItemToArray(list, obj);
    }
    cJSON_AddItemToObject(root, "users", list);
    char *json = cJSON_PrintUnformatted(root);
    cJSON_Delete(root);
    return json;
}
char *handle_user_with_id(int id)
{
    cJSON *obj = cJSON_CreateObject();
    char *json;
    int found = 0;
    for (int i = 0; i < number_of_users; i++)
    {
        if (User_[i].id == id)
        {
            found = 1;
            cJSON_AddNumberToObject(obj, "id", User_[i].id);
            cJSON_AddStringToObject(obj, "Name", User_[i].name);
            cJSON_AddStringToObject(obj, "email", User_[i].email);
            json = cJSON_PrintUnformatted(obj);
            break;
        }
    }
    if (!found)
    {
        cJSON_AddStringToObject(obj, "message", "No record with the specified id found");
        json = cJSON_PrintUnformatted(obj);
    }
    cJSON_Delete(obj);
    return json;
}