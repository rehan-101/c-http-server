#ifndef JSON_H
#define JSON_H

#include <cjson/cJSON.h>

typedef struct User
{
    int id;
    char name[50];
    char email[100];
} User;
extern User User_[];

char *handle_get_info();
char *handle_get_users();
char *handle_user_with_id(int id);
#endif