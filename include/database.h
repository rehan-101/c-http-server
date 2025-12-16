#ifndef DATABASE_H
#define DATABASE_H

#include <sqlite3.h>
#include <stdio.h>
typedef enum
{
    GET_ALL_USERS = 0,
    GET_USER_WITH_ID,
    QUERY_FOR_POST,
    POST_VIA_FORM_FIELD,
    PUT_USER_WITH_ID,
    DELETE_WITH_ID,
    PATCH_WITH_ID,
} Db_Query;

sqlite3 *start_db();
sqlite3_stmt *get_query(sqlite3 *db, Db_Query query);
#endif