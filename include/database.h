#ifndef DATABASE_H
#define DATABASE_H

#include <sqlite3.h>
#include <stdio.h>
typedef enum
{
    GET_USER_WITH_ID = 0,
    GET_USER_WITH_NAME,
    QUERY_FOR_POST_REGISTER,
    PUT_USER_WITH_ID,
    PATCH_WITH_ID,
    DELETE_WITH_ID,
} Db_Query;

sqlite3 *start_db();
sqlite3_stmt *get_query(sqlite3 *db, Db_Query query);
#endif