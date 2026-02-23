#include "../include/database.h"
#include "../include/config.h"
#include <string.h>
sqlite3 *db = NULL;
sqlite3 *start_db()
{
    char *err_msg = NULL;
    int result = sqlite3_open_v2(g_config.db_path, &db, SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE | SQLITE_OPEN_FULLMUTEX, NULL);
    if (result != SQLITE_OK)
    {
        fprintf(stderr, "Cannot open the sqlite file..(%s)", sqlite3_errmsg(db));
        sqlite3_close(db);
        return NULL;
    }
    fprintf(stdout, "sQlite initiated successfully...");
    result = 0;
    const char *register_user = "CREATE TABLE IF NOT EXISTS User("
                                "id INTEGER PRIMARY KEY,"
                                "name TEXT NOT NULL,"
                                "username TEXT NOT NULL UNIQUE,"
                                "email TEXT NOT NULL UNIQUE,"
                                "password BLOB NOT NULL,"
                                "salt BLOB NOT NULL);";
    result = sqlite3_exec(db, register_user, 0, 0, &err_msg);
    if (result != SQLITE_OK)
    {
        fprintf(stderr, "Table(register_user) creation error : %s\n", err_msg);
        sqlite3_free(err_msg);
    }
    else
        fprintf(stdout, "Table (register_user) created successfully\n");
    return db;
}
const char *const SQL_Queries[] = {
    "SELECT id,name,username,email FROM User WHERE id = ?;",
    "SELECT id,password,salt FROM User WHERE username=?;",
    "INSERT INTO User(name,username,email,password,salt) VALUES (?,?,?,?,?);",
    "UPDATE User SET name = ? , email = ? WHERE id = ?;", // Assuming User update
    "DELETE FROM User WHERE id = ?;"};

#define MAX_QUERIES (sizeof(SQL_Queries) / sizeof(SQL_Queries[0]))
sqlite3_stmt *get_query(sqlite3 *db, Db_Query query)
{
    sqlite3_stmt *statement_query = NULL;
    const char *Query = NULL;
    if (query >= MAX_QUERIES || query < 0)
    {
        fprintf(stderr, "Invlaid Query entered..");
        return NULL;
    }
    Query = SQL_Queries[query];
    if (sqlite3_prepare_v2(db, Query, -1, &statement_query, NULL) != SQLITE_OK)
    {
        fprintf(stderr, "Failed to prepare statement for query type %d (%s) => %s\n", query, Query, sqlite3_errmsg(db));
        return NULL;
    }
    return statement_query;
}