#include "../include/database.h"
#include <string.h>
sqlite3 *db = NULL;
sqlite3 *start_db()
{
    char *err_msg = NULL;
    int result = sqlite3_open("/home/rehan_syed/http_server/users.db", &db);
    if (result != SQLITE_OK)
    {
        fprintf(stderr, "Cannot open the sqlite file..(%s)", sqlite3_errmsg(db));
        sqlite3_close(db);
        return NULL;
    }
    fprintf(stdout, "sQlite initiated successfully...");
    const char *query = "CREATE TABLE IF NOT EXISTS STUDENTS("
                        "id INTEGER PRIMARY KEY,"
                        "name TEXT NOT NULL,"
                        "email TEXT NOT NULL UNIQUE);";

    result = sqlite3_exec(db, query, 0, 0, &err_msg);
    if (result != SQLITE_OK)
    {
        fprintf(stderr, "Table(Students) creation error : %s\n", err_msg);
        sqlite3_free(err_msg);
    }
    else
        fprintf(stdout, "Table(Students) created successfully\n");
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
    "SELECT id,name,email FROM STUDENTS;",
    "SELECT id,name,email FROM STUDENTS WHERE id = ?;",
    "SELECT id,password,salt FROM User WHERE username=?;",
    "INSERT INTO STUDENTS(name,email) VALUES (? , ?);",
    "INSERT INTO STUDENTS(name,email) VALUES (? , ?);",
    "INSERT INTO User(name,username,email,password,salt) VALUES (?,?,?,?,?);",
    "UPDATE STUDENTS SET name = ? , email = ? WHERE id = ?;",
    "DELETE FROM STUDENTS WHERE id = ? RETURNING id,name,email;"};

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