#include "server.h"
#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>

int main(int argc, char const *argv[])
{
    struct Server server = server_constructor(AF_INET, 8000, SOCK_STREAM, 0, 10, INADDR_ANY);
    struct httpRequest *REQUEST = parse_methods("GET /users/5 HTTP/1.1");
    if (REQUEST != NULL)

        fprintf(stdout, "method = %s , uri = %s \n", REQUEST->method_string, REQUEST->uri);
    else
        clean_things(REQUEST->method_string, REQUEST->uri, REQUEST);

    if (REQUEST->enum_of_method == GET)
        REQUEST->func.GET(&server, REQUEST->uri);

    clean_things(REQUEST->method_string, REQUEST->uri, REQUEST);
    return 0;
}
void clean_things(void *first, ...)
{
    va_list args;
    va_start(args, first);
    void *ptr = first;
    while (ptr != NULL)
    {
        free(ptr);
        ptr = va_arg(args, void *);
    }
    va_end(args);
}