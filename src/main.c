#include "../include/server.h"
#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>

int main(int argc, char const *argv[])
{
    (void)argc;
    (void)argv;
    struct Server server = server_constructor(AF_INET, 8000, SOCK_STREAM, 0, 10, INADDR_ANY);
    listening_to_client(server.socket_fd);
    return 0;
}
void clean_things(void *first, ...)
{
    va_list args;
    va_start(args, first);
    void *ptr = first;
    while (ptr != NULL)
    {
        printf("freeing pointer : %p\n", ptr);
        free(ptr);
        ptr = va_arg(args, void *);
        printf("Next pointer in the argument list is : %p\n", ptr);
    }
    va_end(args);
}