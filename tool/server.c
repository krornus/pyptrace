#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>
#define SOCKF "/tmp/itrace"
#define INSTR_SIZE 32

int main(int argc, char **argv)
{
    struct sockaddr_un local, remote;
    int len, sockfd;

    if ((sockfd = socket(AF_UNIX, SOCK_STREAM, 0)) == -1)
    {
        perror("socket");
        exit(1);
    }

    local.sun_family = AF_UNIX;
    strcpy(local.sun_path, SOCKF);

    unlink(local.sun_path);

    len = strlen(local.sun_path) + sizeof(local.sun_family);

    if (bind(sockfd, (struct sockaddr *)&local, len) == -1) 
    {
        perror("bind");
        exit(1);
    }

    if (listen(sockfd, 1) == -1) 
    {
        perror("listen");
        exit(1);
    }

    while(1)
    {
        char buf[INSTR_SIZE];
        short func;
        int remsize, client_sock;

        remsize = sizeof(remote);
        if ((client_sock = accept(sockfd, (struct sockaddr *)&remote, &remsize)) == -1) 
        {
            perror("accept");
            exit(1);
        }

        while(*(int *)buf != -1)
        {
            errno = 0;
            if(recv(client_sock, buf, 16, 0) == -1 || errno != 0)
            {
                perror("recv()");
                break;
            }
            printf("%p\n", *(void **)buf);
        }
        close(client_sock);
    }

    return 0;
}
