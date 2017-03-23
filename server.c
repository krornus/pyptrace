#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <stdint.h>
#include <unistd.h>

#include "server.h"

#define SOCKF "/tmp/stackmonitor"

int recv_val(int sock, unsigned char *buf, int size)
{
    int status;

    errno = 0;
    status = 0;

    if(recv(sock, buf, size, 0) <= 0 || errno != 0) {
        status = -1;
    }

    return status; 
}

int next_ins(int sock, instruction *ins)
{
    int status = 0;

    /* dont want to add another if per recv, status will be 0 or -1 */
    status += recv_val(sock, (unsigned char *)&ins->ip, RECV_SIZE);
    status += recv_val(sock, (unsigned char *)&ins->sp, RECV_SIZE);
    status += recv_val(sock, (unsigned char *)&ins->bp, RECV_SIZE);
    status += recv_val(sock, (unsigned char *)&ins->disassembly_len, RECV_SIZE);

    /* add extra byte for null termination */
    if(ins->disassembly_len  >= MAX_DISASS_LENGTH - 1) {
        fprintf(stderr, "WARNING: Max dissasembly length overflowed! (%lu/%d bytes)\n", 
            ins->disassembly_len, MAX_DISASS_LENGTH);

        ins->disassembly_len = MAX_DISASS_LENGTH - 2;
    }

    status += recv_val(sock, (unsigned char *)ins->disassembly, ins->disassembly_len);

    ins->disassembly[ins->disassembly_len] = 0;

    status += recv_mem_op(sock, ins->write);
    status += recv_mem_op(sock, ins->read); 
    status += recv_mem_op(sock, ins->read2); 

    return status;
}

int recv_mem_op(int sock, mem_op *op)
{
    int status;

    recv_val(sock, (unsigned char *)&op->length, RECV_SIZE);
    status = 0;

    if(op->length > 0)
    {
        if(op->length > MAX_OP_VALUE_SIZE) {
            fprintf(stderr, "WARNING: OP Value overflowed! (%lu/%d bytes)\n", 
                op->length, MAX_OP_VALUE_SIZE);

            op->length = MAX_OP_VALUE_SIZE - 1;
            status = -1;
        }
        recv_val(sock, (void *)&op->effective_addr, RECV_SIZE);
        recv_val(sock, (void *)op->value, op->length);
    }
    return status;
}

int recv_client(int sock)
{
    struct sockaddr_un remote;
    unsigned int remsize, client_sock;

    remsize = sizeof(remote);
    if ((client_sock = accept(sock, (struct sockaddr *)&remote, &remsize)) == -1) 
    {
        perror("accept");
        return -1;
    }

    return client_sock;
}

int init_server(char *path)
{
    struct sockaddr_un local;
    int len, sockfd;

    if ((sockfd = socket(AF_UNIX, SOCK_STREAM, 0)) == -1)
    {
        perror("socket");
        return -1;
    }

    local.sun_family = AF_UNIX;
    strcpy(local.sun_path, path);

    unlink(local.sun_path);

    len = strlen(local.sun_path) + sizeof(local.sun_family);

    if (bind(sockfd, (struct sockaddr *)&local, len) == -1) 
    {
        perror("bind");
        return -1;
    }

    if (listen(sockfd, 1) == -1) 
    {
        perror("listen");
        return -1;
    }

    return sockfd;
}



