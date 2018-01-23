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

#define INSTRUCTION 1
#define REACCEPT 2

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

int peek_val(int sock, unsigned char *buf, int size)
{
    int status;

    errno = 0;
    status = 0;

    if(recv(sock, buf, size, MSG_PEEK) <= 0 || errno != 0) {
        status = -1;
    }

    return status;
}

int is_new_connection(int sock) {

    uintptr_t flag;
    peek_val(sock, (unsigned char *)&flag, RECV_SIZE);
    switch(flag) {
        case INSTRUCTION:
            return 0;
        case REACCEPT:
            return 1;
    }

    return 0;
}

int next_ins(int sock, instruction *ins)
{
    uintptr_t type;
    uintptr_t flag;

    int status = 0;

    recv_val(sock, (unsigned char *)&flag, RECV_SIZE);

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


    /*
    * PIN IARG_ORDER does not work for NOP ops for an unknown reason
    * have to recv by type until this issue is resolved
    */
    for(int i = 0; i < 3; i++) {
        recv(sock, (unsigned char *)&type, RECV_SIZE, MSG_PEEK);

        switch(type) {
            case SM_WRITE:
                status += recv_mem_op(sock, ins->write);
                break;
            case SM_READ:
                status += recv_mem_op(sock, ins->read);
                break;
            case SM_READ2:
                status += recv_mem_op(sock, ins->read2);
                break;
        }
    }

    return status;
}

int recv_mem_op(int sock, mem_op *op)
{
    int status;

    recv_val(sock, (unsigned char *)&op->type, RECV_SIZE);
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


    printf("received client\n");
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



