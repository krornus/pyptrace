#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

#define SOCKF "/tmp/stack-monitor"
#define INSTR_SIZE 32
#define SEND_SIZE 16

struct mem_op_t {
    int  length;
    void *effective_addr;
    unsigned char value[];
};

struct instruction_t {
    void *ip;
    void *sp;
    void *bp;
    struct mem_op_t *read;
    struct mem_op_t *read2;
    struct mem_op_t *write;
};

typedef struct instruction_t instruction;
typedef struct mem_op_t mem_op;

instruction *recv_ins(int sock);
mem_op *recv_mem_op(int sock);
int recv_val(int sock, unsigned char *buf, int size);
void destroy_ins(instruction *ins);

int recv_val(int sock, unsigned char *buf, int size)
{
    errno = 0;
    int len = 0;
    if((len = recv(sock, buf, size, 0)) < 0 || errno != 0) {
        perror("recv()");
        exit(-1);
    }
    else if(len == 0 && size != 0)
    {
        exit(0);
    }


    return len;
}

instruction *recv_ins(int sock)
{
    instruction *ins;
    ins = malloc(sizeof(instruction));

    recv_val(sock, (char *)&ins->ip, SEND_SIZE);
    recv_val(sock, (char *)&ins->sp, SEND_SIZE);
    recv_val(sock, (char *)&ins->bp, SEND_SIZE);

    ins->write = recv_mem_op(sock);
    ins->read  = recv_mem_op(sock); 
    ins->read2  = recv_mem_op(sock); 

    return ins;
}

mem_op *recv_mem_op(int sock)
{
    char lenbuf[SEND_SIZE];
    char eabuf[SEND_SIZE];
    char *valbuf;

    unsigned int size;

    mem_op *op;

    recv(sock, lenbuf, SEND_SIZE, 0);
    size = (unsigned int)*lenbuf;

    if(size > 0)
    {
        op = (mem_op *)malloc(sizeof(mem_op)+size);
        op->length = size;

        recv(sock, eabuf, SEND_SIZE, 0);
        op->effective_addr = *(void **)eabuf;

        recv(sock, op->value, size, 0);

        return op;
    }
    else
    {
        return NULL;
    }
}

void destroy_ins(instruction *ins)
{
    if(NULL != ins->read)
        free(ins->read);
    if(NULL != ins->write)
        free(ins->write);
    free(ins);
}

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

        instruction *ins;
        do
        {
            ins = recv_ins(client_sock);

            if ((unsigned long)ins->ip < 0x700000000000)
            {
                printf("ip: %p\n", ins->ip);
                printf("\tsp: %p\n", ins->sp);
                printf("\tbp: %p\n", ins->bp);

                if(NULL != ins->write && ins->write->length > 0) {
                    printf("\twrite (%d bytes): %p->%lu\n", 
                        ins->write->length, 
                        ins->write->effective_addr, 
                        (unsigned long)*ins->write->value);
                }
                if(NULL != ins->read && ins->read->length > 0) {
                    printf("\tread (%d bytes): %p->%lu\n", 
                        ins->read->length, 
                        ins->read->effective_addr, 
                        (unsigned long)*ins->read->value);
                }
            }

            destroy_ins(ins);
        } while((long)ins->ip != -1);

        close(client_sock);
    }

    return 0;
}

