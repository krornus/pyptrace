#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <stdint.h>
#include <unistd.h>

#define SOCKF "/tmp/stack-monitor"
#define INSTR_SIZE 32
#define RECV_SIZE sizeof(void *)

struct mem_op_t {
    uintptr_t length;
    void *effective_addr;
    unsigned char value[];
};

struct instruction_t {
    void *ip;
    void *sp;
    void *bp;
    uintptr_t disassembly_len;
    char *disassembly;
    struct mem_op_t *read;
    struct mem_op_t *read2;
    struct mem_op_t *write;
};

typedef struct instruction_t instruction;
typedef struct mem_op_t mem_op;

instruction *recv_ins(int sock);
mem_op *recv_mem_op(int sock);
int recv_val(int sock, unsigned char *buf, int size);
void print_op(mem_op *op);
void destroy_ins(instruction *ins);
int handle_ins(instruction *ins);
int recv_client(int sock);
int init_server(char *path);

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
        printf("bad exit\n");
        exit(0);
    }


    return len;
}

instruction *recv_ins(int sock)
{
    instruction *ins;
    ins = malloc(sizeof(instruction));

    recv_val(sock, (unsigned char *)&ins->ip, RECV_SIZE);
    recv_val(sock, (unsigned char *)&ins->sp, RECV_SIZE);
    recv_val(sock, (unsigned char *)&ins->bp, RECV_SIZE);
    recv_val(sock, (unsigned char *)&ins->disassembly_len, RECV_SIZE);

    if(ins->disassembly_len > 0){
        ins->disassembly = (char *)malloc(ins->disassembly_len * sizeof(char *));
        recv_val(sock, (unsigned char *)ins->disassembly, ins->disassembly_len);
    }
    printf("received disasm len %lu (%s)\n", ins->disassembly_len, ins->disassembly);

    ins->write = recv_mem_op(sock);
    ins->read  = recv_mem_op(sock); 
    ins->read2  = recv_mem_op(sock); 

    return ins;
}

mem_op *recv_mem_op(int sock)
{
    mem_op *op;
    uintptr_t size;

    recv(sock, &size, RECV_SIZE, 0);

    if(size > 0)
    {
        op = (mem_op *)malloc(sizeof(mem_op)+size);
        op->length = size;

        recv(sock, &op->effective_addr, RECV_SIZE, 0);
        recv(sock, op->value, op->length, 0);


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


int handle_ins(instruction *ins)
{
    /* simulate the stack on heap */
    /* map stack addrs to heap addrs */

    if (NULL != ins->read
            && (uintptr_t)ins->ip < 0x600000000000
            && ins->sp <= ins->bp) {
        printf("%p:\n\tREAD: ", ins->ip);
        print_op(ins->read);
        printf("\n");
    }
    if (NULL != ins->write
            && (uintptr_t)ins->ip < 0x600000000000
            && ins->sp <= ins->bp) {
        printf("%p:\n\tWRITE: ", ins->ip);
        print_op(ins->write);
        printf("\n");
    }


    
    return 0;
}


void print_op(mem_op *op)
{
    if(NULL == op)
        return;
        
    printf("%p [", op->effective_addr);
    for(int i = 0; i < op->length; i++)
    {
        printf("%02x, ", op->value[i]);
    }

    printf("\b\b] (0x");
    int start = 0;
    for(int i = op->length - 1; i >= 0; i--)
    {
        if(!start && !op->value[i])
            continue;
        else if(!start)
            start = 1;
        if(start)
            printf("%02x", op->value[i]);
    }
    if(!start)
        printf("0");
    printf(")");
}

int recv_client(int sock)
{
    struct sockaddr_un remote;
    unsigned int remsize, client_sock;

    remsize = sizeof(remote);
    if ((client_sock = accept(sock, (struct sockaddr *)&remote, &remsize)) == -1) 
    {
        perror("accept");
        exit(1);
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
        exit(1);
    }

    local.sun_family = AF_UNIX;
    strcpy(local.sun_path, path);

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

    return sockfd;
}


int main(int argc, char **argv)
{
    int sockfd;

    sockfd = init_server(SOCKF);
    while(1)
    {
        int csock;
        instruction *ins;
        uintptr_t ip;

        csock = recv_client(sockfd);
        ins = recv_ins(csock);
        ip = (uintptr_t)ins->ip;
        while(ip != (uintptr_t)-1)
        {
            handle_ins(ins);
            destroy_ins(ins);

            ins = recv_ins(csock);
            ip = (uintptr_t)ins->ip;
        } 

        close(csock);
    }

    return 0;
}

