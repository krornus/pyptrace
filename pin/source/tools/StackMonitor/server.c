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


#define MAX_OP_VALUE_SIZE 2048
#define MAX_DISASS_LENGTH 1024

struct mem_op_t {
    uintptr_t length;
    void *effective_addr;
    unsigned char value[MAX_OP_VALUE_SIZE];
};

struct instruction_t {
    void *ip;
    void *sp;
    void *bp;
    uintptr_t disassembly_len;
    char disassembly[MAX_DISASS_LENGTH];
    struct mem_op_t *read;
    struct mem_op_t *read2;
    struct mem_op_t *write;
};

typedef struct instruction_t instruction;
typedef struct mem_op_t mem_op;

void recv_ins(int sock, instruction *ins);
int recv_mem_op(int sock, mem_op *op);
int recv_val(int sock, unsigned char *buf, int size);
void print_op(mem_op *op);
void destroy_ins(instruction *ins);
int handle_ins(instruction *ins);
int recv_client(int sock);
int init_server(char *path);


int recv_val(int sock, unsigned char *buf, int size)
{
    int len;
    errno = 0;
    if((len=recv(sock, buf, size, 0)) == 0) {
        printf("no data received\n");
        exit(-1);
    }

    if(errno != 0) {
        printf("recv addr: %p\n", buf);
        perror("recv()");
    }
}

void recv_ins(int sock, instruction *ins)
{

    recv_val(sock, (unsigned char *)&ins->ip, RECV_SIZE);
    recv_val(sock, (unsigned char *)&ins->sp, RECV_SIZE);
    recv_val(sock, (unsigned char *)&ins->bp, RECV_SIZE);
    recv_val(sock, (unsigned char *)&ins->disassembly_len, RECV_SIZE);

    /* add extra byte for null termination */
    if(ins->disassembly_len > 0 && ins->disassembly_len < MAX_DISASS_LENGTH - 1){
        recv_val(sock, (unsigned char *)ins->disassembly, ins->disassembly_len);
    }
    else if(ins->disassembly_len  >= MAX_DISASS_LENGTH) {
        recv_val(sock, (unsigned char *)ins->disassembly, MAX_DISASS_LENGTH - 2);
    }

    ins->disassembly[ins->disassembly_len] = 0;


    recv_mem_op(sock, ins->write);
    recv_mem_op(sock, ins->read); 
    recv_mem_op(sock, ins->read2); 
}

int recv_mem_op(int sock, mem_op *op)
{
    int status;

    recv(sock, (unsigned char *)&op->length, RECV_SIZE, 0);
    status = 0;

    if(op->length > 0)
    {

        if(op->length > MAX_OP_VALUE_SIZE) {
            printf("\tOP Value overflowed! (%d bytes)\n", op->length);
            op->length = MAX_OP_VALUE_SIZE - 1;
            status = -1;
            exit(-1);
        }
        recv_val(sock, (void *)&op->effective_addr, RECV_SIZE);
        recv_val(sock, (void *)op->value, op->length);
    }
    return status;
}


int handle_ins(instruction *ins)
{
    printf("sizes: %lu %lu %lu\n", 
            ins->write->length, ins->read->length, ins->read2->length);

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
        /* only want to allocate all this once */
        instruction ins;
        mem_op write;
        mem_op read;
        mem_op read2;

        ins.write = &write;
        ins.read = &read;
        ins.read2 = &read2;
        uintptr_t ip;

        csock = recv_client(sockfd);
        recv_ins(csock, &ins);
        while((long int)ins.ip != -1)
        {
            handle_ins(&ins);
            recv_ins(csock, &ins);
        } 
        printf("exited client loop\n");

        close(csock);
    }

    return 0;
}

