#include <stdio.h>
#include <unistd.h>
#include <stdint.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/un.h>
#include "pin.H"

#define SEND_SIZE 16

int init_connection(char *path);
int sockd;

VOID printip(VOID *ip) 
{ 
    if(-1==send(sockd, (VOID *)&ip, 16, 0))
        exit(0);
}

VOID Instruction(INS ins, VOID *v)
{
    INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)printip, IARG_INST_PTR, IARG_END);
}

VOID Fini(INT32 code, VOID *v)
{
    unsigned long i;
    i = -1;
    send(sockd, &i, 16, 0);
    close(sockd);
}

INT32 Usage()
{
    PIN_ERROR("Connects to /tmp/itrace with unix sockets and sends each encountered IP\n" 
              + KNOB_BASE::StringKnobSummary() + "\n");
    return -1;
}

int main(int argc, char *argv[])
{
    char sockfn[] = "/tmp/itrace";
    sockd = init_connection(sockfn);
    
    if(sockd == -1) {
        perror("connect");
        return -1;
    }

    if (PIN_Init(argc, argv)) return Usage();

    INS_AddInstrumentFunction(Instruction, 0);
    PIN_AddFiniFunction(Fini, 0);
    PIN_StartProgram();
    
    return 0;
}

int init_connection(char path[])
{
    int sock;
    struct sockaddr_un remote;

    remote.sun_family = AF_UNIX;
    strncpy(remote.sun_path, path, sizeof(remote.sun_path)-1);

    sock = socket(AF_UNIX, SOCK_STREAM, 0);

    if(connect(sock, (struct sockaddr *)&remote, sizeof(remote)) == -1)
        return -1;

    return sock;
}
