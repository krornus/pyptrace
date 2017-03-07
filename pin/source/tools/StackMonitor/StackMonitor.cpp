#include <unistd.h>
#include <iostream>
#include "pin.H"

#define SEND_SIZE 16

VOID ShowN(UINT32 n, VOID *ea);
int init_connection(char path[]);


KNOB<string> KnobSocketFile(
	KNOB_MODE_WRITEONCE, "pintool", "s", 
	"/tmp/stack-monitor", "sockfile to use");

int sockd;

INT32 Usage()
{
    cerr <<
        "This tool monitors the stack for changes and sends updates to a UNIX socket\n"
        "\n";
    cerr << KNOB_BASE::StringKnobSummary();
    cerr << endl;

    return -1;
}

VOID StackPtr(VOID * ip, string *out, const CONTEXT * ctxt)
{
    ADDRINT sp = (ADDRINT)PIN_GetContextReg( ctxt, REG_STACK_PTR);
    ADDRINT bp = (ADDRINT)PIN_GetContextReg( ctxt, REG_GBP);

    send(sockd, (VOID *)&ip, SEND_SIZE, 0);
    send(sockd, (VOID *)&sp, SEND_SIZE, 0);
    send(sockd, (VOID *)&bp, SEND_SIZE, 0);

    //cout << ip << ":\n\t" << *out << endl;
    //cout << "\tSP: " << (VOID *)sp << endl;
    //cout << "\tBP: " << (VOID *)bp << endl;
}

VOID StackMemoryOperation(VOID * ea, UINT32 size)
{
    UINT8 *val;

    send(sockd, (VOID *)&size, SEND_SIZE, 0);

    if(size > 0 && NULL != ea)
    {
        send(sockd, (VOID *)&ea, SEND_SIZE, 0);

        val = static_cast<UINT8*>(malloc(sizeof(UINT8) * size));
        PIN_SafeCopy(val, static_cast<UINT8*>(ea), size);
        send(sockd, (VOID *)val, size, 0);
    }

    //cout << "\tREAD: " << ea << ", " << size << " bytes" << endl;
    //cout << "\t\t" << ea << " -> ";
    //ShowN(size, ea);
    //cout << endl;
}

VOID Instruction(INS ins, VOID *val)
{
    string out = "";

    out = INS_Disassemble(ins);
    INS_InsertCall( ins, IPOINT_BEFORE, (AFUNPTR)StackPtr, IARG_INST_PTR, IARG_PTR, new string(out), IARG_CONTEXT, IARG_END);

    if (INS_IsStackWrite(ins))
    {
        INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)StackMemoryOperation, IARG_MEMORYWRITE_EA, IARG_MEMORYWRITE_SIZE, IARG_END);
    }
    else
    {
        INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)StackMemoryOperation, IARG_PTR, 0, IARG_UINT32, 0, IARG_END);
    }

    if (INS_IsStackRead(ins) && INS_IsMemoryRead(ins) && !INS_IsPrefetch(ins) && INS_IsStandardMemop(ins))
    {
        INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)StackMemoryOperation, IARG_MEMORYREAD_EA, IARG_MEMORYREAD_SIZE, IARG_END);
    }
    else
    {
        INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)StackMemoryOperation, IARG_PTR, 0, IARG_UINT32, 0, IARG_END);
    }

    if (INS_IsStackRead(ins) && INS_HasMemoryRead2(ins) && INS_IsStandardMemop(ins))
    {
        INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)StackMemoryOperation, IARG_MEMORYREAD2_EA, IARG_MEMORYREAD_SIZE, IARG_END);
    }
    else
    {
        INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)StackMemoryOperation, IARG_PTR, 0, IARG_UINT32, 0, IARG_END);
    }
}

VOID Finish(int code, VOID *val)
{
    send(sockd, (VOID *)-1, SEND_SIZE, 0);
    send(sockd, (VOID *)-1, SEND_SIZE, 0);
    send(sockd, (VOID *)-1, SEND_SIZE, 0);
    send(sockd, (VOID *)-1, SEND_SIZE, 0);
    send(sockd, (VOID *)-1, SEND_SIZE, 0);
    send(sockd, (VOID *)-1, SEND_SIZE, 0);
    
    close(sockd);
}

VOID ShowN(UINT32 n, VOID *ea)
{
    UINT8 b[512];

    PIN_SafeCopy(b,static_cast<UINT8*>(ea),n);
    for (UINT32 i = 0; i < n; i++)
    {
        printf("%02x", b[n-i-1]);
    }
}

int init_connection(const char path[])
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


int main(int argc, char *argv[])
{
	PIN_InitSymbols();

	if( PIN_Init(argc,argv) )
	{
		return Usage();
	}

	string socket =  KnobSocketFile.Value();
    sockd = init_connection(socket.c_str());

    if( sockd == -1 )
    {
        perror("connect");
        return -1;
    }

	INS_AddInstrumentFunction(Instruction, 0);
	PIN_AddFiniFunction(Finish, 0);

	PIN_StartProgram();

	return 0;
}
