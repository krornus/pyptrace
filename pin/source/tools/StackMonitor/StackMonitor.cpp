#include <unordered_map>
#include <unistd.h>
#include <sys/socket.h>
#include <iostream>

#include "pin.H"

#define SEND_SIZE sizeof(void *)
#define SM_WRITE 0
#define SM_READ  1
#define SM_READ2 2

/* TODO: Change how we handle DEBUG */
/* Low priority, only matters when DEBUG is set */
#ifdef DEBUG
#define SEND(fd, buf, len, flags)\
    sent = send(fd, buf, len, flags);\
    sentb += sent;\
    printf("sent %d bytes: (%d total)\n", sent, sentb);
#else
#define SEND(fd, buf, len, flags) send(fd, buf, len, flags);
#endif

struct proc_mapping_t {
    long unsigned int low_addr;
    long unsigned int high_addr;
    long unsigned int offset;
    long unsigned int inode;
    char perms[5];
    short dev_high;
    short dev_low;
    char pathname[1024];
};

struct proc_addr_list_t {
    long unsigned int low;
    long unsigned int high;
    struct proc_addr_list_t *next;
};

typedef struct proc_mapping_t proc_mapping;
typedef struct proc_addr_list_t proc_addr_list;

struct memory_op_t {
    VOID *ea;
    UINT32 size;
};

typedef struct memory_op_t memory_op;
typedef struct proc_mapping_t proc_mapping;

/* PIN does not guarantee lifetime of variables */
/* Hash of operations, uses SM_WRITE, SM_READ, SM_READ2 */
/* Access by ADDRINT of instruction */
static unordered_map<ADDRINT, memory_op *> write_map;
static proc_addr_list *proc;


VOID ShowN(UINT32 n, VOID *ea);
VOID SendMappedStackOp(ADDRINT addr, UINT32 type);
VOID StackNop(UINT32 type);
VOID TryInsertStackOpAfter(INS ins, ADDRINT addr, UINT32 type);
VOID LoadMemoryOperation(ADDRINT addr, VOID *ea, UINT32 size);
VOID ForkNotify(THREADID thread, const CONTEXT *ctx, VOID *arg);
int is_stack_op(void *ea);
proc_mapping get_proc_mapping(int pid);
int init_connection(char path[]);
int get_proc_mapping(FILE *fp, proc_mapping *proc);
FILE *open_proc_mappings(int pid);

static void OnSig(THREADID threadIndex, 
		CONTEXT_CHANGE_REASON reason, 
		const CONTEXT *ctxtFrom,
		CONTEXT *ctxtTo,
		INT32 sig, 
		VOID *v);

/* 
*  TODO: check if we need unique sockets for python module
*  also check DBUS efficiency for our needs vs unix sockets
*/
KNOB<string> KnobSocketFile(
	KNOB_MODE_WRITEONCE, "pintool", "s", 
	"/tmp/stack-monitor", "sockfile to use");

int sockd;

#ifdef DEBUG
int sent = 0;
int sentb = 0;
#endif

INT32 Usage()
{
    cerr <<
        "This tool monitors the stack for \
        changes and sends updates to a UNIX socket\n"
        "\n";
    cerr << KNOB_BASE::StringKnobSummary();
    cerr << endl;

    return -1;
}

VOID StackPtr(VOID *ip, const CONTEXT *ctxt, string *disasm)
{
    /* TODO: Add maskable flag integer for sending */

    uintptr_t len;

    ADDRINT sp = (ADDRINT)PIN_GetContextReg(ctxt, REG_STACK_PTR);
    ADDRINT bp = (ADDRINT)PIN_GetContextReg(ctxt, REG_GBP);

#ifdef DEBUG
    printf("IP %p: ", ip);
#endif
    SEND(sockd, (VOID *)&ip, SEND_SIZE, 0);

#ifdef DEBUG
    printf("SP: ");
#endif
    SEND(sockd, (VOID *)&sp, SEND_SIZE, 0);

#ifdef DEBUG
    printf("BP: ");
#endif
    SEND(sockd, (VOID *)&bp, SEND_SIZE, 0);

    len = (*disasm).length();

#ifdef DEBUG
    printf("Disassembly length: ");
#endif
    SEND(sockd, (VOID *)&len, SEND_SIZE, 0);

#ifdef DEBUG
    printf("Disassembly: ");
#endif
    SEND(sockd, (VOID *)(*disasm).c_str(), len, 0);

}


VOID SendStackOp(VOID *ea, UINT32 size, UINT32 type)
{
    uintptr_t op_type;
    uintptr_t len;
    UINT8 *val;

    /* uintptr_t is size of (VOID *) */
    op_type = type;
    len = size;
#ifdef DEBUG
    printf("OP Length (%lu): ", len);
#endif
    SEND(sockd, (VOID *)&op_type, SEND_SIZE, 0);
    SEND(sockd, (VOID *)&len, SEND_SIZE, 0);

    if(len > 0)
    {
#ifdef DEBUG
        printf("OP Effective address: ");
#endif
        SEND(sockd, (VOID *)&ea, SEND_SIZE, 0);

        val = static_cast<UINT8*>(malloc(sizeof(UINT8) * (len)));

        PIN_SafeCopy(val, static_cast<UINT8*>(ea), len);

#ifdef DEBUG
        printf("OP Value: ");
#endif
        SEND(sockd, (VOID *)val, len, 0);
    }
}

VOID SendMappedStackOp(ADDRINT addr, UINT32 type)
{
    memory_op *op;
    
    /* size of (void *) */
    uintptr_t len;
    uintptr_t op_type;

    UINT8 *val;

    op = write_map[addr];
    write_map[addr] = NULL;

    op_type = type;
    if(NULL == op)
        len = 0;
    else
        len = op->size;

#ifdef DEBUG
    printf("OP Type (%lu): ", type);
#endif
    SEND(sockd, (VOID *)&op_type, SEND_SIZE, 0);
#ifdef DEBUG
    printf("OP Length (%lu): ", len);
#endif
    SEND(sockd, (VOID *)&len, SEND_SIZE, 0);

    if(len > 0)
    {
#ifdef DEBUG
        printf("OP Effective address: ");
#endif
        SEND(sockd, (VOID *)&op->ea, SEND_SIZE, 0);

        val = static_cast<UINT8*>(malloc(sizeof(UINT8) * (op->size)));

        PIN_SafeCopy(val, static_cast<UINT8*>(op->ea), len);

#ifdef DEBUG
        printf("OP Value: ");
#endif
        SEND(sockd, (VOID *)val, len, 0);
    }

    delete op;
}

VOID StackNop(UINT32 type)
{
    uintptr_t len;
    uintptr_t op_type;

    op_type = type;
    len = 0;

#ifdef DEBUG
    printf("NOP TYPE (%d): ", type);
#endif
    SEND(sockd, (VOID *)&op_type, SEND_SIZE, 0);
#ifdef DEBUG
    printf("NOP Length (%lu): ", len);
#endif
    SEND(sockd, (VOID *)&len, SEND_SIZE, 0);
}

VOID LoadMemoryOperation(ADDRINT addr, VOID *ea, UINT32 size)
{
    memory_op *op = new memory_op();

    if(is_stack_op(ea)) {
        op->ea = ea;
        op->size = size;
    } 
    else {
        op->ea = 0;
        op->size = 0;
    }

    write_map[addr] = op;
}


VOID Instruction(INS ins, VOID *val)
{
    string disasm;
    disasm = INS_Disassemble(ins);

    /* send this first */
    INS_InsertCall (ins,
        IPOINT_BEFORE, (AFUNPTR)StackPtr,
        IARG_INST_PTR, IARG_CONTEXT, IARG_PTR, new string(disasm), 
        IARG_CALL_ORDER, CALL_ORDER_FIRST, IARG_END);


    ADDRINT addr;
    addr = INS_Address(ins);

    if (INS_IsMemoryWrite(ins))
    {
        /* Load a memory write into static dict (LoadMemoryOperation) */
        INS_InsertCall(ins, 
            IPOINT_BEFORE, (AFUNPTR)LoadMemoryOperation, 
            IARG_ADDRINT, addr, IARG_MEMORYWRITE_EA, IARG_MEMORYWRITE_SIZE, 
            IARG_END);

        TryInsertStackOpAfter(ins, addr, SM_WRITE);
    }
    else
    {
        INS_InsertCall(ins, 
            IPOINT_BEFORE, (AFUNPTR)StackNop, IARG_UINT32, SM_WRITE, IARG_END);
    }

    if (INS_IsMemoryRead(ins) 
        && !INS_IsPrefetch(ins) && INS_IsStandardMemop(ins))
    {
        /* we just send reads (SendStackOp) */
        INS_InsertCall(ins, 
            IPOINT_BEFORE, (AFUNPTR)SendStackOp, 
            IARG_MEMORYREAD_EA, IARG_MEMORYREAD_SIZE, 
            IARG_UINT32, SM_READ,
            IARG_END);
    }
    else
    {
        INS_InsertCall(ins, 
            IPOINT_BEFORE, (AFUNPTR)StackNop, IARG_UINT32, SM_READ, IARG_END);
    }

    if (INS_IsMemoryRead(ins) && INS_HasMemoryRead2(ins) 
        && INS_IsStandardMemop(ins))
    {
        INS_InsertCall(ins, 
            IPOINT_BEFORE, (AFUNPTR)SendStackOp, 
            IARG_MEMORYREAD_EA, IARG_MEMORYREAD_SIZE, 
            IARG_UINT32, SM_READ2,
            IARG_END);
    }
    else
    {
        INS_InsertCall(ins, 
            IPOINT_BEFORE, (AFUNPTR)StackNop, IARG_UINT32, SM_READ2, IARG_END);
    }
}

VOID TryInsertStackOpAfter(INS ins, ADDRINT addr, UINT32 type)
{
    /* only called on WRITE, should always have a fallthrough(?) */
    
    if(INS_HasFallThrough(ins)) {
        INS_InsertCall(ins, 
            IPOINT_AFTER, (AFUNPTR)SendMappedStackOp, 
            IARG_ADDRINT, addr,
            IARG_UINT32, type, IARG_END);
    }
    else {
        INS_InsertCall(ins, 
            IPOINT_BEFORE, (AFUNPTR)SendMappedStackOp, 
            IARG_ADDRINT, addr, 
            IARG_UINT32, type, IARG_END);
    }
}

VOID Finish(int code, VOID *val)
{
#ifdef DEBUG
    printf("FINISHING: \n");
#endif
    SEND(sockd, (VOID *)-1, SEND_SIZE, 0);
    SEND(sockd, (VOID *)-1, SEND_SIZE, 0);
    SEND(sockd, (VOID *)-1, SEND_SIZE, 0);
    SEND(sockd, (VOID *)-1, SEND_SIZE, 0);
    SEND(sockd, (VOID *)-1, SEND_SIZE, 0);
    SEND(sockd, (VOID *)-1, SEND_SIZE, 0);
    
    close(sockd);

    exit(0);
}

static void OnSig(THREADID threadIndex, 
		CONTEXT_CHANGE_REASON reason, 
		const CONTEXT *ctxtFrom,
		CONTEXT *ctxtTo,
		INT32 sig, 
		VOID *v)
{
    Finish(sig, 0);
}


VOID ForkNotify(THREADID thread, const CONTEXT *ctx, VOID *arg)
{
    fprintf(stderr, "ERROR: Process forked, exiting\n");
    Finish(56, 0);
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


int is_stack_op(void *ea)
{
    proc_addr_list *tmp;
    tmp = proc;
    while(tmp != NULL) {
        /* stack grows downward, h/l are backward */
        if((uintptr_t)ea >= tmp->low && (uintptr_t)ea <= tmp->high) {
            return 1;
        }

        tmp = tmp->next;
    }

    return 0;
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


FILE *open_proc_mappings(int pid)
{
    char fn[1024];

    sprintf(fn, "/proc/%d/maps", pid);

    if (access(fn, F_OK) == -1) {
        fprintf(stderr, "no such file %s\n", fn);
        exit(1);
    }

    return fopen(fn, "r");
}

int get_proc_mapping(FILE *fp, proc_mapping *proc)
{
    char line[2048];
    int res;
    errno = 0;

    /*
    * last string in /proc/[pid]/maps is optional
    * need to consume entire line each read
    */
    if(NULL == fgets(line, 2048, fp))
        return -1;

    res = sscanf(line, "%lx-%lx %s %lu %hu:%hu %lu %s\n",
        &proc->low_addr, &proc->high_addr, proc->perms,
        &proc->offset, &proc->dev_high, &proc->dev_low, &proc->inode, proc->pathname);


    if(res == EOF || errno != 0)
        return -1;
    return 0;
}


int main(int argc, char *argv[])
{
    int pid;
    proc_mapping sproc;
    proc_addr_list *tail;
    FILE *fp;

	PIN_InitSymbols();

	if( PIN_Init(argc,argv) )
	{
		return Usage();
	}

    proc = NULL;
    tail = NULL;

    pid = PIN_GetPid();
    fp = open_proc_mappings(pid);

    while(get_proc_mapping(fp, &sproc) >= 0) {
        if(strcmp("[stack]", sproc.pathname) == 0) {
            if(NULL == proc) {
                proc = new proc_addr_list;
                tail = proc;
            }
            else {
                tail->next = new proc_addr_list;
                tail = tail->next;
            }
            tail->low = sproc.low_addr;
            tail->high = sproc.high_addr;
            tail->next = NULL;
        }
    }

    fclose(fp);

    if(NULL == proc) {
        fprintf(stderr, "unable to find stack boundaries from proc map\n");
        return -1;
    }

	string socket =  KnobSocketFile.Value();
	sockd = init_connection(socket.c_str());

	if( sockd == -1 )
	{
		perror("connect");
		return -1;
	}

	PIN_AddFiniFunction(Finish, 0);
	PIN_AddContextChangeFunction(OnSig, 0);
    PIN_AddForkFunction(FPOINT_BEFORE, ForkNotify, 0);

    /* TODO: Determine how we are going to multithread forked processes */
    /* PIN_AddForkFunction(FPOINT_AFTER_IN_PARENT, ForkParent, 0); */
    /* PIN_AddForkFunction(FPOINT_AFTER_IN_CHILD, ForkChild, 0); */

	INS_AddInstrumentFunction(Instruction, 0);

	PIN_StartProgram();

	return 0;
}
