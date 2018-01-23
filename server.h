
#define INSTR_SIZE 32
#define RECV_SIZE sizeof(void *)

#define MAX_OP_VALUE_SIZE 2048
#define MAX_DISASS_LENGTH 1024

#define SM_WRITE 0
#define SM_READ 1
#define SM_READ2 2

struct mem_op_t {
    uintptr_t type;
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

int next_ins(int sock, instruction *ins);
int is_new_connection(int sock);
int recv_mem_op(int sock, mem_op *op);
int recv_val(int sock, unsigned char *buf, int size);
int peek_val(int sock, unsigned char *buf, int size);
int handle_ins(instruction *ins);
int recv_client(int sock);
int init_server(char *path);
