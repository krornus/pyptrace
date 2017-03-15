#include <python2.7/Python.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <wordexp.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <string.h>


#define DESC "Stack monitor tracer"
#define MODULE "stackmonitor"
#define ITER_METH "monitor"
#define ITER_METH_DESC "iterate over stack actions for given program"
#define ITER_NAME "stackmonitor.StackMonitor"
#define MAX_ERR_LEN  1024
#define PYERR(exception, fmt, ...)  {\
    char __err_str__[MAX_ERR_LEN];\
    snprintf(__err_str__, MAX_ERR_LEN, fmt, __VA_ARGS__);\
    PyErr_SetString(exception, __err_str__);\
};
#define PYRAISE(exception, fmt, ...)  {\
    PYERR(exception, fmt, __VA_ARGS__);\
    return NULL;\
};

#define ITRACE_SOCK "/tmp/stack-monitor"
#define PIN_ROOT "./pin/pin"
#define PIN_TOOL64 "./tool/StackMonitor.so"
 
/* TODO: Make 32 bit version of tool */
#define PIN_TOOL32 "./tool/StackMonitor.so"
#define PINC 6

#define ELFCLASS32 1
#define ELFCLASS64 2
#define EI_CLASS 4

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
    struct mem_op_t *read;
    struct mem_op_t *read2;
    struct mem_op_t *write;
};

typedef struct instruction_t instruction;
typedef struct mem_op_t mem_op;
typedef struct ins_value_t ins_value;


/*  gcc -Wall -shared -I/usr/include/python2.7/ -lpython2.7 -o module.so stackmonitor.c -fpic */
PyObject* stackmonitor_iter(PyObject *self);
PyObject* stackmonitor_next(PyObject *self);
int expand_str(char *args, wordexp_t *result);
int init_server(char *path);
unsigned long read_addr(int sockd);
char **argvcat(int argc1, char **argv1, int argc2, char **argv2, char ***result);
int get_arch_bits(char *fn);
char *get_pin_tool(char *fn);
instruction *recv_ins(int sock);
mem_op *recv_mem_op(int sock);
void destroy_ins(instruction *ins);
int recv_val(int sock, unsigned char *buf, int size);
void handle_child_exit(int pid);

typedef struct {
    PyObject_HEAD
    int csockd;
    int serverfd;
    int child;
} stackmonitor_Type;


static PyTypeObject stackmonitorType = {
    PyObject_HEAD_INIT(NULL)
        0,                         
    ITER_NAME,
    sizeof(stackmonitor_Type),    
    0,                         
    0,                         
    0,                         
    0,                         
    0,                         
    0,                         
    0,                         
    0,                         
    0,                         
    0,                         
    0,                         
    0,                         
    0,                         
    0,                         
    0,                         
    0,                         
    Py_TPFLAGS_DEFAULT | Py_TPFLAGS_HAVE_ITER,
    DESC, 
    0,  
    0,  
    0,  
    0,  
    stackmonitor_iter,  
    stackmonitor_next  
};

static PyObject *stackmonitor_iterator(PyObject *self, PyObject *args, PyObject *keywd);
PyMODINIT_FUNC init_StackMonitor(void);

static PyMethodDef StackMonitorMethods[] = {
    /* set flag to accept VARARGS and KEYWORDS, cast init to a PyCFunction */
    {ITER_METH, (PyCFunction)stackmonitor_iterator, METH_VARARGS|METH_KEYWORDS, ITER_METH_DESC},
    {NULL, NULL, 0, NULL}        /* Sentinel */
};

PyObject* stackmonitor_iter(PyObject *self)
{
    Py_INCREF(self);
    return self;
}

PyObject* stackmonitor_next(PyObject *self)
{
    PyObject *stackObj;
    stackmonitor_Type *py_StackMonitor;
    instruction *ins;

    py_StackMonitor = (stackmonitor_Type *)self;

    ins = recv_ins(py_StackMonitor->csockd);

    if(ins == NULL) {
        close(py_StackMonitor->csockd);
        handle_child_exit(py_StackMonitor->child);
        return NULL;
    }

    stackObj = Py_BuildValue("{s:k,s:k,s:k, s:{s:k, s:k, s:s}, s:{s:k, s:k, s:s}, s:{s:k, s:k, s:s}}",
                              "ip", ins->ip,
                              "sp", ins->sp,
                              "bp", ins->bp,
                              "write",
                                  "length", ins->write->length,
                                  "addr", ins->write->effective_addr,
                                  "data", ins->write->value,
                              "read", 
                                  "length", ins->read->length,
                                  "addr", ins->read->effective_addr,
                                  "data", ins->read->value,
                              "read2", 
                                  "length", ins->read2->length,
                                  "addr", ins->read2->effective_addr,
                                  "data", ins->read2->value
                              );

    destroy_ins(ins);

    //PYERR(PyExc_IOError, "debug %s", "\n"); return NULL;
    return stackObj;
}

static PyObject *stackmonitor_iterator(PyObject *self, PyObject *args, PyObject *keywds)
{
    stackmonitor_Type *py_StackMonitor;
    int argc, sockd, csockd;
    unsigned int remsize;
    char *path, **argv, *pin_tool;
    char *sockfile = ITRACE_SOCK;
    struct sockaddr_un remote;
    wordexp_t wargs;

    static char *kwlist[] = {"path", "socket", NULL};

    py_StackMonitor = PyObject_New(stackmonitor_Type, &stackmonitorType);

    if (!PyObject_Init((PyObject *)py_StackMonitor, &stackmonitorType)) {
        Py_DECREF(py_StackMonitor);
        return NULL;
    }

    /* parse a required string and optional string */
    if (!PyArg_ParseTupleAndKeywords(
                args, keywds, "s|s", kwlist, &path, &sockfile)) {
        return NULL;
    }

    // get argv and access
    if (expand_str(path, &wargs) == -1 || access(wargs.we_wordv[0], F_OK) == -1)
        PYRAISE(PyExc_IOError, "No such file or directory: '%s'", wargs.we_wordv[0]);

    if ((sockd = init_server(ITRACE_SOCK)) == -1)
        PYRAISE(PyExc_IOError, "Unable to initiate server:\n\t%s", strerror(errno));

    py_StackMonitor->serverfd = sockd;
    
    pin_tool = get_pin_tool(wargs.we_wordv[0]);

    if(NULL == pin_tool)
        return NULL;

    char *pinv[PINC] = { PIN_ROOT, "-t", pin_tool, "-s", sockfile, "--" };

    argc = PINC + wargs.we_wordc;
    argv = (char **)malloc(sizeof(char *)*(argc + 1));

    argvcat(PINC, pinv, wargs.we_wordc, wargs.we_wordv, &argv);
    
    if((py_StackMonitor->child = fork()) == 0) {
        execv(PIN_ROOT, argv);
    }

    remsize = sizeof(remote);
    if ((csockd = accept(sockd, (struct sockaddr *)&remote, &remsize)) == -1)
        PYRAISE(PyExc_IOError, 
                "Unable to accept local client for IPC:\n\t%s", 
                strerror(errno));
        
    py_StackMonitor->csockd = csockd;

    return (PyObject *)py_StackMonitor;
}


PyMODINIT_FUNC initstackmonitor(void)
{
    PyObject* obj;

    stackmonitorType.tp_new = PyType_GenericNew;
    if (PyType_Ready(&stackmonitorType) < 0)  return;

    obj = Py_InitModule(MODULE, StackMonitorMethods);

    Py_INCREF(&stackmonitorType);
    PyModule_AddObject(obj, "StackMonitor", (PyObject *)&stackmonitorType);
}


int expand_str(char *args, wordexp_t *result)
{
    if(NULL == args)
        return -1;

    switch (wordexp (args, result, 0))
    {
        case 0:
            break;
        case WRDE_NOSPACE:
            wordfree (result);
        default:
            return -1;
    }
    return 0;
}

int init_server(char *path)
{
    int len, sockfd;
    struct sockaddr_un local;

    if ((sockfd = socket(AF_UNIX, SOCK_STREAM, 0)) == -1) {
        return -1;
    }

    local.sun_family = AF_UNIX;
    strcpy(local.sun_path, path);

    unlink(local.sun_path);

    len = strlen(local.sun_path) + sizeof(local.sun_family);

    if (bind(sockfd, (struct sockaddr *)&local, len) == -1) {
        return -1;
    }

    if (listen(sockfd, 1) == -1) {
        return -1;
    }

    return sockfd;
}

char **argvcat(int argc1, char **argv1, int argc2, char **argv2, char ***result)
{
    for(int i = 0; i < argc1; i++)
        (*result)[i] = argv1[i];

    for(int i = 0; i < argc2; i++)
        (*result)[i+argc1] = argv2[i]; 

    (*result)[argc1+argc2] = NULL;
    return *result;
}

int get_arch_bits(char *fn)
{
    FILE *elf;
    unsigned char arch[1];
    unsigned char magic[4] = {
        '\x7f', 'E', 'L', 'F'
    };


    elf = fopen(fn, "r");


    if(NULL==elf)
    {
        PYERR(PyExc_IOError, "Unable to open file '%s'\n\t\t(%d): %s", 
            fn, errno, strerror(errno));
        return -1;
    }

    for(int i = 0; i < 4; i++)
    {
        char c;

        errno = 0;
        if(fread(&c, 1, 1, elf) == 0 || errno != 0)
        {
            PYERR(PyExc_IOError, "Unable to read from file '%s',\n\t\t(%d): %s", 
                fn, errno, strerror(errno));
            return -1;
        }

        if(c != magic[i])
        {
            PYERR(PyExc_IOError, "Invalid header, not a vaid ELF file.\
                                      \n\tExpected '0x7fELF'\
                                      \n\tPosition %d, byte '%c'\n", 
                                      i, c);
            return -1;
        }
    }

    errno = 0;
    if(fread(arch, 1, 1, elf)==0 || errno != 0)
    {
        PYERR(PyExc_IOError, "Unable to read from file '%s',\n\t\t(%d): %s", 
            fn, errno, strerror(errno));
        return -1;
    }

    
    return arch[0];
}

char *get_pin_tool(char *fn)
{
    switch(get_arch_bits(fn))
    {
        case -1:
            return NULL;
        case ELFCLASS32:
            return PIN_TOOL32;
        case ELFCLASS64:
            return PIN_TOOL64;
        default:
            return NULL;
    }
}

instruction *recv_ins(int sock)
{
    instruction *ins;
    ins = malloc(sizeof(instruction));

    if(recv_val(sock, (unsigned char *)&ins->ip, RECV_SIZE) < 0) {
        return NULL;
    }
    if(recv_val(sock, (unsigned char *)&ins->sp, RECV_SIZE) < 0) {
        PYERR(PyExc_IOError, 
            "Error receiving SP from client\n\t%d: %s", 
            errno, strerror(errno));
        return NULL;
    }
    if(recv_val(sock, (unsigned char *)&ins->bp, RECV_SIZE) < 0) {
        PYERR(PyExc_IOError, 
            "Error receiving BP from client\n\t%d: %s", 
            errno, strerror(errno));
        return NULL;
    }

    ins->write = recv_mem_op(sock);
    ins->read  = recv_mem_op(sock); 
    ins->read2  = recv_mem_op(sock); 

    if(ins->write == NULL || ins->read == NULL || ins->read2 == NULL) {
        PYERR(PyExc_IOError, 
            "Error receiving memory operation from client \n\t%d: %s", 
            errno, strerror(errno));
        return NULL;
    }

    return ins;
}

mem_op *recv_mem_op(int sock)
{
    mem_op *op;
    uintptr_t size;

    if(recv_val(sock, (unsigned char *)&size, RECV_SIZE) < 0) {
        PYERR(PyExc_IOError, 
            "Error receiving memory operation size from client\n\t%d: %s", 
            errno, strerror(errno));
        return NULL;
    }

    if(size > 0)
    {
        op = (mem_op *)malloc(sizeof(mem_op)+size);
        op->length = size;

        if(recv_val(sock, (unsigned char *)&op->effective_addr, RECV_SIZE) < 0) {
            PYERR(PyExc_IOError, 
                "Error receiving effective address from client\n\t%d: %s", 
                errno, strerror(errno));
            return NULL;
        }
        if(recv_val(sock, op->value, op->length) < 0) {
            PYERR(PyExc_IOError, 
                "Error receiving memory value from client\n\t%d: %s", 
                errno, strerror(errno));
            return NULL;
        }


        return op;
    }
    else
    {
        op = (mem_op *)malloc(sizeof(mem_op) + 1);
        op->length = 0;
        op->effective_addr = 0;
        *op->value = '\x00';
        return op;
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

int recv_val(int sock, unsigned char *buf, int size)
{
    errno = 0;
    int len = 0;
    if((len = recv(sock, buf, size, 0)) < 0 || errno != 0) {
        return -1;
    }
    else if(len == 0 && size != 0)
    {
        return -2; 
    }

    return len;
}

void handle_child_exit(int pid)
{
    int status;

    /* get unreported statuses */
    waitpid(pid, &status, WCONTINUED | WUNTRACED);


    if(WIFSIGNALED(status))
    {
        PYERR(PyExc_IOError, 
              "Program exited due to signal %s, status:\n\t%d", 
              strsignal(WTERMSIG(status)), WEXITSTATUS(status));
    }
}
