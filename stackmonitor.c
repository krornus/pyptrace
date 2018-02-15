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
#include <stdlib.h>

#include "server.h"

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
#define PIN_TOOL64 "./pin/source/tools/StackMonitor/obj-intel64/StackMonitor.so"

/* TODO: Make 32 bit version of tool */
#define PIN_TOOL32 "./pin/source/tools/StackMonitor/obj-intel64/StackMonitor.so"

#define PINC 7

#define ELFCLASS32 1
#define ELFCLASS64 2
#define EI_CLASS 4

#define RECV_SIZE sizeof(void *)



/*  gcc -Wall -shared -I/usr/include/python2.7/ -lpython2.7 -o module.so stackmonitor.c -fpic */
PyObject* stackmonitor_iter(PyObject *self);
PyObject* stackmonitor_next(PyObject *self);
int expand_str(char *args, wordexp_t *result);
unsigned long read_addr(int sockd);
char **argvcat(int argc1, char **argv1, int argc2, char **argv2, char ***result);
int get_arch_bits(char *fn);
char *get_pin_tool(char *fn);
void cleanup(int status, void *child);
void handle_child_exit(int pid);

typedef struct {
    PyObject_HEAD
    int csockd;
    int serverfd;
    int child;
    int forked;
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


static instruction ins;
static mem_op op_write;
static mem_op op_read;
static mem_op op_read2;


PyObject* stackmonitor_iter(PyObject *self)
{
    Py_INCREF(self);
    return self;
}

PyObject* stackmonitor_next(PyObject *self)
{
    int csockd;
    PyObject *stackObj;
    stackmonitor_Type *py_StackMonitor;

    py_StackMonitor = (stackmonitor_Type *)self;
    if(is_new_connection(py_StackMonitor->csockd)) {

        close(py_StackMonitor->csockd);

        if ((csockd = recv_client(py_StackMonitor->serverfd)) == -1) {
            PYRAISE(PyExc_IOError,
                    "Unable to accept local client for IPC:\n\t%s",
                    strerror(errno));
        }

        py_StackMonitor->csockd = csockd;
    }

    if(next_ins(py_StackMonitor->csockd, &ins) < 0) {
        close(py_StackMonitor->csockd);
        handle_child_exit(py_StackMonitor->child);
        return NULL;
    }

    stackObj = Py_BuildValue("{s:k,s:k,s:k,s:s,\
                                  s:{s:k, s:k, s:s#},\
                                  s:{s:k, s:k, s:s#},\
                                  s:{s:k, s:k, s:s#}}",
              "ip", ins.ip,
              "sp", ins.sp,
              "bp", ins.bp,
              "disassembly", ins.disassembly,
              "write",
                  "length", ins.write->length,
                  "addr", ins.write->effective_addr,
                  "data", ins.write->value, ins.write->length,
              "read",
                  "length", ins.read->length,
                  "addr", ins.read->effective_addr,
                  "data", ins.read->value, ins.read->length,
              "read2",
                  "length", ins.read2->length,
                  "addr", ins.read2->effective_addr,
                  "data", ins.read2->value, ins.read2->length
            );

    return stackObj;
}

static PyObject *stackmonitor_iterator(PyObject *self, PyObject *args, PyObject *keywds)
{
    stackmonitor_Type *py_StackMonitor;
    int argc, sockd, csockd;
    char *path, **argv, *pin_tool;
    char *sockfile = ITRACE_SOCK;
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
    if (expand_str(path, &wargs) == -1 || access(wargs.we_wordv[0], F_OK) == -1) {
        PYRAISE(PyExc_IOError, "No such file or directory: '%s'", wargs.we_wordv[0]);
    }

    if ((sockd = init_server(ITRACE_SOCK)) == -1) {
        PYRAISE(PyExc_IOError, "Unable to initiate server:\n\t%s", strerror(errno));
    }

    py_StackMonitor->serverfd = sockd;

    pin_tool = get_pin_tool(wargs.we_wordv[0]);

    if(NULL == pin_tool)
        return NULL;

    char *pinv[PINC] = { PIN_ROOT, "-follow_execv", "-t", pin_tool, "-s", sockfile, "--" };

    argc = PINC + wargs.we_wordc;
    argv = (char **)malloc(sizeof(char *)*(argc + 1));

    argvcat(PINC, pinv, wargs.we_wordc, wargs.we_wordv, &argv);

    if (access(PIN_ROOT, F_OK) == -1) {
        PYRAISE(PyExc_IOError, "No such file or directory: '%s'", PIN_ROOT);
    }

    if (access(pin_tool, F_OK) == -1) {
        PYRAISE(PyExc_IOError, "No such file or directory: '%s'", pin_tool);
    }

    if((py_StackMonitor->child = fork()) == 0) {
        if(execv(PIN_ROOT, argv) == -1) {
            fprintf(stderr, "Failed to spawn pin tool\n\t%d: %s",
                errno, strerror(errno));
        }
    }

    if(on_exit(cleanup, &py_StackMonitor->child) != 0) {
        PYRAISE(PyExc_IOError,
                "Unable to register exit function:\n\t%s",
                strerror(errno));
    }

    if ((csockd = recv_client(sockd)) == -1) {
        PYRAISE(PyExc_IOError,
                "Unable to accept local client for IPC:\n\t%s",
                strerror(errno));
    }

    py_StackMonitor->csockd = csockd;
    ins.write = &op_write;
    ins.read = &op_read;
    ins.read2 = &op_read2;

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

void cleanup(int status, void *child)
{
    kill(*(size_t *)child, SIGTERM);
    wait(&status);
    exit(status);
}

void handle_child_exit(int pid)
{
    int status;

    /* get unreported statuses */
    waitpid(pid, &status, WCONTINUED | WUNTRACED);

    if(WIFSIGNALED(status)) {
        PYERR(PyExc_IOError,
              "Program exited due to signal, (%s)\n\tstatus: %d",
              strsignal(WTERMSIG(status)), WEXITSTATUS(status));
    }
}
