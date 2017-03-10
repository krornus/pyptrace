#include <python2.7/Python.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <wordexp.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>

#define DESC "Instruction trace iterator"
#define MODULE "pyitrace"
#define ITER_METH "instructions"
#define ITER_METH_DESC "Iterate over instructions"
#define ITER_NAME "pyitrace.PyITrace"
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

#define ITRACE_SOCK "/tmp/itrace"
#define PIN_ROOT "./pin/pin"
#define PIN_TOOL64 "./tool/itrace64.so"
#define PIN_TOOL32 "./tool/itrace32.so"
#define PINC 4

#define ELFCLASS32 1
#define ELFCLASS64 2
#define EI_CLASS 4

/*  gcc -Wall -shared -i/usr/include/python2.7/ -lpython2.7 -o module.so pyitrace.c -fpic */
PyObject* pyitrace_PyITrace_iter(PyObject *self);
PyObject* pyitrace_PyITrace_next(PyObject *self);
int expand_str(char *args, wordexp_t *result);
int init_server(char *path);
unsigned long read_addr(int sockd);
char **argvcat(int argc1, char **argv1, int argc2, char **argv2, char ***result);
int get_arch_bits(char *fn);
char *get_pin_tool(char *fn);

typedef struct {
    PyObject_HEAD
    int csockd;
    int serverfd;
} pyitrace_PyITrace;


static PyTypeObject pyitrace_PyITraceType = {
    PyObject_HEAD_INIT(NULL)
        0,                         
    ITER_NAME,
    sizeof(pyitrace_PyITrace),    
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
    pyitrace_PyITrace_iter,  
    pyitrace_PyITrace_next  
};

static PyObject *pyitrace_iterator(PyObject *self, PyObject *args, PyObject *keywd);
PyMODINIT_FUNC init_PyITrace(void);

static PyMethodDef PyITraceMethods[] = {
    /* set flag to accept VARARGS and KEYWORDS, cast init to a PyCFunction */
    {ITER_METH, (PyCFunction)pyitrace_iterator, METH_VARARGS|METH_KEYWORDS, ITER_METH_DESC},
    {NULL, NULL, 0, NULL}        /* Sentinel */
};

PyObject* pyitrace_PyITrace_iter(PyObject *self)
{
    Py_INCREF(self);
    return self;
}

PyObject* pyitrace_PyITrace_next(PyObject *self)
{
    pyitrace_PyITrace *py_PyITrace;
    py_PyITrace = (pyitrace_PyITrace *)self;

    unsigned long addr;
    
    addr = read_addr(py_PyITrace->csockd);

    if(addr == -1) {
        close(py_PyITrace->csockd);
        return NULL;
    }

    /* return a tuple of (pyitrace, bar, i) */
    return Py_BuildValue("k", addr);
}

static PyObject *pyitrace_iterator(PyObject *self, PyObject *args, PyObject *keywds)
{
    pyitrace_PyITrace *py_PyITrace;
    int argc, sockd, csockd;
    unsigned int remsize;
    char *path, **argv, *pin_tool;
    struct sockaddr_un remote;
    wordexp_t wargs;


    static char *kwlist[] = {"path", NULL};

    py_PyITrace = PyObject_New(pyitrace_PyITrace, &pyitrace_PyITraceType);

    if (!PyObject_Init((PyObject *)py_PyITrace, &pyitrace_PyITraceType)) {
        Py_DECREF(py_PyITrace);
        return NULL;
    }

    /* parse a required string and optional string */
    if (!PyArg_ParseTupleAndKeywords(
                args, keywds, "s", kwlist, &path)) {
        return NULL;
    }

    // get argv and access
    if (expand_str(path, &wargs) == -1 || access(wargs.we_wordv[0], F_OK) == -1)
        PYRAISE(PyExc_IOError, "No such file or directory: '%s'", wargs.we_wordv[0]);

    if ((sockd = init_server(ITRACE_SOCK)) == -1)
        PYRAISE(PyExc_IOError, "Unable to initiate server:\n\t%s", strerror(errno));

    py_PyITrace->serverfd = sockd;
    
    pin_tool = get_pin_tool(wargs.we_wordv[0]);

    if(NULL == pin_tool)
        return NULL;

    char *pinv[PINC] = { PIN_ROOT, "-t", pin_tool, "--" };

    argc = PINC + wargs.we_wordc;
    argv = (char **)malloc(sizeof(char *)*(argc + 1));

    argvcat(PINC, pinv, wargs.we_wordc, wargs.we_wordv, &argv);
    
    if(fork() == 0) {
        execv(PIN_ROOT, argv);
    }

    remsize = sizeof(remote);
    if ((csockd = accept(sockd, (struct sockaddr *)&remote, &remsize)) == -1)
        PYRAISE(PyExc_IOError, 
                "Unable to accept local client for ICP:\n\t%s", 
                strerror(errno));
        
    py_PyITrace->csockd = csockd;

    return (PyObject *)py_PyITrace;
}


PyMODINIT_FUNC initpyitrace(void)
{
    PyObject* obj;

    pyitrace_PyITraceType.tp_new = PyType_GenericNew;
    if (PyType_Ready(&pyitrace_PyITraceType) < 0)  return;

    obj = Py_InitModule(MODULE, PyITraceMethods);

    Py_INCREF(&pyitrace_PyITraceType);
    PyModule_AddObject(obj, "PyITrace", (PyObject *)&pyitrace_PyITraceType);

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

unsigned long read_addr(int sockd)
{
    void *ip = NULL;
    char buf[16];

    errno = 0;
    if(recv(sockd, buf, 16, 0) == -1 || errno != 0)
        return -1;
    
    ip = *(void **)buf; 

    return (unsigned long)ip;
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
