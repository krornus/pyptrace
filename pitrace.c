#include <python2.7/Python.h>

#define DESC "Python instruction trace generator"
#define MODULE "pitrace"
#define ITER_METH "instructions"
#define ITER_METH_DESC "iterate through instructions of given program"
#define ITER_NAME "pitrace.ITraceIter"
#define MAX_ERR_LEN  1024
#define PYERR(exception, fmt, ...)  {\
    char __err_str__[MAX_ERR_LEN];\
    snprintf(__err_str__, MAX_ERR_LEN, fmt, __VA_ARGS__);\
    PyErr_SetString(exception, __err_str__);\
};

#define PYERR_NOARGS(exception, fmt) {\
    char __err_str__[MAX_ERR_LEN];\
    snprintf(__err_str__, MAX_ERR_LEN, fmt);\
    PyErr_SetString(exception, __err_str__);\
};

#define ADDR_SIZE 1024 
#define ELFCLASS32 1
#define ELFCLASS64 2
#define EI_CLASS 4

/*  gcc -shared -I/usr/include/python2.7/ -lpython2.7 -o MODULE.so pyiter.c -fPIC */
PyObject* pitrace_ITraceIter_iter(PyObject *self);
PyObject* pitrace_ITraceIter_next(PyObject *self);

typedef struct {
    PyObject_HEAD
    FILE *pin;
    char *file;
} pitrace_ITraceIter;


static PyTypeObject pitrace_ITraceIterType = {
    PyObject_HEAD_INIT(NULL)
    0,                         
    ITER_NAME,
    sizeof(pitrace_ITraceIter),    
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
    pitrace_ITraceIter_iter,  
    pitrace_ITraceIter_next  
};

static PyObject *pitrace_iterator(PyObject *self, PyObject *args, PyObject *keywd);
PyMODINIT_FUNC init_ITraceIter(void);
int get_arch_bits(char *fn);

static PyMethodDef ITraceMethods[] = {
    /* set flag to accept VARARGS and KEYWORDS, cast init to a PyCFunction */
    {ITER_METH,  (PyCFunction)pitrace_iterator, METH_VARARGS|METH_KEYWORDS, ITER_METH_DESC},
    {NULL, NULL, 0, NULL}        /* Sentinel */
};

PyObject* pitrace_ITraceIter_iter(PyObject *self)
{
    Py_INCREF(self);
    return self;
}

PyObject* pitrace_ITraceIter_next(PyObject *self)
{
    pitrace_ITraceIter *py_ITraceIter;
    py_ITraceIter = (pitrace_ITraceIter *)self;
    char line[ADDR_SIZE];
    unsigned long long addr;
    
    //do
    //{
        errno = 0;
        if(!fgets(line, ADDR_SIZE, py_ITraceIter->pin))
            return NULL;

        PYERR(PyExc_IOError, "debug %s", line); 
        return NULL;

        /* exit condition */
        if(errno != 0)
            return NULL;

        addr = strtoull(line, NULL, 16);
        
    //} while(addr < 0xff);

    /* return a tuple of (pitrace, bar, i) */
	return Py_BuildValue("k", addr);
}

static PyObject *pitrace_iterator(PyObject *self, PyObject *args, PyObject *keywds)
{
    pitrace_ITraceIter *py_ITraceIter;
    static char *pin32 = "./pin/pin -t ./pin/source/tools/ManualExamples/obj-ia32/itrace.so -- ";
    static char *pin64 = "./pin/pin -t ./pin/source/tools/ManualExamples/obj-intel64/itrace.so -- ";

    char *fn, *argv = NULL, *pin, *cmd; /* first positional argument */

    static char *kwlist[] = {"file", "argv", NULL};

    py_ITraceIter = PyObject_New(pitrace_ITraceIter, &pitrace_ITraceIterType);

    if (!PyObject_Init((PyObject *)py_ITraceIter, &pitrace_ITraceIterType)) {
        Py_DECREF(py_ITraceIter);
        return NULL;
    }

    /* parse a required string and optional string */
    if (!PyArg_ParseTupleAndKeywords(
            args, keywds, "s|s", kwlist, &fn, &argv))
    {
        return NULL;
    }

    if (access(fn, F_OK) == -1) {
        PYERR(PyExc_IOError, "No such file or directory: '%s'", fn);
        return NULL;
    }

    
    switch(get_arch_bits(fn)){
        case ELFCLASS32:
            pin = pin32;
            break;
        case ELFCLASS64:
            pin = pin64;
            break;
        case -1:
            return NULL;
        default:
            PYERR(PyExc_IOError, "Invalid architecture for file: '%s' (EI_CLASS is %d)", 
                fn, get_arch_bits(fn));
            return NULL;
    }

    /* anything related to malloc or strcat segfaults */
    PyObject *pin_obj;
    PyObject *fn_obj;

    /* kill me */    
    pin_obj = PyString_FromString(pin);
    fn_obj = PyString_FromString(fn);
    PyString_ConcatAndDel(&pin_obj,fn_obj);

    if(NULL != argv)
    {
        PyObject *ws_obj;
        PyObject *arg_obj;
        ws_obj = PyString_FromString(" ");
        arg_obj = PyString_FromString(argv);
        PyString_ConcatAndDel(&pin_obj,ws_obj);
        PyString_ConcatAndDel(&pin_obj,arg_obj);
    }

    cmd = PyString_AsString(pin_obj);
    Py_DECREF(pin_obj);

    py_ITraceIter->file = fn;
    py_ITraceIter->pin = popen(cmd, "r");

    return (PyObject *)py_ITraceIter;
}


/* file name becomes module name, replace initpitrace with init<file> */
PyMODINIT_FUNC initpitrace(void)
{
    PyObject* obj;

    pitrace_ITraceIterType.tp_new = PyType_GenericNew;
    if (PyType_Ready(&pitrace_ITraceIterType) < 0)  return;

    obj = Py_InitModule(MODULE, ITraceMethods);

    Py_INCREF(&pitrace_ITraceIterType);
    PyModule_AddObject(obj, "ITraceIter", (PyObject *)&pitrace_ITraceIterType);
}

int get_arch_bits(char *fn)
{
    unsigned char arch[1];
    FILE *elf;


    elf = fopen(fn, "r");


    if(NULL==elf)
    {
        PYERR(PyExc_IOError, "Unable to open file '%s'\n\t\t(%d): %s", 
            fn, errno, strerror(errno));
        return -1;
    }
    if(fseek(elf, EI_CLASS, SEEK_SET)==-1)
    {
        PYERR(PyExc_IOError, "Unable to seek in file '%s'\n\t\t(%d): %s", 
            fn, errno, strerror(errno));
        return -1;
    }
    
    errno = 0;
    if(fread(arch, 1, 1, elf)==0 && errno != 0)
    {
        PYERR(PyExc_IOError, "Unable to read from file '%s',\n\t\t(%d): %s", 
            fn, errno, strerror(errno));
        return -1;
    }

    
    return arch[0];
}
