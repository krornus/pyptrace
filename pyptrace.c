#include <python2.7/Python.h>
#include <sys/personality.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/user.h>
#include <syslog.h>
#include <stdint.h>
#include <inttypes.h>

/*  gcc -shared -I/usr/include/python2.7/ -lpython2.7 -o pyptrace.so pyptrace.c -fPIC */

#define PIN_PATH "./pin/pin"
#define ITRACE_PATH64 "./pin/source/tools/ManualExamples/obj-intel64/itrace.so"
#define ITRACE_PATH32 "./pin/source/tools/ManualExamples/obj-ia32/itrace.so" 
#define ADDR_SIZE 18
#define ELFCLASS32 1
#define ELFCLASS64 2
#define EI_CLASS 4


typedef struct {
    PyObject_HEAD
    unsigned int pid;
    int status;
} pyptrace_Instr;

PyObject* pyptrace_Instr_iter(PyObject *self);
PyObject* pyptrace_Instr_iternext(PyObject *self);
static PyObject *pyptrace_instructions(PyObject *self, PyObject *args, PyObject *keywd);
PyMODINIT_FUNC initpyptrace(void);
int get_arch_bits(char *fn);
void init_reader();
char *next_addr();
int run(char *fn, char **argv);

int fd[2];
FILE *fs;

static PyTypeObject pyptrace_InstrType = {
    PyObject_HEAD_INIT(NULL)
    0,                         
    "pyptrace._Instr",         
    sizeof(pyptrace_Instr),    
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
    "Instruction trace iterator", 
    0,  
    0,  
    0,  
    0,  
    pyptrace_Instr_iter,  
    pyptrace_Instr_iternext  
};


PyObject* pyptrace_Instr_iter(PyObject *self)
{
    Py_INCREF(self);
    return self;
}


PyObject* pyptrace_Instr_iternext(PyObject *self)
{
    char line[ADDR_SIZE];
    fgets(line, ADDR_SIZE, fs);

	return Py_BuildValue("s", &(line[0]));
}



static PyObject *pyptrace_instructions(PyObject *self, PyObject *args, PyObject *keywds)
{
    char *fn, **argv, *in;
    int child, argc;

	PyObject *obj_argv;

    static char *kwlist[] = {"path", "argv", "stdin", NULL};

    pyptrace_Instr *py_instr;
	
	argc = -1;
    py_instr = PyObject_New(pyptrace_Instr, &pyptrace_InstrType);
    if (!py_instr) return NULL;

    if (!PyObject_Init((PyObject *)py_instr, &pyptrace_InstrType)) {
        Py_DECREF(py_instr);
        return NULL;
    }

	if (!PyArg_ParseTupleAndKeywords(args, keywds, "s|O!s", kwlist, 
            &fn, 
            &PyList_Type, &obj_argv, 
            &in))
        return NULL;

    if(access(fn, F_OK ) == -1)
    {
        char err[1024];
        sprintf(err, "No such file or directory: '%s'", fn);
        PyErr_SetString(PyExc_IOError, err);
        return NULL;
    }

	if(NULL!=obj_argv)
		argc = PyList_Size(obj_argv);

	if(argc < 1)
	{
		argv = NULL;
	}
	else
	{
		argv = (char**)malloc(sizeof(char *)*(argc+1));	

		if(NULL == argv)
			return NULL;

		for(int i = 0; i < argc; i++)
		{
			PyObject *str_arg;

			str_arg = PyList_GetItem(obj_argv, i);	
			argv[i] = PyString_AsString(str_arg);	
		}
        argv[argc] = 0;
	}

    if(run(fn, NULL) < 0)
        return NULL;

    return (PyObject *)py_instr;
}

static PyMethodDef PyPtraceMethods[] = {
    {"instructions",  (PyCFunction)pyptrace_instructions, METH_VARARGS|METH_KEYWORDS, "Iterator for and instruction trace"},
    {NULL, NULL, 0, NULL}        /* Sentinel */
};


PyMODINIT_FUNC initpyptrace(void)
{
    PyObject* obj;

    pyptrace_InstrType.tp_new = PyType_GenericNew;
    if (PyType_Ready(&pyptrace_InstrType) < 0)  return;

    obj = Py_InitModule("pyptrace", PyPtraceMethods);

    Py_INCREF(&pyptrace_InstrType);
    PyModule_AddObject(obj, "_Instr", (PyObject *)&pyptrace_InstrType);
}


int run(char *fn, char **argv)
{
    int arch, child;
    char *tracer;
    
    arch = get_arch_bits(fn);

    if(arch == ELFCLASS32)
    {
        tracer = ITRACE_PATH32;
    }
    else if(arch == ELFCLASS64)
    {
        tracer = ITRACE_PATH64;
    }
    else
    {
        fprintf(stderr, "Invalid architecture for file '%s'\n", fn);
        return -1;
    }

    printf("using '%s'\n", tracer);

    pipe(fd);

    child = fork();

    if(child == 0)
    {
        /* child produces stdout */
        close(fd[0]);
        dup2(fd[1], STDOUT_FILENO);

        if(execl(PIN_PATH, PIN_PATH, "-t", tracer, "--", fn, (char *)0) < 0)
        {
            perror("execl");
            return -1;
        }
    }
    else
    {
        init_reader();
    }

    return 0;
}

void init_reader()
{
    close(fd[1]);
    fs=fdopen(fd[0],"r");
}

int get_arch_bits(char *fn)
{
    unsigned char arch;
    FILE *elf;

    elf = fopen(fn, "r");
    if(NULL==elf)
    {
        perror("fopen");
        return -1;
    }
    if(fseek(elf, EI_CLASS, SEEK_SET)==-1)
    {
        perror("fseek");
        return -1;
    }
    
    if(fread(&arch, 1, 1, elf)==-1)
    {
        perror("fread");
        return -1;
    }
    

    return arch;
}
