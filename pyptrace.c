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


typedef struct {
    PyObject_HEAD
    unsigned int pid;
    int status;
} pyptrace_Instr;

PyObject* pyptrace_Instr_iter(PyObject *self);
PyObject* pyptrace_Instr_iternext(PyObject *self);
static PyObject *pyptrace_instructions(PyObject *self, PyObject *args, PyObject *keywd);
PyMODINIT_FUNC initspam(void);
int trace(char *fn, char **argv, char *stdin);

int fd[2];


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
    pyptrace_Instr *py_instr;
    struct user_regs_struct regs;
    unsigned int op;

    py_instr = (pyptrace_Instr *)self;

    if(0!=WIFEXITED(py_instr->status))
    {
        return NULL;
    }

    
    errno = 0;
    ptrace(PTRACE_GETREGS, py_instr->pid, &regs, &regs);
    if(errno != 0)
    {
        char *err;
        sprintf(err, "Failed to retrieve registers:\n\tError code %d (%s)\n", 
            errno, strerror(errno));
        PyErr_SetString(PyExc_IOError, err);
        return NULL;
    }

    errno = 0;
    op = ptrace(PTRACE_PEEKDATA, py_instr->pid, regs.rip, NULL);

    if(errno != 0)
    {
        char *err;
        sprintf(err, "Failed to retrieve data at address 0x%x:\n\tError code %d (%s)\n", 
            regs.rip, errno, strerror(errno));
        PyErr_SetString(PyExc_IOError, err);
        return NULL;
    }


    ptrace(PTRACE_SINGLESTEP, py_instr->pid, NULL, NULL);
    waitpid(py_instr->pid, &py_instr->status, 0);

	return Py_BuildValue("(kkk)", py_instr->pid, regs.rip, op);
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

   
    child = trace(fn, argv, in);

    if(child == 0) return NULL;

    py_instr->pid = child;
    wait(&py_instr->status);

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


int trace(char *fn, char **argv, char *in)
{
    int child;

    personality(ADDR_NO_RANDOMIZE);
    
    pipe(fd);
    child = fork();

    if(child == 0)
    {
        close(fd[1]);
        dup2(fd[0], STDIN_FILENO);
        
        /* attach tracing */
        ptrace(PTRACE_TRACEME, 0, NULL, NULL);
        execvp(fn, argv);
    }
    else
    {
        close(fd[0]);
        write(fd[1], in, strlen(in));
    }

    return child;
}
