#include <python2.7/Python.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/user.h>
#include <syslog.h>


#define TRACE_PROG(name, desc, pstruct, iter, next)\
	{\
    PyObject_HEAD_INIT(NULL)\
    0,                         /*ob_size*/\
    name,                  /*tp_name*/\
    sizeof(pstruct),           /*tp_basicsize*/\
    0,                         /*tp_itemsize*/\
    0,                         /*tp_dealloc*/\
    0,                         /*tp_print*/\
    0,                         /*tp_getattr*/\
    0,                         /*tp_setattr*/\
    0,                         /*tp_compare*/\
    0,                         /*tp_repr*/\
    0,                         /*tp_as_number*/\
    0,                         /*tp_as_sequence*/\
    0,                         /*tp_as_mapping*/\
    0,                         /*tp_hash */\
    0,                         /*tp_call*/\
    0,                         /*tp_str*/\
    0,                         /*tp_getattro*/\
    0,                         /*tp_setattro*/\
    0,                         /*tp_as_buffer*/\
    Py_TPFLAGS_DEFAULT | Py_TPFLAGS_HAVE_ITER,\
    desc,           /* tp_doc */\
    0,  /* tp_traverse */\
    0,  /* tp_clear */\
    0,  /* tp_richcompare */\
    0,  /* tp_weaklistoffset */\
    iter,  /* __iter__() */\
    next/* next() */\
};

typedef struct {
    PyObject_HEAD
    int pid;
    int status;
} trace_prog;

typedef struct instruction_t instruction;

int trace(char *fn, char **argv);
PyObject *trace_iter_process(PyObject *self, PyObject *args);
PyObject *trace_iter_process_iter(PyObject *self);
PyObject *trace_iter_process_next(PyObject *self);
instruction *parent_trace(int pid, unsigned long long *length);

static PyTypeObject trace_type = TRACE_PROG(
	"trace._Iter", 
	"Instruction trace iterator", 
	trace_prog, 
	trace_iter_process_iter,
	trace_iter_process_next)

static PyMethodDef trace_methods[] = {
	{"traceInstructions", trace_iter_process, METH_VARARGS, "Instruction trace iterator"},
	{NULL, NULL, 0, NULL}
};


PyMODINIT_FUNC
inittrace(void)
{
	PyObject *prog;
	
	trace_type.tp_new = PyType_GenericNew;
	if(PyType_Ready(&trace_type) < 0) return;

	prog = Py_InitModule("trace", trace_methods);
	
	Py_INCREF(&trace_type);
	PyModule_AddObject(prog, "_Iter", (PyObject *)&trace_type);
}

PyObject *trace_iter_process(PyObject *self, PyObject *args)
{
    char *fn;
    int child;
    instruction *itrace;
    unsigned long long ilength;
    trace_prog *prog;

	
    if(PyArg_ParseTuple(args, "s", &fn)==0) 
        return NULL;

    child = trace(fn, NULL);

    if(child == 0)
        return NULL;

	prog = PyObject_New(trace_prog, &trace_type);

	if(prog == 0) return NULL;
	
	if(!PyObject_Init((PyObject *)prog, &trace_type)) 
	{
		Py_DECREF(prog);
		return NULL;
	}	
	
	prog->pid = child;
    wait(&prog->status);

	return (PyObject *)prog;
}

PyObject *trace_iter_process_next(PyObject *self)
{
    trace_prog *prog;
    struct user_regs_struct regs;
    unsigned long addr, op;

    prog = (trace_prog *)self;

    waitpid(prog->pid, &(prog->status), 0);

    if(0!=WIFEXITED(prog->status))
    {
        return NULL;
    }

    ptrace(PTRACE_GETREGS, prog->pid, NULL, &regs);


    addr = regs.rip;
    op = ptrace(PTRACE_PEEKDATA, prog->pid, addr, NULL);

    ptrace(PTRACE_SINGLESTEP, prog->pid, NULL, NULL);
	
	return Py_BuildValue("l", addr);

}

PyObject *trace_iter_process_iter(PyObject *self)
{
    Py_INCREF(self);
    return self;
}

int trace(char *fn, char **argv)
{
    int child;

    child = fork();

    if(child == 0)
    {
        /* attach tracing */
        ptrace(PTRACE_TRACEME, 0, NULL, NULL);
        execl(fn, fn, argv, NULL);
    }

    return child;
}

/*
instruction *parent_trace(int pid, unsigned long long *length)
{
    int status;
    instruction *head, *tail;

    *length = 0;
    head = (instruction *)malloc(sizeof(instruction));
    tail = head;

    wait(&status);
    while(1)
    {
        struct user_regs_struct regs;

        ptrace(PTRACE_GETREGS, pid, NULL, &regs);

        tail->addr = regs.rip;
        tail->op = ptrace(PTRACE_PEEKDATA, pid, regs.rip, NULL);

        ptrace(PTRACE_SINGLESTEP, pid, NULL, NULL);

        *length++;
        waitpid(pid, &status, 0);

        if(WIFEXITED(status)) break;

        tail->next = (instruction *)malloc(sizeof(instruction));
        tail = tail->next;
    }

    tail->next = NULL;

    return head;
}

*/
