#include <python2.7/Python.h>

#define DESC "Foo bar"
#define MODULE "foo"
#define ITER_METH "iter"
#define ITER_METH_DESC "iter foo bar"
#define ITER_NAME "foo.FooIter"
#define MAX_ERR_LEN  1024
#define PYRAISE(exception, fmt, ...)  {\
    char __err_str__[MAX_ERR_LEN];\
    snprintf(__err_str__, MAX_ERR_LEN, fmt, __VA_ARGS__);\
    PyErr_SetString(exception, __err_str__);\
    return NULL;\
};

/*  gcc -shared -I/usr/include/python2.7/ -lpython2.7 -o MODULE.so pyiter.c -fPIC */
PyObject* foo_FooIter_iter(PyObject *self);
PyObject* foo_FooIter_next(PyObject *self);

typedef struct {
    PyObject_HEAD
    int i;
    char *foo;
    char *bar;
} foo_FooIter;


static PyTypeObject foo_FooIterType = {
    PyObject_HEAD_INIT(NULL)
    0,                         
    ITER_NAME,
    sizeof(foo_FooIter),    
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
    foo_FooIter_iter,  
    foo_FooIter_next  
};

static PyObject *foo_iterator(PyObject *self, PyObject *args, PyObject *keywd);
PyMODINIT_FUNC init_FooIter(void);

static PyMethodDef FooMethods[] = {
    /* set flag to accept VARARGS and KEYWORDS, cast init to a PyCFunction */
    {ITER_METH,  (PyCFunction)foo_iterator, METH_VARARGS|METH_KEYWORDS, ITER_METH_DESC},
    {NULL, NULL, 0, NULL}        /* Sentinel */
};

PyObject* foo_FooIter_iter(PyObject *self)
{
    Py_INCREF(self);
    return self;
}

PyObject* foo_FooIter_next(PyObject *self)
{
    foo_FooIter *py_FooIter;
    py_FooIter = (foo_FooIter *)self;

    /* exit condition */
    if(py_FooIter->i > 9)
        return NULL;

    /* return a tuple of (foo, bar, i) */
	return Py_BuildValue("(ssi)", py_FooIter->foo, py_FooIter->bar, py_FooIter->i++);
}

static PyObject *foo_iterator(PyObject *self, PyObject *args, PyObject *keywds)
{
    foo_FooIter *py_FooIter;
    char *foo; /* first positional argument */
    char *bar = NULL; /* first named argument, set default to None*/

    static char *kwlist[] = {"foo", "bar", NULL};

    py_FooIter = PyObject_New(foo_FooIter, &foo_FooIterType);

    if (!PyObject_Init((PyObject *)py_FooIter, &foo_FooIterType)) {
        Py_DECREF(py_FooIter);
        return NULL;
    }

    /* parse a required string and optional string */
    if (!PyArg_ParseTupleAndKeywords(
            args, keywds, "s|s", kwlist, &foo, &bar))
    {
        return NULL;
    }

    if (access(foo, F_OK) == -1)
        PYRAISE(PyExc_IOError, "No such file or directory: '%s'", foo);

    py_FooIter->i = 0;
    py_FooIter->foo = foo;
    py_FooIter->bar = bar;

    return (PyObject *)py_FooIter;
}


/* file name becomes module name, replace initfoo with init<file> */
PyMODINIT_FUNC initfoo(void)
{
    PyObject* obj;

    foo_FooIterType.tp_new = PyType_GenericNew;
    if (PyType_Ready(&foo_FooIterType) < 0)  return;

    obj = Py_InitModule(MODULE, FooMethods);

    Py_INCREF(&foo_FooIterType);
    PyModule_AddObject(obj, "FooIter", (PyObject *)&foo_FooIterType);
}
