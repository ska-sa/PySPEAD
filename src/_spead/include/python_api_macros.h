#ifndef PYTHON_API_MACROS_H
#define PYTHON_API_MACROS_H

#include <Python.h>

// Some python macros...
#define QUOTE(a) # a
#define CHK_NULL(a) \
    if (a == NULL) { \
        PyErr_Format(PyExc_MemoryError, "Failed to allocate %s", QUOTE(a)); \
        return NULL; }
#define CHK_STRING(o) \
    if (!PyString_Check(o)) { \
        PyErr_Format(PyExc_ValueError, "expected a string"); \
        return NULL; }
#define CHK_INT(o) \
    if (!PyInt_Check(o)) { \
        PyErr_Format(PyExc_ValueError, "expected an int"); \
        return NULL; }
#define CHK_LONG(o) \
    if (!PyLong_Check(o)) { \
        PyErr_Format(PyExc_ValueError, "expected a long"); \
        return NULL; }
#define CHK_FLOAT(o) \
    if (!PyFloat_Check(o)) { \
        PyErr_Format(PyExc_ValueError, "expected a float"); \
        return NULL; }
#define CHK_COMPLEX(o) \
    if (!PyComplex_Check(o)) { \
        PyErr_Format(PyExc_ValueError, "expected a complex"); \
        return NULL; }

#endif
