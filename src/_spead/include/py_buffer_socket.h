#ifndef PY_BUFFFER_SOCKET_H
#define PY_BUFFFER_SOCKET_H

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>

#include <Python.h>
#include "python_api_macros.h"
#include "structmember.h"
#include "buffer_socket.h"

// Python object that holds a BufferSocket
typedef struct {
    PyObject_HEAD
    BufferSocket bs;
    PyObject *pycallback;
} BsockObject;

extern PyTypeObject BsockType;

#endif
