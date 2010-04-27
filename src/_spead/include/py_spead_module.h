#ifndef PY_SPEAD_MODULE_H
#define PY_SPEAD_MODULE_H

#define PY_SSIZE_T_CLEAN
#include <Python.h>
#include "structmember.h"
#include "python_api_macros.h"
#include "py_spead_packet.h"
#include "py_spead_heap.h"
#include "py_buffer_socket.h"

#define T_INT64 (sizeof(long) < 8 ? T_LONGLONG : T_LONG)
#define BUILDLONG (sizeof(long) < 8 ? "L" : "l")
#endif
