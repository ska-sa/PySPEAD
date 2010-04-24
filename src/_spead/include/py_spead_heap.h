#ifndef PY_SPEAD_HEAP_H
#define PY_SPEAD_HEAP_H

#include "spead_packet.h"

// Python object that holds a SpeadHeap
typedef struct {
    PyObject_HEAD
    SpeadHeap heap;
    PyObject *list_of_pypkts;
} SpeadHeapObj;

extern PyTypeObject SpeadHeapType;

#endif
