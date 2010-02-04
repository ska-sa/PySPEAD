#ifndef PY_SPEAD_FRAME_H
#define PY_SPEAD_FRAME_H

#include "spead_packet.h"

// Python object that holds a SpeadFrame
typedef struct {
    PyObject_HEAD
    SpeadFrame frame;
    PyObject *list_of_pypkts;
} SpeadFrameObj;

extern PyTypeObject SpeadFrameType;

#endif
