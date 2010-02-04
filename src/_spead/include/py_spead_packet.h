#ifndef PY_SPEAD_PACKET_H
#define PY_SPEAD_PACKET_H

#include "spead_packet.h"

// Python object that holds a SpeadPacket
typedef struct {
    PyObject_HEAD
    SpeadPacket *pkt;
} SpeadPktObj;

extern PyTypeObject SpeadPktType;

#endif
