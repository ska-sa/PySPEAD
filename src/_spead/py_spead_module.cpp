#include "include/py_spead_module.h"

/*___                       _ ____            _        _   
/ ___| _ __   ___  __ _  __| |  _ \ __ _  ___| | _____| |_ 
\___ \| '_ \ / _ \/ _` |/ _` | |_) / _` |/ __| |/ / _ \ __|
 ___) | |_) |  __/ (_| | (_| |  __/ (_| | (__|   <  __/ |_ 
|____/| .__/ \___|\__,_|\__,_|_|   \__,_|\___|_|\_\___|\__|
      |_|                                                  */

// Deallocate memory when Python object is deleted
static void SpeadPktObj_dealloc(SpeadPktObj* self) {
    //PyObject_GC_UnTrack(self);
    spead_packet_wipe(&self->pkt);
    self->ob_type->tp_free((PyObject*)self);
}

// Allocate memory for Python object 
static PyObject *SpeadPktObj_new(PyTypeObject *type,
        PyObject *args, PyObject *kwds) {
    SpeadPktObj *self;
    self = (SpeadPktObj *) type->tp_alloc(type, 0);
    return (PyObject *) self;
}

// Initialize object (__init__)
static int SpeadPktObj_init(SpeadPktObj *self) {
    spead_packet_init(&self->pkt);
    return 0;
}

// Unpack header from a string
PyObject *SpeadPktObj_unpack_header(SpeadPktObj *self, PyObject *args) {
    char *data;
    int64_t size;
    if (!PyArg_ParseTuple(args, "s#", &data, &size)) return NULL;
    if (size < SPEAD_ITEM_BYTES) {
        PyErr_Format(PyExc_ValueError, "len(data) < %d", SPEAD_ITEM_BYTES);
        return NULL;
    }
    size = spead_packet_unpack_header(&self->pkt, data);
    if (size == SPEAD_ERR) {
        PyErr_Format(PyExc_ValueError, "data does not represent a SPEAD packet");
        return NULL;
    }
    return Py_BuildValue("l", size);
}

// Unpack items from a string
PyObject *SpeadPktObj_unpack_items(SpeadPktObj *self, PyObject *args) {
    char *data;
    int64_t size;
    if (!PyArg_ParseTuple(args, "s#", &data, &size)) return NULL;
    if (size < self->pkt.n_items * SPEAD_ITEM_BYTES) {
        PyErr_Format(PyExc_ValueError, "len(data) < %d", self->pkt.n_items*SPEAD_ITEM_BYTES);
        return NULL;
    }
    size = spead_packet_unpack_items(&self->pkt, data);
    if (size == SPEAD_ERR) {
        PyErr_Format(PyExc_MemoryError, "in SpeadPacket.unpack_items()");
        return NULL;
    }
    return Py_BuildValue("l", size);
}

// Unpack payload from a string
PyObject *SpeadPktObj_unpack_payload(SpeadPktObj *self, PyObject *args) {
    char *data;
    int64_t size;
    if (!PyArg_ParseTuple(args, "s#", &data, &size)) return NULL;
    if (self->pkt.payload == NULL) {
        PyErr_Format(PyExc_RuntimeError, "SpeadPacket not initialized with PAYLOAD_LENGTH");
        return NULL;
    } else if (size < self->pkt.payload->length) {
        PyErr_Format(PyExc_ValueError, "len(data) < %d", self->pkt.payload->length);
        return NULL;
    }
    size = spead_packet_unpack_payload(&self->pkt, data);
    if (size == SPEAD_ERR) {
        PyErr_Format(PyExc_MemoryError, "in SpeadPacket.unpack_payload()");
        return NULL;
    }
    return Py_BuildValue("l", size);
}

// Unpack all from a string
PyObject *SpeadPktObj_unpack(SpeadPktObj *self, PyObject *args) {
    char *data;
    int64_t size, off, val;
    int flag=1;
    if (!PyArg_ParseTuple(args, "s#", &data, &size)) return NULL;
    if (size >= SPEAD_ITEM_BYTES) {
        off = spead_packet_unpack_header(&self->pkt, data);
        if (off == SPEAD_ERR) {
            PyErr_Format(PyExc_ValueError, "data does not represent a SPEAD packet");
            return NULL;
        }
        if (size >= off + self->pkt.n_items * SPEAD_ITEM_BYTES) {
            val = spead_packet_unpack_items(&self->pkt, data+off);
            if (val == SPEAD_ERR) {
                PyErr_Format(PyExc_MemoryError, "in SpeadPacket.unpack()");
                return NULL;
            } else if (self->pkt.payload == NULL) {
                PyErr_Format(PyExc_RuntimeError, "SpeadPacket not initialized with PAYLOAD_LENGTH");
                return NULL;
            }
            off += val;
            if (size >= off + self->pkt.payload->length) {
                val = spead_packet_unpack_payload(&self->pkt, data+off);
                if (val == SPEAD_ERR) {
                    PyErr_Format(PyExc_MemoryError, "in SpeadPacket.unpack()");
                    return NULL;
                }
                off += val;
                flag = 0;
            }
        }
    }
    if (flag) {
        PyErr_Format(PyExc_ValueError, "Insufficient data to unpack packet");
        return NULL;
    }
    return Py_BuildValue("l", off);
}

// Get packet payload
PyObject *SpeadPktObj_get_payload(SpeadPktObj *self) {
    if (self->pkt.payload == NULL || self->pkt.payload->length == 0) {
        return Py_BuildValue("s", "");
    } else {
        return Py_BuildValue("s#", self->pkt.payload->data, self->pkt.payload->length);
    }
}

// Get packet items
PyObject *SpeadPktObj_get_rawitems(SpeadPktObj *self) {
    PyObject *tup=PyTuple_New(self->pkt.n_items);
    int i;
    for (i=0; i < self->pkt.n_items; i++) {
        //printf("get_items,item%d: is_ext=%d, id=%d, val=%d\n", i, self->pkt.items[i].is_ext,
        //    self->pkt.items[i].id, self->pkt.items[i].val);
        PyTuple_SET_ITEM(tup, i, 
            Py_BuildValue("(iil)", self->pkt.raw_items[i].is_ext, self->pkt.raw_items[i].id,
            self->pkt.raw_items[i].val));
    }
    return tup;
}

// Bind methods to object
static PyMethodDef SpeadPktObj_methods[] = {
    {"get_items", (PyCFunction)SpeadPktObj_get_rawitems, METH_NOARGS,
        "get_rawitems()\nReturn a tuple of (is_ext,id,val) raw items in the header of this packet."},
    //{"set_items", (PyCFunction)SpeadPktObj_set_payload, METH_VARARGS,
    //    "set_items()\nSet the raw items in the header of this packet."},
    {"get_payload", (PyCFunction)SpeadPktObj_get_payload, METH_NOARGS,
        "get_payload()\nReturn the payload of this packet."},
    //{"set_payload", (PyCFunction)SpeadPktObj_set_payload, METH_VARARGS,
    //    "set_payload()\nSet the payload of this packet to a binary string."},
    {"unpack_header", (PyCFunction)SpeadPktObj_unpack_header, METH_VARARGS,
        "unpack_header(data)\nSet packet header from binary string. Raise ValueError if data doesn't match packet format.  Otherwise, return # bytes read."},
    {"unpack_items", (PyCFunction)SpeadPktObj_unpack_items, METH_VARARGS,
        "unpack_items(data)\nSet packet items from binary string. Raise ValueError if insufficient data.  Otherwise, return # bytes read."},
    {"unpack_payload", (PyCFunction)SpeadPktObj_unpack_payload, METH_VARARGS,
        "unpack_payload(data)\nRead packet payload from binary string. Raise ValueError if insufficient data.  Otherwise, return # bytes read."},
    {"unpack", (PyCFunction)SpeadPktObj_unpack, METH_VARARGS,
        "unpack(data)\nRead entire packet from binary string. Raise ValueError if failure.  Otherwise, return # bytes read."},
    //{"pack", (PyCFunction)SpeadPktObj_pack, METH_NOARGS,
    //    "pack()\nReturn packet as a binary string."},
    {NULL}  // Sentinel
};

static PyMemberDef SpeadPktObj_members[] = {
    {"n_items", T_USHORT, offsetof(SpeadPktObj, pkt) +
        offsetof(SpeadPacket, n_items), 0, "n_items"},
    {"frame_cnt", T_LONG, offsetof(SpeadPktObj, pkt) +
        offsetof(SpeadPacket, frame_cnt), 0, "frame_cnt"},
    {NULL}  /* Sentinel */
};

PyTypeObject SpeadPktType = {
    PyObject_HEAD_INIT(NULL)
    0,                         /*ob_size*/
    "SpeadPacket", /*tp_name*/
    sizeof(SpeadPktObj), /*tp_basicsize*/
    0,                         /*tp_itemsize*/
    (destructor)SpeadPktObj_dealloc, /*tp_dealloc*/
    0,                         /*tp_print*/
    0,                         /*tp_getattr*/
    0,                         /*tp_setattr*/
    0,                         /*tp_compare*/
    0,                         /*tp_repr*/
    0,                         /*tp_as_number*/
    0,                         /*tp_as_sequence*/
    0,                         /*tp_as_mapping*/
    0,                         /*tp_hash */
    0,                         /*tp_call*/
    0,                         /*tp_str*/
    0,                         /*tp_getattro*/
    0,                         /*tp_setattro*/
    0,                         /*tp_as_buffer*/
    Py_TPFLAGS_DEFAULT | Py_TPFLAGS_BASETYPE,        /*tp_flags*/
    "This class provides a basic interface for examining Spead packets.  SpeadPacket()",       /* tp_doc */
    0,                     /* tp_traverse */
    0,                     /* tp_clear */
    0,                     /* tp_richcompare */
    0,                     /* tp_weaklistoffset */
    0,                     /* tp_iter */
    0,                     /* tp_iternext */
    SpeadPktObj_methods,     /* tp_methods */
    SpeadPktObj_members,     /* tp_members */
    0,                         /* tp_getset */
    0,                         /* tp_base */
    0,                         /* tp_dict */
    0,                         /* tp_descr_get */
    0,                         /* tp_descr_set */
    0,                         /* tp_dictoffset */
    (initproc)SpeadPktObj_init,      /* tp_init */
    0,                         /* tp_alloc */
    SpeadPktObj_new,       /* tp_new */
};

/*___                       _ _____                         
/ ___| _ __   ___  __ _  __| |  ___| __ __ _ _ __ ___   ___ 
\___ \| '_ \ / _ \/ _` |/ _` | |_ | '__/ _` | '_ ` _ \ / _ \
 ___) | |_) |  __/ (_| | (_| |  _|| | | (_| | | | | | |  __/
|____/| .__/ \___|\__,_|\__,_|_|  |_|  \__,_|_| |_| |_|\___|
      |_|                                                   */

// Deallocate memory when Python object is deleted
static void SpeadFrameObj_dealloc(SpeadFrameObj* self) {
    //PyObject_GC_UnTrack(self);
    spead_frame_wipe(&self->frame);
    self->ob_type->tp_free((PyObject*)self);
}

// Allocate memory for Python object 
static PyObject *SpeadFrameObj_new(PyTypeObject *type,
        PyObject *args, PyObject *kwds) {
    SpeadFrameObj *self;
    self = (SpeadFrameObj *) type->tp_alloc(type, 0);
    return (PyObject *) self;
}

// Initialize object (__init__)
static int SpeadFrameObj_init(SpeadFrameObj *self) {
    spead_frame_init(&self->frame);
    return 0;
}

// Add a packet to the frame
PyObject *SpeadFrameObj_add_packet(SpeadFrameObj *self, PyObject *args) {
    SpeadPktObj *pkto;
    SpeadPacket *pkt;
    if (!PyArg_ParseTuple(args, "O!", &SpeadPktType, &pkto)) return NULL;
    pkt = spead_packet_clone(&pkto->pkt);  // Clone packet b/c Python need to keep the original
    if (pkt == NULL) {
        PyErr_Format(PyExc_MemoryError, "Could not copy SpeadPacket");
        return NULL;
    } else if (spead_frame_add_packet(&self->frame, pkt) == SPEAD_ERR) {
        // Clean up cloned packet--we didn't use it
        spead_packet_wipe(pkt);
        free(pkt);
        PyErr_Format(PyExc_ValueError, "SpeadPacket not part of frame, or it is incorrectly initialized");
        return NULL;
    }
    Py_INCREF(Py_None);
    return Py_None;
}

// Add a packet to the frame
PyObject *SpeadFrameObj_finalize(SpeadFrameObj *self) {
    if (spead_frame_finalize(&self->frame) == SPEAD_ERR) {
        PyErr_Format(PyExc_MemoryError, "Memory allocation failed in SpeadFrame.finalize()");
        return NULL;
    }
    Py_INCREF(Py_None);
    return Py_None;
}

// Get the final items from a frame
PyObject *SpeadFrameObj_get_items(SpeadFrameObj *self) {
    int result;
    SpeadItem *item;
    PyObject *rv;
    if (self->frame.head_item == NULL) {
        PyErr_Format(PyExc_RuntimeError, "SpeadFrame was not finalized before SpeadFrame.get_items() was called");
        return NULL;
    }
    rv = PyDict_New();
    if (rv == NULL) {
        PyErr_Format(PyExc_MemoryError, "Memory allocation failed in SpeadFrame.finalize()");
        return NULL;
    }
    item = self->frame.head_item;
    while (item != NULL) {
        if (item->is_valid) {
            if (item->length == 0) {
                result = PyDict_SetItem(rv, PyInt_FromLong(item->id), PyString_FromString(""));
            } else {
                result = PyDict_SetItem(rv, PyInt_FromLong(item->id), 
                    PyString_FromStringAndSize(item->val,item->length));
            }
            if (result == -1) {
                PyErr_Format(PyExc_MemoryError, "Memory allocation failed in SpeadFrame.get_items()");
                return NULL;
            }
        }
        item = item->next;
    }
    return rv;
}

// Bind methods to object
static PyMethodDef SpeadFrameObj_methods[] = {
    {"add_packet", (PyCFunction)SpeadFrameObj_add_packet, METH_VARARGS,
        "add_packet(SpeadPacket)\nAdd SpeadPacket to this frame.  A fresh SpeadFrame will accept packets with any FRAME_CNT, but thereafter will only accept ones with the same FRAME_CNT.  Raise ValueError on failure."},
    {"finalize", (PyCFunction)SpeadFrameObj_finalize, METH_NOARGS,
        "finalize()\nTry to finalize the values of all items in this frame.  Check SpeadFrame.is_valid to see if all values were able to be finalized."},
    {"get_items", (PyCFunction)SpeadFrameObj_get_items, METH_NOARGS,
        "get_items()\nReturn a dictionary of id:value pairs for all valid items in a finalized frame."},
    {NULL}  // Sentinel
};

static PyMemberDef SpeadFrameObj_members[] = {
    {"frame_cnt", T_LONG, offsetof(SpeadFrameObj, frame) +
        offsetof(SpeadFrame, frame_cnt), 0, "frame_cnt"},
    {"is_valid", T_BOOL, offsetof(SpeadFrameObj, frame) +
        offsetof(SpeadFrame, is_valid), 0, "is_valid"},
    {NULL}  /* Sentinel */
};

PyTypeObject SpeadFrameType = {
    PyObject_HEAD_INIT(NULL)
    0,                         /*ob_size*/
    "SpeadFrame", /*tp_name*/
    sizeof(SpeadFrameObj), /*tp_basicsize*/
    0,                         /*tp_itemsize*/
    (destructor)SpeadFrameObj_dealloc, /*tp_dealloc*/
    0,                         /*tp_print*/
    0,                         /*tp_getattr*/
    0,                         /*tp_setattr*/
    0,                         /*tp_compare*/
    0,                         /*tp_repr*/
    0,                         /*tp_as_number*/
    0,                         /*tp_as_sequence*/
    0,                         /*tp_as_mapping*/
    0,                         /*tp_hash */
    0,                         /*tp_call*/
    0,                         /*tp_str*/
    0,                         /*tp_getattro*/
    0,                         /*tp_setattro*/
    0,                         /*tp_as_buffer*/
    Py_TPFLAGS_DEFAULT | Py_TPFLAGS_BASETYPE,        /*tp_flags*/
    "This class provides a basic interface for examining Spead frames.  SpeadFrame()",       /* tp_doc */
    0,                     /* tp_traverse */
    0,                     /* tp_clear */
    0,                     /* tp_richcompare */
    0,                     /* tp_weaklistoffset */
    0,                     /* tp_iter */
    0,                     /* tp_iternext */
    SpeadFrameObj_methods,     /* tp_methods */
    SpeadFrameObj_members,     /* tp_members */
    0,                         /* tp_getset */
    0,                         /* tp_base */
    0,                         /* tp_dict */
    0,                         /* tp_descr_get */
    0,                         /* tp_descr_set */
    0,                         /* tp_dictoffset */
    (initproc)SpeadFrameObj_init,      /* tp_init */
    0,                         /* tp_alloc */
    SpeadFrameObj_new,       /* tp_new */
};

/*___         __  __           ____             _        _   
| __ ) _   _ / _|/ _| ___ _ __/ ___|  ___   ___| | _____| |_ 
|  _ \| | | | |_| |_ / _ \ '__\___ \ / _ \ / __| |/ / _ \ __|
| |_) | |_| |  _|  _|  __/ |   ___) | (_) | (__|   <  __/ |_ 
|____/ \__,_|_| |_|  \___|_|  |____/ \___/ \___|_|\_\___|\__| */

// Deallocate memory when Python object is deleted
static void BsockObject_dealloc(BsockObject* self) {
    buffer_socket_wipe(&self->bs);
    if (self->pycallback) Py_DECREF(self->pycallback);
    self->ob_type->tp_free((PyObject*)self);
}

// Allocate memory for Python object 
static PyObject *BsockObject_new(PyTypeObject *type,
        PyObject *args, PyObject *kwds) {
    BsockObject *self;
    self = (BsockObject *) type->tp_alloc(type, 0);
    return (PyObject *) self;
}

// Initialize object (__init__)
static int BsockObject_init(BsockObject *self, PyObject *args, PyObject *kwds) {
    int pkt_count=128;
    static char *kwlist[] = {"pkt_count", NULL};
    if (!PyArg_ParseTupleAndKeywords(args, kwds,"|i", kwlist, &pkt_count))
        return -1;
    buffer_socket_init(&self->bs, pkt_count);
    self->pycallback = NULL;
    return 0;
}

static PyObject * BsockObject_start(BsockObject *self, PyObject *args) {
    int port;
    if (!PyArg_ParseTuple(args, "i", &port)) return NULL;
    PyEval_InitThreads();
    buffer_socket_start(&self->bs, port);
    Py_INCREF(Py_None);
    return Py_None;
}

static PyObject * BsockObject_stop(BsockObject *self) {
    //PyThreadState *_save;
    // Release Python Global Interpreter Lock so that a python callback end
    Py_BEGIN_ALLOW_THREADS
    buffer_socket_stop(&(self->bs));
    // Reacquire Python Global Interpreter Lock
    Py_END_ALLOW_THREADS
    Py_INCREF(Py_None);
    return Py_None;
}

int wrap_bs_pycallback(SpeadPacket *pkt, void *userdata) {
    BsockObject *bso;
    SpeadPktObj *pkto;
    PyObject *arglist, *rv;
    PyGILState_STATE gstate;
    // Acquire Python Global Interpeter Lock
    gstate = PyGILState_Ensure();
    bso = (BsockObject *) userdata;  // Recast userdata as reference to a bs
    // Wrap pkt into a SpeadPacket python object
    pkto = PyObject_New(SpeadPktObj, &SpeadPktType);
    pkto->pkt.n_items = pkt->n_items;
    pkto->pkt.frame_cnt = pkt->frame_cnt;
    // Deviously steal the references to items and payload from this pkt!
    pkto->pkt.raw_items = pkt->raw_items;
    pkto->pkt.payload = pkt->payload;
    spead_packet_init(pkt);  // Clears out the packet so that only we can free items and payload
    arglist = Py_BuildValue("(O)", (PyObject *)pkto);
    // Call the python callback with the wrapped-up SpeadPacket
    rv = PyEval_CallObject(bso->pycallback, arglist);
    Py_DECREF(arglist);
    if (rv == NULL) {
        PyGILState_Release(gstate);
        return 1;
    }
    Py_DECREF(rv);
    // Release Python Global Interpeter Lock
    PyGILState_Release(gstate);
    return 0;
}

// Routine for setting a python callback for BufferSocket data output
static PyObject * BsockObject_set_callback(BsockObject *self, PyObject *args){
    PyObject *cbk;
    PyErr_Clear();
    if (!PyArg_ParseTuple(args, "O", &cbk)) return NULL;
    if (!PyCallable_Check(cbk)) {
        PyErr_SetString(PyExc_TypeError, "parameter must be callable");
        return NULL;
    }
    Py_INCREF(cbk);
    if (self->pycallback != NULL) Py_DECREF(self->pycallback);
    self->bs.userdata = (void *)self;
    self->pycallback = cbk;
    buffer_socket_set_callback(&self->bs, &wrap_bs_pycallback);
    Py_INCREF(Py_None);
    return Py_None;
}

// Routine for removing a python callback for data output
static PyObject * BsockObject_unset_callback(BsockObject *self) {
    buffer_socket_set_callback(&self->bs, &default_callback);
    if (self->pycallback != NULL) Py_DECREF(self->pycallback);
    self->pycallback = NULL;
    self->bs.userdata = NULL;
    Py_INCREF(Py_None);
    return Py_None;
}

// Get status of socket
static PyObject * BsockObject_is_running(BsockObject *self) {
    return Py_BuildValue("i", self->bs.run_threads);
}

// Bind methods to object
static PyMethodDef BsockObject_methods[] = {
    {"start", (PyCFunction)BsockObject_start, METH_VARARGS,
        "start(port)\nBegin listening for UDP packets on the specified port."},
    {"stop", (PyCFunction)BsockObject_stop, METH_NOARGS,
        "stop()\nHalt listening for UDP packets."},
    {"set_callback", (PyCFunction)BsockObject_set_callback, METH_VARARGS,
        "set_callback(cbk)\nSet a callback function for output data from a BufferSocket.  If cbk is a CollateBuffer, a special handler is used that feeds data into the CollateBuffer without entering back into Python (for speed).  Otherwise, cbk should be a function that accepts a single argument: a binary string containing packet data."},
    {"unset_callback", (PyCFunction)BsockObject_unset_callback, METH_NOARGS,
        "unset_callback()\nReset the callback to the default."},
    {"is_running", (PyCFunction)BsockObject_is_running, METH_NOARGS,
        "is_running()\nReturn 1 if receiver is running, 0 otherwise."},
    {NULL}  // Sentinel
};

PyTypeObject BsockType = {
    PyObject_HEAD_INIT(NULL)
    0,                         /*ob_size*/
    "_spead.BufferSocket", /*tp_name*/
    sizeof(BsockObject), /*tp_basicsize*/
    0,                         /*tp_itemsize*/
    (destructor)BsockObject_dealloc, /*tp_dealloc*/
    0,                         /*tp_print*/
    0,                         /*tp_getattr*/
    0,                         /*tp_setattr*/
    0,                         /*tp_compare*/
    0,                         /*tp_repr*/
    0,                         /*tp_as_number*/
    0,                         /*tp_as_sequence*/
    0,                         /*tp_as_mapping*/
    0,                         /*tp_hash */
    0,                         /*tp_call*/
    0,                         /*tp_str*/
    0,                         /*tp_getattro*/
    0,                         /*tp_setattro*/
    0,                         /*tp_as_buffer*/
    Py_TPFLAGS_DEFAULT | Py_TPFLAGS_BASETYPE,        /*tp_flags*/
    "A ring-buffered, multi-threaded socket interface for holding Spead packets.  BufferSocket(pkt_count=128)",       /* tp_doc */
    0,                     /* tp_traverse */
    0,                     /* tp_clear */
    0,                     /* tp_richcompare */
    0,                     /* tp_weaklistoffset */
    0,                     /* tp_iter */
    0,                     /* tp_iternext */
    BsockObject_methods,     /* tp_methods */
    0,                       /* tp_members */
    0,                         /* tp_getset */
    0,                         /* tp_base */
    0,                         /* tp_dict */
    0,                         /* tp_descr_get */
    0,                         /* tp_descr_set */
    0,                         /* tp_dictoffset */
    (initproc)BsockObject_init,      /* tp_init */
    0,                         /* tp_alloc */
    BsockObject_new,       /* tp_new */
};

/*___                       _   __  __           _       _      
/ ___| _ __   ___  __ _  __| | |  \/  | ___   __| |_   _| | ___ 
\___ \| '_ \ / _ \/ _` |/ _` | | |\/| |/ _ \ / _` | | | | |/ _ \
 ___) | |_) |  __/ (_| | (_| | | |  | | (_) | (_| | |_| | |  __/
|____/| .__/ \___|\__,_|\__,_| |_|  |_|\___/ \__,_|\__,_|_|\___|
      |_|                                                       */

// Module methods
static PyMethodDef spead_methods[] = {
    {NULL}  /* Sentinel */
};

#ifndef PyMODINIT_FUNC  /* declarations for DLL import/export */
#define PyMODINIT_FUNC void
#endif

// Module init
PyMODINIT_FUNC init_spead(void) {
    PyObject* m;
    SpeadPktType.tp_new = PyType_GenericNew;
    BsockType.tp_new = PyType_GenericNew;
    if (PyType_Ready(&SpeadPktType) < 0) return;
    if (PyType_Ready(&SpeadFrameType) < 0) return;
    if (PyType_Ready(&BsockType) < 0) return;
    m = Py_InitModule3("_spead", spead_methods,
    "A module for handling low-level (high performance) SPEAD packet manipulation.");
    Py_INCREF(&BsockType);
    PyModule_AddObject(m, "BufferSocket", (PyObject *)&BsockType);
    Py_INCREF(&SpeadFrameType);
    PyModule_AddObject(m, "SpeadFrame", (PyObject *)&SpeadFrameType);
    Py_INCREF(&SpeadPktType);
    PyModule_AddObject(m, "SpeadPacket", (PyObject *)&SpeadPktType);
}

