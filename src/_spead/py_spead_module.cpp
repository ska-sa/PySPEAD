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
    spead_free_packet(&(self->pkt));
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
    spead_init_packet(&(self->pkt));
    return 0;
}

// Unpack header from a string
PyObject *SpeadPktObj_unpack_hdr(SpeadPktObj *self, PyObject *args) {
    char *data;
    int size;
    if (!PyArg_ParseTuple(args, "s#", &data, &size)) return NULL;
    if (size < 8) {
        PyErr_Format(PyExc_ValueError, "len(data) < 8");
        return NULL;
    }
    size = spead_unpack_hdr(&self->pkt, data);
    if (size < 0) {
        PyErr_Format(PyExc_ValueError, "data does not represent a SPEAD packet");
        return NULL;
    }
    return Py_BuildValue("i", size);
}

// Unpack items from a string
PyObject *SpeadPktObj_unpack_items(SpeadPktObj *self, PyObject *args) {
    char *data;
    int size;
    if (!PyArg_ParseTuple(args, "s#", &data, &size)) return NULL;
    if (size < self->pkt.n_items * SPEAD_ITEM_BYTES) {
        PyErr_Format(PyExc_ValueError, "len(data) < %d", self->pkt.n_items*8);
        return NULL;
    }
    size = spead_unpack_items(&self->pkt, data);
    return Py_BuildValue("i", size);
}

// Unpack payload from a string
PyObject *SpeadPktObj_unpack_payload(SpeadPktObj *self, PyObject *args) {
    char *data;
    int size;
    if (!PyArg_ParseTuple(args, "s#", &data, &size)) return NULL;
    if (size < self->pkt.payload_len) {
        PyErr_Format(PyExc_ValueError, "len(data) < %d", self->pkt.payload_len);
        return NULL;
    }
    size = spead_unpack_payload(&self->pkt, data);
    return Py_BuildValue("i", size);
}

// Unpack all from a string
PyObject *SpeadPktObj_unpack(SpeadPktObj *self, PyObject *args) {
    char *data;
    int size, off, ok=0;
    if (!PyArg_ParseTuple(args, "s#", &data, &size)) return NULL;
    if (size >= SPEAD_ITEM_BYTES) {
        off = spead_unpack_hdr(&self->pkt, data);
        if (size >= off + self->pkt.n_items * SPEAD_ITEM_BYTES) {
            off += spead_unpack_items(&self->pkt, data+off);
            if (size >= off + self->pkt.payload_len) {
                off += spead_unpack_payload(&self->pkt, data+off);
                ok = 1;
            }
        }
    }
    if (!ok) {
        PyErr_Format(PyExc_ValueError, "unpack failed");
        return NULL;
    }
    return Py_BuildValue("i", off);
}

// Get packet payload
PyObject *SpeadPktObj_get_payload(SpeadPktObj *self) {
    if (self->pkt.payload_len == 0) {
        return Py_BuildValue("s", "");
    } else {
        return Py_BuildValue("s#", self->pkt.payload, self->pkt.payload_len);
    }
}

// Get packet items
PyObject *SpeadPktObj_get_items(SpeadPktObj *self) {
    PyObject *tup=PyTuple_New(self->pkt.n_items);
    int i;
    for (i=0; i < self->pkt.n_items; i++) {
        //printf("get_items,item%d: is_ext=%d, id=%d, val=%d\n", i, self->pkt.items[i].is_ext,
        //    self->pkt.items[i].id, self->pkt.items[i].val);
        if (self->pkt.items[i].is_ext) {
            PyTuple_SET_ITEM(tup, i, 
                Py_BuildValue("(ii(ii))", self->pkt.items[i].is_ext, self->pkt.items[i].id,
                (self->pkt.items[i].val >> 24) & 0xFFFFFF, (self->pkt.items[i].val >> 0) & 0xFFFFFF));
        } else {
            PyTuple_SET_ITEM(tup, i, 
                Py_BuildValue("(iil)", self->pkt.items[i].is_ext, self->pkt.items[i].id,
                self->pkt.items[i].val));
        }
    }
    return tup;
}

// Bind methods to object
static PyMethodDef SpeadPktObj_methods[] = {
    {"get_items", (PyCFunction)SpeadPktObj_get_items, METH_NOARGS,
        "get_items()\nReturn a tuple of (is_ext,id,val) items in the header of this packet, where val is (off,len) for an extension item or a 48b unsigned integer value otherwise."},
    //{"set_items", (PyCFunction)SpeadPktObj_set_payload, METH_VARARGS,
    //    "set_items()\nSet the raw items in the header of this packet."},
    {"get_payload", (PyCFunction)SpeadPktObj_get_payload, METH_NOARGS,
        "get_payload()\nReturn the payload of this packet."},
    //{"set_payload", (PyCFunction)SpeadPktObj_set_payload, METH_VARARGS,
    //    "set_payload()\nSet the payload of this packet to a binary string."},
    {"unpack_hdr", (PyCFunction)SpeadPktObj_unpack_hdr, METH_VARARGS,
        "unpack_hdr(data)\nSet packet header from binary string. Raise ValueError if data doesn't match packet format.  Otherwise, return # bytes read."},
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
    {"frame_cnt", T_ULONG, offsetof(SpeadPktObj, pkt) +
        offsetof(SpeadPacket, frame_cnt), 0, "frame_cnt"},
    {"payload_cnt", T_UINT, offsetof(SpeadPktObj, pkt) +
        offsetof(SpeadPacket, payload_cnt), 0, "payload_cnt"},
    {"payload_len", T_UINT, offsetof(SpeadPktObj, pkt) +
        offsetof(SpeadPacket, payload_len), 0, "payload_len"},
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

/*___         __  __           ____             _        _   
| __ ) _   _ / _|/ _| ___ _ __/ ___|  ___   ___| | _____| |_ 
|  _ \| | | | |_| |_ / _ \ '__\___ \ / _ \ / __| |/ / _ \ __|
| |_) | |_| |  _|  _|  __/ |   ___) | (_) | (__|   <  __/ |_ 
|____/ \__,_|_| |_|  \___|_|  |____/ \___/ \___|_|\_\___|\__| */

// Deallocate memory when Python object is deleted
static void BsockObject_dealloc(BsockObject* self) {
    free_buffer_socket(&self->bs);
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
    init_buffer_socket(&self->bs, pkt_count);
    self->pycallback = NULL;
    return 0;
}

static PyObject * BsockObject_start(BsockObject *self, PyObject *args) {
    int port;
    if (!PyArg_ParseTuple(args, "i", &port)) return NULL;
    PyEval_InitThreads();
    start(&self->bs, port);
    Py_INCREF(Py_None);
    return Py_None;
}

static PyObject * BsockObject_stop(BsockObject *self) {
    //PyThreadState *_save;
    // Release Python Global Interpreter Lock so that a python callback end
    Py_BEGIN_ALLOW_THREADS
    stop(&(self->bs));
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
    pkto->pkt.payload_len = pkt->payload_len;
    pkto->pkt.payload_cnt = pkt->payload_cnt;
    // Deviously steal the references to items and payload from this pkt!
    pkto->pkt.items = pkt->items;
    pkto->pkt.payload = pkt->payload;
    spead_init_packet(pkt);  // Clears out the packet so that only we can free items and payload
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
    set_callback(&self->bs, &wrap_bs_pycallback);
    Py_INCREF(Py_None);
    return Py_None;
}

// Routine for removing a python callback for data output
static PyObject * BsockObject_unset_callback(BsockObject *self) {
    set_callback(&self->bs, &default_callback);
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
    if (PyType_Ready(&BsockType) < 0) return;
    m = Py_InitModule3("_spead", spead_methods,
    "A module for handling low-level (high performance) SPEAD packet manipulation.");
    Py_INCREF(&BsockType);
    PyModule_AddObject(m, "BufferSocket", (PyObject *)&BsockType);
    Py_INCREF(&SpeadPktType);
    PyModule_AddObject(m, "SpeadPacket", (PyObject *)&SpeadPktType);
}

