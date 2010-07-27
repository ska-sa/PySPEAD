#include "include/py_spead_module.h"

/*___                       _ ____            _        _   
/ ___| _ __   ___  __ _  __| |  _ \ __ _  ___| | _____| |_ 
\___ \| '_ \ / _ \/ _` |/ _` | |_) / _` |/ __| |/ / _ \ __|
 ___) | |_) |  __/ (_| | (_| |  __/ (_| | (__|   <  __/ |_ 
|____/| .__/ \___|\__,_|\__,_|_|   \__,_|\___|_|\_\___|\__|
      |_|                                                  */

// Deallocate memory when Python object is deleted
static void SpeadPktObj_dealloc(SpeadPktObj* self) {
    if (self->pkt != NULL) {
        free(self->pkt);
    }
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
    self->pkt = (SpeadPacket *) malloc(sizeof(SpeadPacket));
    if (self->pkt == NULL) {
        PyErr_Format(PyExc_MemoryError, "Could not allocate memory for SPEAD packet");
        return -1;
    }
    spead_packet_init(self->pkt);
    return 0;
}

// Unpack header from a string
PyObject *SpeadPktObj_unpack_header(SpeadPktObj *self, PyObject *args) {
    char *data;
    Py_ssize_t i, size;
    if (!PyArg_ParseTuple(args, "s#", &data, &size)) return NULL;
    if (size < SPEAD_ITEMLEN) {
        PyErr_Format(PyExc_ValueError, "len(data) = %d (needed at least %d)", size, SPEAD_ITEMLEN);
        return NULL;
    }
    for (i=0; i < SPEAD_HEADERLEN; i++) {
        self->pkt->data[i] = data[i];
    }
    size = (Py_ssize_t) spead_packet_unpack_header(self->pkt);
    if (size == SPEAD_ERR) {
        PyErr_Format(PyExc_ValueError, "data does not represent a SPEAD packet");
        return NULL;
    }
    return Py_BuildValue("n", size);
}

// Unpack items from a string
PyObject *SpeadPktObj_unpack_items(SpeadPktObj *self, PyObject *args) {
    char *data;
    Py_ssize_t i, size, item_bytes;
    if (!PyArg_ParseTuple(args, "s#", &data, &size)) return NULL;
    item_bytes = self->pkt->n_items * SPEAD_ITEMLEN;
    if (size < item_bytes) {
        PyErr_Format(PyExc_ValueError, "len(data) = %d (needed at least %d)", size, item_bytes);
        return NULL;
    }
    for (i=0; i < item_bytes; i++) {
        self->pkt->data[i + SPEAD_HEADERLEN] = data[i];
        //if (i % SPEAD_ITEMLEN == 0) printf("\n");
        //printf("%02x", data[i]);
    }
    //printf("\n");
    size = spead_packet_unpack_items(self->pkt);
    if (size == SPEAD_ERR) {
        PyErr_Format(PyExc_MemoryError, "in SpeadPacket.unpack_items()");
        return NULL;
    }
    return Py_BuildValue("n", size);
}

// Unpack all from a string
PyObject *SpeadPktObj_unpack(SpeadPktObj *self, PyObject *args) {
    char *data;
    Py_ssize_t i, size, item_bytes;
    if (!PyArg_ParseTuple(args, "s#", &data, &size)) return NULL;
    if (size < SPEAD_ITEMLEN) {
        PyErr_Format(PyExc_ValueError, "len(data) = %d (needed at least %d)", size, SPEAD_ITEMLEN);
        return NULL;
    }
    for (i=0; i < SPEAD_ITEMLEN; i++) {
        self->pkt->data[i] = data[i];
    }
    if (spead_packet_unpack_header(self->pkt) == SPEAD_ERR) {
        PyErr_Format(PyExc_ValueError, "data does not represent a SPEAD packet");
        return NULL;
    }
    item_bytes = self->pkt->n_items * SPEAD_ITEMLEN;
    if (size < item_bytes + SPEAD_ITEMLEN) {
        PyErr_Format(PyExc_ValueError, "len(data) = %d (needed at least %d)", size, item_bytes + SPEAD_ITEMLEN);
        return NULL;
    }
    for (i=0; i < item_bytes; i++) {
        self->pkt->data[i + SPEAD_ITEMLEN] = data[i + SPEAD_ITEMLEN];
    }
    spead_packet_unpack_items(self->pkt);
    if (SPEAD_ITEMLEN + item_bytes + self->pkt->payload_len > SPEAD_MAX_PACKET_LEN) {
        PyErr_Format(PyExc_ValueError, "packet size (%d) exceeds max of %d bytes", size, SPEAD_MAX_PACKET_LEN);
        return NULL;
    } else if (size < item_bytes + SPEAD_ITEMLEN + self->pkt->payload_len) {
        PyErr_Format(PyExc_ValueError, "len(data) = %d (needed at least %d)", size, item_bytes + SPEAD_ITEMLEN);
        return NULL;
    }
    for (i=0; i < self->pkt->payload_len; i++) {
        self->pkt->payload[i] = data[i + item_bytes + SPEAD_ITEMLEN];
    }
    return Py_BuildValue(BUILDLONG, SPEAD_ITEMLEN + item_bytes + self->pkt->payload_len);
}

// Pack all to a string
PyObject *SpeadPktObj_pack(SpeadPktObj *self) {
    Py_ssize_t size;
    size = SPEAD_ITEMLEN * (self->pkt->n_items + 1) + self->pkt->payload_len;
    if (size <= 0 || size > SPEAD_MAX_PACKET_LEN) {
        PyErr_Format(PyExc_ValueError, "This packet is uninitialized or malformed.  Cannot currently pack");
        return NULL;
    }
    return Py_BuildValue("s#", self->pkt->data, size);
}

PyObject *SpeadPktObj_get_heapcnt(SpeadPktObj *self, void *closure) {
    return Py_BuildValue(BUILDLONG, self->pkt->heap_cnt);
}

PyObject *SpeadPktObj_get_heaplen(SpeadPktObj *self, void *closure) {
    return Py_BuildValue(BUILDLONG, self->pkt->heap_len);
}

PyObject *SpeadPktObj_get_nitems(SpeadPktObj *self, void *closure) {
    return Py_BuildValue("i", self->pkt->n_items);
}
    
PyObject *SpeadPktObj_get_isstreamctrlterm(SpeadPktObj *self, void *closure) {
    if (self->pkt->is_stream_ctrl_term) Py_RETURN_TRUE;
    Py_RETURN_FALSE;
}

PyObject *SpeadPktObj_get_payloadlen(SpeadPktObj *self, void *closure) {
    return Py_BuildValue(BUILDLONG, self->pkt->payload_len);
}

PyObject *SpeadPktObj_get_payloadoff(SpeadPktObj *self, void *closure) {
    return Py_BuildValue(BUILDLONG, self->pkt->payload_off);
}

// Get packet payload
PyObject *SpeadPktObj_get_payload(SpeadPktObj *self, void *closure) {
    if (self->pkt->payload_len == 0 || self->pkt->payload == NULL) {
        return Py_BuildValue("s", "");
    } else {
        return Py_BuildValue("s#", self->pkt->payload, (Py_ssize_t) self->pkt->payload_len);
    }
}
int SpeadPktObj_set_payload(SpeadPktObj *self, PyObject *value, void *closure) {
    char *data;
    Py_ssize_t i, size;
    if (!PyString_Check(value)) { 
        PyErr_Format(PyExc_ValueError, "payload must be a string");
        return -1;
    }
    PyString_AsStringAndSize(value, &data, &size);
    if (self->pkt->payload == NULL) {
        PyErr_Format(PyExc_RuntimeError, "SpeadPacket header not initialized");
        return -1;
    } else if (size < self->pkt->payload_len) {
        PyErr_Format(PyExc_ValueError, "Expected payload of size %d (got %d)", self->pkt->payload_len, size);
        return -1;
    }
    for (i=0; i < size; i++) {
        self->pkt->payload[i] = data[i];
    }
    return 0;
}

// Get packet items
PyObject *SpeadPktObj_get_items(SpeadPktObj *self, void *closure) {
    int i;
    uint64_t item;
    PyObject *tup=PyTuple_New(self->pkt->n_items);
    if (tup == NULL) {
        PyErr_Format(PyExc_MemoryError, "Could not allocate tuple in SpeadPacket.get_items()");
        return NULL;
    }
    for (i=0; i < self->pkt->n_items; i++) {
        item = SPEAD_ITEM(self->pkt->data, i+1);
        if (sizeof(long) < 8) PyTuple_SET_ITEM(tup, i, Py_BuildValue("(iiL)", SPEAD_ITEM_MODE(item), SPEAD_ITEM_ID(item), SPEAD_ITEM_ADDR(item)));
        else PyTuple_SET_ITEM(tup, i, Py_BuildValue("(iil)", SPEAD_ITEM_MODE(item), SPEAD_ITEM_ID(item), SPEAD_ITEM_ADDR(item)));
    }
    return tup;
}
int SpeadPktObj_set_items(SpeadPktObj *self, PyObject *items, void *closure) {
    PyObject *iter1, *iter2, *item1, *item2;
    int n_items=0, i;
    int64_t data[3];
    iter1 = PyObject_GetIter(items);
    if (iter1 == NULL) return -1;
    while (item1 = PyIter_Next(iter1)) {
        iter2 = PyObject_GetIter(item1);
        if (iter2 == NULL) {
            PyErr_Format(PyExc_ValueError, "items must be a list of (mode, id, bin-val) triplets");
            Py_DECREF(item1);
            break;
        }
        for (i=0; i < 3; i++) {
            item2 = PyIter_Next(iter2);
            if (item2 == NULL) {
                PyErr_Format(PyExc_ValueError, "items must be a list of (mode, id, bin-val) triplets");
                break;
            }
            if (PyInt_Check(item2)) {
                if (sizeof(long) < 8) data[i] = PyInt_AsLong(item2);
                else data[i] = PyInt_AsLong(item2);
            } else if (PyLong_Check(item2)) {
                if (sizeof(long) < 8) data[i] = PyLong_AsLongLong(item2);
                else data[i] = PyLong_AsLong(item2);
            } else {
                PyErr_Format(PyExc_ValueError, "items must be a list of (mode, id, bin-val) triplets");
                Py_DECREF(item2);
                break;
            }
            Py_DECREF(item2);
        }
        Py_DECREF(iter2);
        Py_DECREF(item1);
        if (i != 3) break;
        n_items++;
        SPEAD_SET_ITEM(self->pkt->data,n_items,SPEAD_ITEM_BUILD(data[0],data[1],data[2]));
        data[0] = SPEAD_ITEM(self->pkt->data,n_items);
    }
    Py_DECREF(iter1);
    if (PyErr_Occurred()) return -1;
    SPEAD_SET_ITEM(self->pkt->data,0,SPEAD_HEADER_BUILD(n_items));
    if (spead_packet_unpack_header(self->pkt) == SPEAD_ERR || spead_packet_unpack_items(self->pkt) == SPEAD_ERR) {
        PyErr_Format(PyExc_ValueError, "malformed SPEAD packet");
        return -1;
    }
    return 0;
}

static PyMethodDef SpeadPktObj_methods[] = {
    {"unpack_header", (PyCFunction)SpeadPktObj_unpack_header, METH_VARARGS,
        "unpack_header(data)\nSet packet header from binary string. Raise ValueError if data doesn't match packet format.  Otherwise, return # bytes read."},
    {"unpack_items", (PyCFunction)SpeadPktObj_unpack_items, METH_VARARGS,
        "unpack_items(data)\nSet packet items from binary string. Raise ValueError if insufficient data.  Otherwise, return # bytes read."},
    {"unpack", (PyCFunction)SpeadPktObj_unpack, METH_VARARGS,
        "unpack(data)\nRead entire packet from binary string. Raise ValueError if failure.  Otherwise, return # bytes read."},
    {"pack", (PyCFunction)SpeadPktObj_pack, METH_NOARGS,
        "pack()\nReturn packet as a binary string."},
    {NULL}  // Sentinel
};

static PyGetSetDef SpeadPktObj_getseters[] = {
    {"heap_cnt", (getter)SpeadPktObj_get_heapcnt, NULL, "heap_cnt", NULL},
    {"heap_len", (getter)SpeadPktObj_get_heaplen, NULL, "heap_len", NULL},
    {"n_items", (getter)SpeadPktObj_get_nitems, NULL, "n_items", NULL},
    {"is_stream_ctrl_term", (getter)SpeadPktObj_get_isstreamctrlterm, NULL, "is_stream_ctrl_term", NULL},
    {"payload_len", (getter)SpeadPktObj_get_payloadlen, NULL, "payload_len", NULL},
    {"payload_off", (getter)SpeadPktObj_get_payloadoff, NULL, "payload_off", NULL},
    {"payload", (getter)SpeadPktObj_get_payload, (setter)SpeadPktObj_set_payload, "payload", NULL},
    {"items", (getter)SpeadPktObj_get_items, (setter)SpeadPktObj_set_items, "items", NULL},
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
    NULL,                    /* tp_members */
    SpeadPktObj_getseters,     /* tp_getset */
    0,                         /* tp_base */
    0,                         /* tp_dict */
    0,                         /* tp_descr_get */
    0,                         /* tp_descr_set */
    0,                         /* tp_dictoffset */
    (initproc)SpeadPktObj_init,      /* tp_init */
    0,                         /* tp_alloc */
    SpeadPktObj_new,       /* tp_new */
};

/*___                       _ _   _                  
/ ___| _ __   ___  __ _  __| | | | | ___  __ _ _ __  
\___ \| '_ \ / _ \/ _` |/ _` | |_| |/ _ \/ _` | '_ \ 
 ___) | |_) |  __/ (_| | (_| |  _  |  __/ (_| | |_) |
|____/| .__/ \___|\__,_|\__,_|_| |_|\___|\__,_| .__/ 
      |_|                                     |_|    */

// Deallocate memory when Python object is deleted
static void SpeadHeapObj_dealloc(SpeadHeapObj* self) {
    // self->heap is sharing references to pkts with pypkts in self->list_of_pypkts
    // we have to first unlink the packets so only Python deallocates packets
    self->heap.head_pkt = NULL;  
    Py_DECREF(self->list_of_pypkts);
    spead_heap_wipe(&self->heap);
    self->ob_type->tp_free((PyObject*)self);
}

// Allocate memory for Python object 
static PyObject *SpeadHeapObj_new(PyTypeObject *type,
        PyObject *args, PyObject *kwds) {
    SpeadHeapObj *self;
    self = (SpeadHeapObj *) type->tp_alloc(type, 0);
    return (PyObject *) self;
}

// Initialize object (__init__)
static int SpeadHeapObj_init(SpeadHeapObj *self) {
    spead_heap_init(&self->heap);
    // This holds pypkts in spead_heap to prevent them from being GC'd
    self->list_of_pypkts = PyList_New(0);
    return 0;
}

// Add a packet to the heap
PyObject *SpeadHeapObj_add_packet(SpeadHeapObj *self, PyObject *args) {
    SpeadPktObj *pkto;
    int rv;
    if (!PyArg_ParseTuple(args, "O!", &SpeadPktType, &pkto)) return NULL;
    rv = spead_heap_add_packet(&self->heap, pkto->pkt);
    if (rv == SPEAD_ERR) {
        PyErr_Format(PyExc_ValueError, "SpeadPacket not part of heap, or it is incorrectly initialized");
        return NULL;
    }
    // Hold pkto in list of safekeeping (keep it from being GC'd)
    PyList_Append(self->list_of_pypkts, (PyObject *) pkto);
    return Py_BuildValue("i", rv);
}

// Add a packet to the heap
PyObject *SpeadHeapObj_finalize(SpeadHeapObj *self) {
    if (spead_heap_finalize(&self->heap) == SPEAD_ERR) {
        PyErr_Format(PyExc_MemoryError, "Memory allocation failed in SpeadHeap.finalize()");
        return NULL;
    }
    Py_INCREF(Py_None);
    return Py_None;
}

// Get the final items from a heap
PyObject *SpeadHeapObj_get_items(SpeadHeapObj *self) {
    int result;
    SpeadItem *item;
    PyObject *rv, *key, *value;
    if (self->heap.head_item == NULL) {
        PyErr_Format(PyExc_RuntimeError, "SpeadHeap was not finalized before SpeadHeap.get_items() was called");
        return NULL;
    }
    rv = PyDict_New();
    if (rv == NULL) {
        PyErr_Format(PyExc_MemoryError, "Memory allocation failed in SpeadHeap.finalize()");
        return NULL;
    }
    // Every heap should have a list of descriptors to process
    key = PyInt_FromLong(SPEAD_DESCRIPTOR_ID);
    value = PyList_New(0);
    PyDict_SetItem(rv, key, value);
    Py_DECREF(key);
    Py_DECREF(value);
    item = self->heap.head_item;
    while (item != NULL) {
        if (item->is_valid) {
            // Build key:value pair
            key = PyInt_FromLong(item->id);
            if (item->len == 0) {
                value = PyString_FromString("");
            } else {
                value = PyString_FromStringAndSize(item->val,item->len);
            }
            // For DESCRIPTORs only, repeat item entries appear in a list
            if (item->id == SPEAD_DESCRIPTOR_ID) {
                // We know PyDict_GetItem can't fail b/c we set this key above
                result = PyList_Append(PyDict_GetItem(rv, key), value);
            // Otherwise, overwrite previous value
            } else {
                result = PyDict_SetItem(rv, key, value);
            }
            if (result == -1) {
                PyErr_Format(PyExc_MemoryError, "Memory allocation failed in SpeadHeap.get_items()");
                return NULL;
            } 
            // Release ownership of key and value (they live in the dict now)
            Py_DECREF(key);
            Py_DECREF(value);
        }
        item = item->next;
    }
    return rv;
}

// Bind methods to object
static PyMethodDef SpeadHeapObj_methods[] = {
    {"add_packet", (PyCFunction)SpeadHeapObj_add_packet, METH_VARARGS,
        "add_packet(SpeadPacket)\nAdd SpeadPacket to this heap.  A fresh SpeadHeap will accept packets with any HEAP_CNT, but thereafter will only accept ones with the same HEAP_CNT.  Raise ValueError on failure.  Returns 1 if heap is known to be complete."},
    {"finalize", (PyCFunction)SpeadHeapObj_finalize, METH_NOARGS,
        "finalize()\nTry to finalize the values of all items in this heap.  Check SpeadHeap.is_valid to see if all values were able to be finalized."},
    {"get_items", (PyCFunction)SpeadHeapObj_get_items, METH_NOARGS,
        "get_items()\nReturn a dictionary of id:value pairs for all valid items in a finalized heap."},
    {NULL}  // Sentinel
};

static PyMemberDef SpeadHeapObj_members[] = {
    {"heap_cnt", T_INT64, offsetof(SpeadHeapObj, heap) +
        offsetof(SpeadHeap, heap_cnt), 0, "heap_cnt"},
    {"heap_len", T_INT64, offsetof(SpeadHeapObj, heap) +
        offsetof(SpeadHeap, heap_len), 0, "heap_len"},
    {"is_valid", T_INT, offsetof(SpeadHeapObj, heap) +
        offsetof(SpeadHeap, is_valid), 0, "is_valid"},
    {"has_all_packets", T_INT, offsetof(SpeadHeapObj, heap) +
        offsetof(SpeadHeap, has_all_packets), 0, "has_all_packets"},
    {NULL}  /* Sentinel */
};

PyTypeObject SpeadHeapType = {
    PyObject_HEAD_INIT(NULL)
    0,                         /*ob_size*/
    "SpeadHeap", /*tp_name*/
    sizeof(SpeadHeapObj), /*tp_basicsize*/
    0,                         /*tp_itemsize*/
    (destructor)SpeadHeapObj_dealloc, /*tp_dealloc*/
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
    "This class provides a basic interface for examining Spead heaps.  SpeadHeap()",       /* tp_doc */
    0,                     /* tp_traverse */
    0,                     /* tp_clear */
    0,                     /* tp_richcompare */
    0,                     /* tp_weaklistoffset */
    0,                     /* tp_iter */
    0,                     /* tp_iternext */
    SpeadHeapObj_methods,     /* tp_methods */
    SpeadHeapObj_members,     /* tp_members */
    0,                         /* tp_getset */
    0,                         /* tp_base */
    0,                         /* tp_dict */
    0,                         /* tp_descr_get */
    0,                         /* tp_descr_set */
    0,                         /* tp_dictoffset */
    (initproc)SpeadHeapObj_init,      /* tp_init */
    0,                         /* tp_alloc */
    SpeadHeapObj_new,       /* tp_new */
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
    int port, buffer_size;
    if (!PyArg_ParseTuple(args, "ii", &port,&buffer_size)) return NULL;
    PyEval_InitThreads();
    buffer_socket_start(&self->bs, port, buffer_size);
    Py_INCREF(Py_None);
    return Py_None;
}

static PyObject * BsockObject_stop(BsockObject *self) {
    //PyThreadState *_save;
    // Release Python Global Interpreter Lock so that python callback can end
    Py_BEGIN_ALLOW_THREADS
    buffer_socket_stop(&self->bs);
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
    //printf("wrap_bs_pycallback: acquiring GIL\n");
    gstate = PyGILState_Ensure();
    //printf("wrap_bs_pycallback: got GIL\n");
    bso = (BsockObject *) userdata;  // Recast userdata as reference to a bs
    // Wrap pkt into a SpeadPacket python object
    pkto = PyObject_NEW(SpeadPktObj, &SpeadPktType); // This does not call SpeadPktObj_init!
    // Deviously swap in reference to this pkt instead of initializing
    // Python will take care of freeing pkt when pkto dies.
    pkto->pkt = pkt;
    arglist = Py_BuildValue("(O)", (PyObject *)pkto);
    // Call the python callback with the wrapped-up SpeadPacket
    rv = PyEval_CallObject(bso->pycallback, arglist);
    Py_DECREF(arglist);
    Py_DECREF(pkto);
    //printf("wrap_bs_pycallback: releasing GIL\n");
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


int _spead_unpack_fmt(char *fmt, Py_ssize_t fmt_len, char *fmt_types, int *fmt_bits) {
    int n_fmts, i,  flag=0, tot_fmt_bits=0;
    uint32_t fmt_item;
    if (fmt_len <= 0 || fmt_len % SPEAD_FMT_LEN != 0 || fmt_len / SPEAD_FMT_LEN > SPEAD_MAX_FMT_LEN)
        return -1;
    // Validate fmt
    n_fmts = fmt_len / SPEAD_FMT_LEN;
    for (i=0; i < n_fmts; i++) {
        fmt_item = SPEAD_FMT(fmt,i);
        fmt_types[i] = SPEAD_FMT_GET_TYPE(fmt_item);
        fmt_bits[i] = SPEAD_FMT_GET_NBITS(fmt_item);
        tot_fmt_bits += fmt_bits[i];
        switch (fmt_types[i]) {
            case 'i': case 'u': break;
            case 'f':
                switch (fmt_bits[i]) {
                    case 32: case 64: break;
                    default: flag = 1; break;
                }
                break;
            case 'c': if (fmt_bits[i] != 8) flag = 1; break;
            case '0': // This isn't supported at this level--it must be accounted for at a higher level
            default: flag = 1; break;
        }
        if (flag) break;
    }
    if (flag) return -1;
    return tot_fmt_bits;
}
        
PyObject *spead_unpack(PyObject *self, PyObject *args, PyObject *kwds) {
    PyObject *rv, *tup;
    char *fmt, *data, fmt_types[SPEAD_MAX_FMT_LEN];
    Py_ssize_t fmt_len, data_len;
    uint64_t u64;
    int64_t i64;
    uint32_t u32;
    uint8_t u8;
    int n_fmts, i, fmt_bits[SPEAD_MAX_FMT_LEN], tot_fmt_bits=0, offset=0;
    long cnt=1, j;
    static char *kwlist[] = {"fmt", "data", "cnt", "offset", NULL};
    if (!PyArg_ParseTupleAndKeywords(args, kwds,"s#s#|li", kwlist, &fmt, &fmt_len, &data, &data_len, &cnt, &offset))
        return NULL;
    if (offset > 8) {
        PyErr_Format(PyExc_ValueError, "offset must be <= 8 (got %d)", offset);
        return NULL;
    }
    tot_fmt_bits = _spead_unpack_fmt(fmt, fmt_len, fmt_types, fmt_bits);
    if (tot_fmt_bits == -1) {
        PyErr_Format(PyExc_ValueError, "Invalid fmt string");
        return NULL;
    }
    n_fmts = fmt_len / SPEAD_FMT_LEN;
    // Check if this is  dynamically sized variable
    if (cnt < 0) cnt = data_len * 8 / tot_fmt_bits; // 8 bits per byte
    // Make sure we have enough data
    if (cnt * tot_fmt_bits + offset > data_len * 8) {
        PyErr_Format(PyExc_ValueError, "Not enough data to unpack fmt");
        return NULL;
    }

    // Create our return tuple
    rv = PyTuple_New(cnt);
    if (rv == NULL) return NULL;
    for (j=0; j < cnt; j++) {
        tup = PyTuple_New(n_fmts);
        if (tup == NULL) return NULL;
        for (i=0; i < n_fmts; i++) {
            switch(fmt_types[i]) {
                case 'u':
                    u64 = spead_u64_align(data + sizeof(char)*(offset/8), offset % 8, fmt_bits[i]);
                    if (fmt_bits[i] < 8*sizeof(long)) {
                        PyTuple_SET_ITEM(tup, i, PyInt_FromLong((long) u64)); break;
                    } else if (fmt_bits[i] == 8*sizeof(long)) {
                        PyTuple_SET_ITEM(tup, i, PyLong_FromUnsignedLong((unsigned long) u64)); break;
                    } else if (fmt_bits[i] < 8*sizeof(long long)) {
                        PyTuple_SET_ITEM(tup, i, PyLong_FromLongLong((long long) u64)); break;
                    } else {
                        PyTuple_SET_ITEM(tup, i, PyLong_FromUnsignedLongLong((unsigned long long) u64)); break;
                    }
                case 'i':
                    i64 = spead_i64_align(data + sizeof(char)*(offset/8), offset % 8, fmt_bits[i]);
                    if (fmt_bits[i] <= 8*sizeof(long)) {
                        PyTuple_SET_ITEM(tup, i, PyInt_FromLong((long) i64)); break;
                    } else {
                        PyTuple_SET_ITEM(tup, i, PyLong_FromLongLong((long long) i64)); break;
                    }
                    break;
                case 'f':
                    if (fmt_bits[i] == 32) {
                        u32 = spead_u32_align(data + sizeof(char)*(offset/8), offset % 8, fmt_bits[i]);
                        PyTuple_SET_ITEM(tup, i, PyFloat_FromDouble((double) ((float *)&u32)[0])); break;
                    } else {
                        u64 = spead_u64_align(data + sizeof(char)*(offset/8), offset % 8, fmt_bits[i]);
                        PyTuple_SET_ITEM(tup, i, PyFloat_FromDouble(((double *)&u64)[0])); break;
                    }
                    break;
                case 'c':
                    u8 = SPEAD_U8_ALIGN(data + sizeof(char)*(offset/8), offset % 8);
                    PyTuple_SET_ITEM(tup, i, PyString_FromStringAndSize(((char *)&u8), 1)); break;
            }
            offset += fmt_bits[i];
        }
        PyTuple_SET_ITEM(rv, j, tup);
    }
    return rv;        
}

PyObject *spead_pack(PyObject *self, PyObject *args, PyObject *kwds) {
    PyObject *rv, *tup, *iter1, *iter2, *item1, *item2;
    char *fmt, *data, fmt_types[SPEAD_MAX_FMT_LEN], *sval;
    Py_ssize_t fmt_len, val_len;
    float fval;
    double dval;
    uint64_t u64val;
    uint32_t u32val;
    int64_t i64val;
    int n_fmts, i, fmt_bits[SPEAD_MAX_FMT_LEN], tot_fmt_bits, flag=0, offset=0;
    long cnt, j, tot_bytes;
    static char *kwlist[] = {"fmt", "data", "offset", NULL};
    if (!PyArg_ParseTupleAndKeywords(args, kwds,"s#O|i", kwlist, &fmt, &fmt_len, &tup, &offset))
        return NULL;
    if (offset > 8) {
        PyErr_Format(PyExc_ValueError, "offset must be <= 8 (got %d)", offset);
        return NULL;
    }
    tot_fmt_bits = _spead_unpack_fmt(fmt, fmt_len, fmt_types, fmt_bits);
    if (tot_fmt_bits == -1) {
        PyErr_Format(PyExc_ValueError, "Invalid fmt string");
        return NULL;
    }
    n_fmts = fmt_len / SPEAD_FMT_LEN;
    //printf("Format has length %d\n", n_fmts);
    //printf("Format has %d bits\n", tot_fmt_bits);
    cnt = PyObject_Length(tup);
    if (cnt == -1) {
        PyErr_Format(PyExc_ValueError, "data does not match format");
        return NULL;
    }
    tot_bytes = cnt * tot_fmt_bits / 8;  // 8 bits per byte
    if (offset != 0) tot_bytes += 1;
    //printf("Data has length %d\n", cnt);
    //printf("Allocating %d bytes\n", tot_bytes);
    rv = PyString_FromStringAndSize(NULL, tot_bytes);
    if (rv == NULL) {
        PyErr_Format(PyExc_MemoryError, "Could not allocate output data in spead_pack()");
        return NULL;
    }
    data = PyString_AS_STRING(rv);
    iter1 = PyObject_GetIter(tup);
    if (iter1 == NULL) return NULL;
    // Loop over dimension of array
    for (j=0; j < cnt; j++) {
        item1 = PyIter_Next(iter1); // item1 has to be valid b/c cnt was derived from len(tup)
        iter2 = PyObject_GetIter(item1);
        if (iter2 == NULL) {
            flag = 1;
            Py_DECREF(item1);
            break;
        }
        // Loop over each format entry
        for (i=0; i < n_fmts; i++) {
            //printf("Entry %d, Format %d\n", j, i);
            item2 = PyIter_Next(iter2);
            if (item2 == NULL) {
                flag = 1;
                break;
            }
            // actually handle the data
            //printf("   Fmt: (%c,%d) applied to ", fmt_types[i], fmt_bits[i]);
            //PyObject_Print(item2, stdout, 0);
            //printf("\n");
            switch(fmt_types[i]) {
                case 'u':
                    //printf("   Uint copy at byte=%d offset=%d, bits=%d\n", offset/8, offset%8, fmt_bits[i]);
                    u64val = (uint64_t) PyInt_AsUnsignedLongLongMask(item2);
                    //printf("   got %ld\n", u64val);
                    if (PyErr_Occurred()) {
                        flag = 1;
                        break;
                    }
                    u64val = htonll(u64val);
                    //printf("   sending %02x%02x%02x%02x%02x%02x%02x%02x\n", ((char *)&u64val)[0], ((char *)&u64val)[1], ((char *)&u64val)[2], ((char *)&u64val)[3], ((char *)&u64val)[4], ((char *)&u64val)[5], ((char *)&u64val)[6], ((char *)&u64val)[7]);
                    spead_copy_bits(data+offset/8, (char *)&u64val + (8*sizeof(uint64_t)-fmt_bits[i])/8, offset%8, fmt_bits[i]);
                    break;
                case 'i':
                    //printf("   Int copy at byte=%d offset=%d, bits=%d\n", offset/8, offset%8, fmt_bits[i]);
                    i64val = (int64_t) PyInt_AsLong(item2);
                    if (PyErr_Occurred()) {
                        flag = 1;
                        break;
                    }
                    u64val = htonll(((uint64_t *)&i64val)[0]);
                    spead_copy_bits(data+offset/8, (char *)&u64val + (8*sizeof(uint64_t)-fmt_bits[i])/8, offset%8, fmt_bits[i]);
                    break;
                case 'f':
                    dval = PyFloat_AsDouble(item2);
                    if (PyErr_Occurred()) {
                        flag = 1;
                        break;
                    }
                    if (fmt_bits[i] == 32) {
                        //printf("   Float32 copy at byte=%d offset=%d, bits=%d\n", offset/8, offset%8, fmt_bits[i]);
                        fval = (float) dval;
                        u32val = htonl(((uint32_t *)&fval)[0]);
                        spead_copy_bits(data+offset/8, (char *)&u32val, offset%8, 32);
                    } else {
                        //printf("   Float64 copy at byte=%d offset=%d, bits=%d\n", offset/8, offset%8, fmt_bits[i]);
                        u64val = htonll(((uint64_t *)&dval)[0]);
                        spead_copy_bits(data+offset/8, (char *)&u64val, offset%8, 64);
                    }
                    break;
                case 'c':
                    if (PyString_AsStringAndSize(item2, &sval, &val_len) == -1 || sval == NULL || val_len == 0) {
                        flag = 1;
                        break;
                    }
                    //printf("   Copy at byte=%d offset=%d, bits=%d\n", offset/8, offset%8, fmt_bits[i]);
                    spead_copy_bits(data+offset/8, sval, offset%8, fmt_bits[i]);
                    break;
            }
            offset += fmt_bits[i];
            Py_DECREF(item2);
        }
        Py_DECREF(iter2);
        Py_DECREF(item1);
        if (flag) break;
    }
    Py_DECREF(iter1);
    if (flag) {
        PyErr_Format(PyExc_ValueError, "data does not match format");
        Py_DECREF(rv);
        return NULL;
    }
    return rv;
}

// Module methods
static PyMethodDef spead_methods[] = {
    {"unpack", (PyCFunction)spead_unpack, METH_VARARGS | METH_KEYWORDS,
        "unpack(fmt, data, cnt=1, offset=0)\nReturn tuple using fmt to read from binary string 'data'"},
    {"pack", (PyCFunction)spead_pack, METH_VARARGS | METH_KEYWORDS,
        "pack(fmt, data, offset=0)\nReturn binary string packed from 'data' using fmt"},
    {NULL, NULL}  /* Sentinel */
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
    if (PyType_Ready(&SpeadHeapType) < 0) return;
    if (PyType_Ready(&BsockType) < 0) return;
    m = Py_InitModule3("_spead", spead_methods,
    "A module for handling low-level (high performance) SPEAD packet manipulation.");
    Py_INCREF(&BsockType);
    PyModule_AddObject(m, "BufferSocket", (PyObject *)&BsockType);
    Py_INCREF(&SpeadHeapType);
    PyModule_AddObject(m, "SpeadHeap", (PyObject *)&SpeadHeapType);
    Py_INCREF(&SpeadPktType);
    PyModule_AddObject(m, "SpeadPacket", (PyObject *)&SpeadPktType);
    PyModule_AddIntConstant(m, "MAGIC", SPEAD_MAGIC);
    PyModule_AddIntConstant(m, "VERSION", SPEAD_VERSION);
    PyModule_AddIntConstant(m, "MAX_PACKET_LEN", SPEAD_MAX_PACKET_LEN);
    PyModule_AddIntConstant(m, "MAX_FMT_LEN", SPEAD_MAX_FMT_LEN);
    PyModule_AddIntConstant(m, "HEAP_CNT_ID", SPEAD_HEAP_CNT_ID);
    PyModule_AddIntConstant(m, "HEAP_LEN_ID", SPEAD_HEAP_LEN_ID);
    PyModule_AddIntConstant(m, "PAYLOAD_OFF_ID", SPEAD_PAYLOAD_OFF_ID);
    PyModule_AddIntConstant(m, "PAYLOAD_LEN_ID", SPEAD_PAYLOAD_LEN_ID);
    PyModule_AddIntConstant(m, "DESCRIPTOR_ID", SPEAD_DESCRIPTOR_ID);
    PyModule_AddIntConstant(m, "STREAM_CTRL_ID", SPEAD_STREAM_CTRL_ID);
    PyModule_AddIntConstant(m, "STREAM_CTRL_TERM_VAL", SPEAD_STREAM_CTRL_TERM_VAL);
    PyModule_AddIntConstant(m, "DIRECTADDR", SPEAD_DIRECTADDR);
    PyModule_AddIntConstant(m, "IMMEDIATEADDR", SPEAD_IMMEDIATEADDR);
    PyModule_AddIntConstant(m, "ERR", SPEAD_ERR);
    PyModule_AddIntConstant(m, "ITEMLEN", SPEAD_ITEMLEN);
    PyModule_AddIntConstant(m, "ITEMSIZE", SPEAD_ITEMSIZE);
    PyModule_AddIntConstant(m, "ADDRLEN", SPEAD_ADDRLEN);
    PyModule_AddIntConstant(m, "ADDRSIZE", SPEAD_ADDRSIZE);
    PyModule_AddIntConstant(m, "FMT_LEN", SPEAD_FMT_LEN);
}

