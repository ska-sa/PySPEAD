'''
Data packet:
[ SPEAD #    (8b) | Ver  (8b) | ItemSize (8b) | AddrSize (8b) | Reserved (16b) | # Items (16b) ]
[ MODE (1b) |         ID1 (23b)               |              Offset(40b)                       ]
[ MODE (1b) |         ID1 (23b)               |              Value (40b)                       ]
...
[ Packet Payload .............................................
.............................................................]
'''
import socket, math, numpy, logging, sys, time, struct
from numpy.lib.utils import safe_eval
from _spead import *

logger = logging.getLogger('spead')

#   ____                _              _       
#  / ___|___  _ __  ___| |_ __ _ _ __ | |_ ___ 
# | |   / _ \| '_ \/ __| __/ _` | '_ \| __/ __|
# | |__| (_) | | | \__ \ || (_| | | | | |_\__ \
#  \____\___/|_| |_|___/\__\__,_|_| |_|\__|___/

MAX_CONCURRENT_HEAPS = 16
UNRESERVED_OPTION = 2**12
NAME_ID = 0x10
DESCRIPTION_ID = 0x11
SHAPE_ID = 0x12
FORMAT_ID = 0x13
ID_ID = 0x14
DTYPE_ID = 0x15
ADDRNULL = '\x00'*ADDRLEN
DEBUG = False

#def pack(fmt, *args): return _spead.pack(fmt, args)

FORMAT_FMT = 'c\x00\x00\x08u\x00\x00\x18'  # This must be explicit to bootstrap packing formats
def mkfmt(*args): return pack(FORMAT_FMT, args)
def parsefmt(fmt): return unpack(FORMAT_FMT, fmt, cnt=-1)
DEFAULT_FMT = mkfmt(('u',ADDRSIZE))
HDR_FMT = mkfmt(('u',8),('u',8),('u',8),('u',8),('u',16),('u',16))
RAW_ITEM_FMT = mkfmt(('u',1),('u',ITEMSIZE-ADDRSIZE-1),('c',8),('c',8),('c',8),('c',8),('c',8))
ITEM_FMT = mkfmt(('u',1),('u',ITEMSIZE-ADDRSIZE-1),('u',ADDRSIZE))
ID_FMT = mkfmt(('u',ADDRSIZE-(ITEMSIZE-ADDRSIZE)),('u',ITEMSIZE-ADDRSIZE))
SHAPE_FMT = mkfmt(('u',8),('u',56))
STR_FMT = mkfmt(('c',8))

ITEM = {
    'HEAP_CNT':      {'ID':HEAP_CNT_ID,      'FMT':DEFAULT_FMT,        'CNT':1},
    'HEAP_LEN':      {'ID':HEAP_LEN_ID,      'FMT':DEFAULT_FMT,        'CNT':1},
    'PAYLOAD_LEN':    {'ID':PAYLOAD_LEN_ID, 'FMT':DEFAULT_FMT,        'CNT':1},
    'PAYLOAD_OFF':    {'ID':PAYLOAD_OFF_ID, 'FMT':DEFAULT_FMT,        'CNT':1},
    'DESCRIPTOR':     {'ID':DESCRIPTOR_ID,     'FMT':DEFAULT_FMT,        'CNT':1},
    'STREAM_CTRL':    {'ID':STREAM_CTRL_ID,    'FMT':DEFAULT_FMT,        'CNT':1},
    'NAME':           {'ID':NAME_ID,           'FMT':STR_FMT,            'CNT':-1},
    'DESCRIPTION':    {'ID':DESCRIPTION_ID,    'FMT':STR_FMT,            'CNT':-1},
    'DTYPE':          {'ID':DTYPE_ID,          'FMT':STR_FMT,            'CNT':-1},
    'SHAPE':          {'ID':SHAPE_ID,          'FMT':SHAPE_FMT,          'CNT':-1},
    'FORMAT':         {'ID':FORMAT_ID,         'FMT':FORMAT_FMT,         'CNT':-1},
    'ID':             {'ID':ID_ID,             'FMT':ID_FMT,             'CNT':1},
}

NAME = {}
for name, d in ITEM.iteritems(): NAME[d['ID']] = name

#  _   _ _   _ _ _ _         
# | | | | |_(_) (_) |_ _   _ 
# | | | | __| | | | __| | | |
# | |_| | |_| | | | |_| |_| |
#  \___/ \__|_|_|_|\__|\__, |
#                      |___/ 

def hexify(s):
    return ''.join(map(lambda x: ('0'+hex(ord(x))[2:])[-2:], s))

def calcsize(fmt):
    return sum([f[1] for f in unpack(FORMAT_FMT, fmt, cnt=-1)])

def calcdim(fmt):
    return len(fmt)/3

#def unpack(fmt, data, cnt=1, offset=0): return _spead.unpack(fmt, data, cnt=cnt, offset=offset)

def readable_payload(payload, prepend=''):
    return prepend + hexify(payload)

def readable_header(h, prepend=''):
    rv = unpack(RAW_ITEM_FMT, h)[0]
    mode, id = rv[:2]
    raw_val = ''.join(rv[2:])
    if mode == DIRECTADDR: val = 'OFF=%s' % (hexify(raw_val))
    else: val = 'VAL=%s' % (hexify(raw_val))
    try: return prepend+'[ MODE=%d | NAME=%16s | %s ]' % (mode, NAME[id], val)
    except(KeyError): return prepend+'[ MODE=%d |   ID=%16x | %s ]' % (mode, id, val)

def readable_binpacket(pkt, prepend='', show_payload=False):
    o, rv = 0, ['', 'vvv PACKET ' + 'v'*(50-len(prepend))]
    magic, version, itemsize, addrsize, junk, n_options = unpack(HDR_FMT, pkt[o:o+ITEMLEN])[0] ; o += ITEMLEN
    rv.append(' HEADER:[ SPEAD-CODE=%06x | VERSION=%d | N_OPTIONS=%d ]' % (magic, version, n_options))
    for cnt in range(n_options):
        rv.append(readable_header(pkt[o:o+ITEMLEN], prepend='ITEM%02d:' % (cnt)))
        o += ITEMLEN
    rv.append('PAYLOAD: BYTES=%d' % (len(pkt[o:])))
    if show_payload: rv.append('PAYLOAD: ' + readable_payload(pkt[o:]))
    rv.append('^'*(60-len(prepend)))
    return '\n'.join([prepend+r for r in rv])

def readable_speadpacket(pkt, prepend='', show_payload=False):
    o, rv = 0, ['', 'vvv PACKET ' + 'v'*(50-len(prepend))]
    rv.append('HEAP_CNT=%d' % (pkt.heap_cnt))
    for cnt,(mode,id,val) in enumerate(pkt.items):
        if mode == DIRECTADDR: val = 'OFF=%s' % (hex(val)[2:])
        else: val = 'VAL=%s' % (hex(val)[2:])
        try: rv.append('ITEM%02d: [ MODE=%d | NAME=%16s | %s ]' % (cnt, mode, NAME[id], val))
        except(KeyError): rv.append('ITEM%02d: [ MODE=%d |   ID=%16d | %s ]' % (cnt, mode, id, val))
    if show_payload: rv.append('PAYLOAD: ' + readable_payload(pkt.get_payload()))
    rv.append('^'*(60-len(prepend)))
    return '\n'.join([prepend+r for r in rv])

def readable_heap(heap, prepend=''):
    rv = ['', 'vvv HEAP ' + 'v'*(50-len(prepend))]
    for id in heap:
        try:
            name = NAME[id]
            if name == 'DESCRIPTOR':
                for cnt, d in enumerate(heap[id]):
                    rv += readable_binpacket(d, prepend='DESCRIPTOR%d:' % (cnt)).split('\n')
            else:
                fmt, cnt = ITEM[name]['FMT'], ITEM[name]['CNT']
                val = unpack(fmt, heap[id][1], cnt=cnt)
                try:
                    while type(val) != str and len(val) == 1: val = val[0]
                except(TypeError): pass
                s = '%16s: %s' % (name, val)
                if len(s) > (70 - len(prepend)): s = s[:(70-len(prepend)-3)]+'...'
                rv.append(s)
        except(KeyError):
            s = '%16d: %s' % (id, '0x'+hexify(heap[id][1]))
            if len(s) > (70 - len(prepend)): s = s[:(70-len(prepend)-3)]+'...'
            rv.append(s)
    rv.append('^'*(60-len(prepend)))
    return '\n'.join([prepend+r for r in rv])
        
#  ____                      _       _             
# |  _ \  ___  ___  ___ _ __(_)_ __ | |_ ___  _ __ 
# | | | |/ _ \/ __|/ __| '__| | '_ \| __/ _ \| '__|
# | |_| |  __/\__ \ (__| |  | | |_) | || (_) | |   
# |____/ \___||___/\___|_|  |_| .__/ \__\___/|_|   
#                             |_|                  

class Descriptor:
    '''A Descriptor is meta-information associated with an Item, including its id, name, description, 
    vector shape, and format for representation as a binary strings.  A shape of [] indicates an Item 
    with a singular value, while a shape of [1] indicates a value that is a 1D array with one entry.  
    A shape of -1 creates a dynamically-sized 1D array.

    A Numpy compatible descriptor can also be created. This utilises numpy style packing and unpacking in the data
    transport and is significantly faster. The ndarray parameter takes either an existing numpy array or a two element
    tuple containing a numpy compatible dtype and a shape tuple. e.g. ndarray=(np.float32,(512,24))
    '''
    def __init__(self, from_string=None, id=None, name='', description='', shape=[], fmt=DEFAULT_FMT, ndarray=None):
        if from_string: self.from_descriptor_string(from_string)
        else:
            self.id = id
            self.name = name
            self.description = description
            self.shape = shape
            self.format = fmt
            self.dtype_str = None
            self.dtype = None
            self.fortran_order = False
            if ndarray is not None:
                if type(ndarray) == numpy.ndarray or (type(ndarray) == type(()) and len(ndarray) == 2):
                    self.dtype_str = self._dtype_pack(ndarray)
                    self.shape = ndarray.shape if type(ndarray) == numpy.ndarray else ndarray[1]
                    self.size = numpy.multiply.reduce(self.shape)
                else:
                    raise TypeError('The specified ndarray is not a tuple (dtype,shape) or an array of type numpy.ndarray (it has type: ' + str(type(ndarray)) + ')')
            else:
                self._calcsize()

    def _dtype_pack(self, ndarray):
        '''Generate a numpy compatible description string from the specified numpy array.'''
        if type(ndarray) == type(()):
            d = {}
            d['shape'] = ndarray[1]
            d['fortran_order'] = False
            d['descr'] = numpy.lib.format.dtype_to_descr(ndarray[0])
        else:
            d = numpy.lib.format.header_data_from_array_1_0(ndarray)
        header = ["{"]
        for key, value in sorted(d.items()):
            # Need to use repr here, since we eval these when reading
            header.append("'%s': %s, " % (key, repr(value)))
        header.append("}")
        return "".join(header)

    def _calcsize(self):
        '''Generate self.size, which says how many repetitions of self.format are in a vector.  A size
        of -1 signifies a 1D dynamically sized array.'''
        if self.shape == -1: self.size = -1
        else:
            try: self.size = reduce(lambda x,y: x*y, self.shape)
            except(TypeError): self.size = 1
        self.nbits = calcsize(self.format) * self.size
        # If nbits is smaller than ADDRSIZE, generate offset needed for reading ADDRSIZE
        if self.nbits > 0 and self.nbits < ADDRSIZE: self._offset = ADDRSIZE - self.nbits
        else: self._offset = 0

    def pack(self, val):
        '''Convert a series of values into a binary string according to the format of this Descriptor.
        Multi-dimensonal arrays are serialized in C-like order (as opposed to Fortran-like).'''
        if self.shape != -1 and len(self.shape) != 0:
            val = numpy.array(val)
            dim = calcdim(self.format)
            if self.shape == -1: val = numpy.reshape(val, (val.size/dim,dim))
            else: val = numpy.reshape(val, (self.size, dim))
        st = time.time()
        ret = pack(self.format, val)
        return ret

    def pack_numpy(self, val):
        val = numpy.array(val)
         # make sure we have a valid array
        return val.byteswap().data.__str__()

    def unpack(self, s):
        '''Convert a binary string into a value based on the format and shape of this Descriptor.'''
        logger.debug("Using traditional unpack")
        try:
            val = unpack(self.format, s[self._offset/8:], cnt=self.size, offset=self._offset%8)
        except ValueError, e:
            raise ValueError(''.join(e.args) + ': Could not unpack %s: fmt=%s, size=%d, _offset=%d, but length of binary string was %d' % (self.name, parsefmt(self.format), self.size, self._offset, len(s)))
        if self.shape == -1 or len(self.shape) != 0:
            val = numpy.array(val)
            if self.shape != -1: val.shape = self.shape
        if self.format[0] == 's': val = val[0]
        return val

    def unpack_numpy(self,s):
        '''If our format string is numpy compatible, then convert string directly into numpy array.'''
        logger.debug("Using numpy unpack") 
        val = numpy.fromstring(s, dtype=self.dtype, count=self.size).byteswap()
        val.shape = self.shape
        return val

    #def resolve_ids(self, id_dict={}):
    #    '''Use a dictionary of IDs to resolve descriptors that are linked to other descriptors.'''
    #    self._unresolved_ids = {}
    #    if self.count[0] == '1':
    #        try: self.count = id_dict[self.count[1]]
    #        except(KeyError): self._unresolved_ids[self.count[1]] = None
    #    for i, u in enumerate(self.unpack_list):
    #        try: self.unpack_list[i] = id_dict[u[1]]
    #        except(KeyError): self._unresolved_ids[self.count[1]] = None
    #    ids = self._unresolved_ids.keys()
    #    return len(ids) == 0, ids
    def to_descriptor_string(self):
        '''Create a string representation that encodes the attributes of this descriptor.'''
        if self.size == -1: shape = pack(SHAPE_FMT, ((2, 0),))
        else: shape = pack(SHAPE_FMT, [(0, s) for s in self.shape])
        heap = {
            ID_ID: (IMMEDIATEADDR, pack(ID_FMT, ((0, self.id),))),
            SHAPE_ID: (DIRECTADDR, shape),
            FORMAT_ID: (DIRECTADDR, self.format),
            NAME_ID: (DIRECTADDR, self.name),
            DESCRIPTION_ID: (DIRECTADDR, self.description),
            HEAP_CNT_ID: (IMMEDIATEADDR, ADDRNULL),
        }
        if self.dtype_str is not None:
            heap[DTYPE_ID] = (DIRECTADDR, self.dtype_str)

        return ''.join([p for p in iter_genpackets(heap)])

    def _dtype_unpack(self, s):
        # pulled from np.lib.format.read_array_header_1_0
        # The header is a pretty-printed string representation of a literal Python
        # dictionary with trailing newlines padded to a 16-byte boundary. The keys
        # are strings.
        #   "shape" : tuple of int
        #   "fortran_order" : bool
        #   "descr" : dtype.descr
        try:
            d = safe_eval(s)
        except SyntaxError, e:
            msg = "Cannot parse descriptor: %r\nException: %r"
            raise ValueError(msg % (s, e))
        if not isinstance(d, dict):
            msg = "Descriptor is not a dictionary: %r"
            raise ValueError(msg % d)
        keys = d.keys()
        keys.sort()
        if keys != ['descr', 'fortran_order', 'shape']:
            msg = "Descriptor does not contain the correct keys: %r"
            raise ValueError(msg % (keys,))
        # Sanity-check the values.
        if (not isinstance(d['shape'], tuple) or
            not numpy.all([isinstance(x, (int,long)) for x in d['shape']])):
            msg = "shape is not valid: %r"
            raise ValueError(msg % (d['shape'],))
        if not isinstance(d['fortran_order'], bool):
            msg = "fortran_order is not a valid bool: %r"
            raise ValueError(msg % (d['fortran_order'],))
        try:
            dtype = numpy.dtype(d['descr'])
        except TypeError, e:
            msg = "descr is not a valid dtype descriptor: %r"
            raise ValueError(msg % (d['descr'],))
        return d['shape'], d['fortran_order'], dtype


    def from_descriptor_string(self, s):
        '''Set the attributes of this descriptor from a string generated by to_descriptor_string().'''
        for heap in iterheaps(TransportString(s)):
            items = heap.get_items()
            self.id = unpack(ID_FMT, items[ID_ID])[0][-1]
            shape = unpack(SHAPE_FMT, items[SHAPE_ID], cnt=-1)
            # Check if we have a dynamically sized value
            try:
                if shape[0][0] == 2: self.shape = -1
                else: self.shape = [s[1] for s in shape]
            except(IndexError,TypeError): self.shape = []
            self.format = items[FORMAT_ID]
            self.dtype_str = None
            self.dtype = None
            self.fortran_order = False
            if items.has_key(DTYPE_ID):
                self.dtype_str = ''.join(f[0] for f in items[DTYPE_ID])
                self.shape, self.fortran_order, self.dtype = self._dtype_unpack(self.dtype_str)
                self.size = numpy.multiply.reduce(self.shape)
            else:
                self._calcsize()
            self.name = ''.join([f[0] for f in items[NAME_ID]])
            self.description = ''.join([f[0] for f in items[DESCRIPTION_ID]])

#  ___ _                 
# |_ _| |_ ___ _ __ ___  
#  | || __/ _ \ '_ ` _ \ 
#  | || ||  __/ | | | | |
# |___|\__\___|_| |_| |_|

class Item(Descriptor):
    '''An Item inherits from a Descriptor, and adds a value that can be set, retrieved, an converted
    into a binary string.  An Item also keeps track of when its value has changed.'''
    def __init__(self, name='', id=None, description='', 
            shape=[], fmt=DEFAULT_FMT, from_string=None, ndarray=None, init_val=None):
        if init_val is not None and type(init_val) == numpy.ndarray and shape==[] and fmt==DEFAULT_FMT:
            ndarray = init_val
             # if we can, setup our shape and format from the initial value. Honour any override from the user in terms of shape and format.
        Descriptor.__init__(self, from_string=from_string, id=id,
            name=name, description=description, shape=shape, fmt=fmt, ndarray=ndarray)
        self._value = None
        self._changed = False
        if not init_val is None: self.set_value(init_val)
    def set_value(self, v):
        '''Directly set the value of this Item to the provided value, and mark this Item as changed.'''
        if self.size != -1 and len(self.shape) == 0:
            v = (v,)
            if calcdim(self.format) == 1: v = [(x,) for x in v]
        self._value = v
        self._changed = True
    def from_value_string(self, s):
        '''Set the value of this Item by unpacking the provided binary string.'''
        if self.dtype_str is not None: self._value, self._changed = self.unpack_numpy(s), True
        else: self._value, self._changed = self.unpack(s), True
    def get_value(self):
        '''Directly return the value of this Item.'''
        v = self._value
        if self.shape != -1 and len(self.shape) == 0:
            if calcdim(self.format) == 1: v = [x[0] for x in v]
            v = v[0]
        return v
    def to_value_string(self):
        '''Return the value of this Item encoded as a binary string.'''
        if self._value == None: raise RuntimeError('item "%s" (ID=%d): value was not initialized' % (self.name, self.id))
        try:
            if self.dtype_str is not None: return self.pack_numpy(self._value)
            else: return self.pack(self._value)
        except(TypeError,ValueError): raise TypeError('item "%s" (ID=%d): had an invalid value for format=%s, shape=%s: %s' % (self.name, self.id, [self.format], self.shape, self._value))
    def has_changed(self):
        '''Return whether this Item has been changed.'''
        return self._changed
    def unset_changed(self):
        '''Mark this Item as unchanged.'''
        self._changed = False

#  ___ _                  ____                       
# |_ _| |_ ___ _ __ ___  / ___|_ __ ___  _   _ _ __  
#  | || __/ _ \ '_ ` _ \| |  _| '__/ _ \| | | | '_ \ 
#  | || ||  __/ | | | | | |_| | | | (_) | |_| | |_) |
# |___|\__\___|_| |_| |_|\____|_|  \___/ \__,_| .__/ 
#                                             |_|    

class ItemGroup:
    '''An ItemGroup is a collection of Items whose collective state may be synchronized to another
    instance of an ItemGroup via heaps that are encoded as SPEAD packets.'''
    def __init__(self):
        self.heap_cnt = 1  # We start heap_cnt at 1 b/c control packets have heap_cnt = 0
        self._items = {}
        self._names = {}
        self._new_names = []
    def add_item(self, *args, **kwargs):
        '''Add an Item to the group.  The state of this Item will be propagated through the heaps
        of this ItemGroup.  Arguments to this function are passed directly to the Item constructor.'''
        item = Item(*args, **kwargs)
        if item.id is None:
            item.id = UNRESERVED_OPTION + len(self._items)
            while self._items.has_key(item.id): item.id += 1
        self._items[item.id] = item
        self._new_names.append(item.name)
        self._update_keys()
    def _update_keys(self):
        '''Regenerate the self._names dictionary that maps Item names to the ids by which Items
        are indexed in self._items.'''
        self._names = {}
        for o in self._items.itervalues(): self._names[o.name] = o.id
    def get_item(self, name):
        '''Return the Item with the requested name.'''
        return self._items[self._names[name]]
    def keys(self):
        '''Return a list of the names of all Items.'''
        return self._names.keys()
    def ids(self):
        '''Return a list of the ids of all Items.'''
        return self._items.keys()
    def __getitem__(self, name):
        '''ItemGroup[name] returns the value of the Item with the provided name.'''
        return self.get_item(name).get_value()
    def __setitem__(self, name, val):
        '''ItemGroup[name] = val sets the value of the Item with the provided name.'''
        return self.get_item(name).set_value(val)
    def get_heap(self, heap=None):
        '''Return the heap that must be transmitted to propagate the change in the state of 
        this ItemGroup since the last time this function was called.  An existing heap
        (a dictionary) can be provided as a starting point, if desired.'''
        # Inject an automatically generated heap count
        logger.info('ITEMGROUP.get_heap: Building heap with HEAP_CNT=%d' % self.heap_cnt)
        if heap is None: heap = {}
        heap[HEAP_CNT_ID] = (IMMEDIATEADDR, pack(DEFAULT_FMT, ((self.heap_cnt,),)))
        self.heap_cnt += 1
        # Process descriptors for any items that have been added. Since there can 
        # be multiple ITEM_DESCRIPTORs, it will be a list that is specially handled.
        heap[DESCRIPTOR_ID] = []
        while len(self._new_names) > 0:
            id = self._names[self._new_names.pop()]
            item = self._items[id]
            if DEBUG: logger.debug('ITEMGROUP.get_heap: Adding descriptor for id=%d (name=%s)' % (item.id, item.name))
            heap[DESCRIPTOR_ID].append(item.to_descriptor_string())
        # Add entries for any items that have changed
        for item in self._items.itervalues():
            if not item.has_changed(): continue
            val = item.to_value_string()
            if len(val) > ADDRLEN or item.size < 0: mode = DIRECTADDR
            else: mode = IMMEDIATEADDR
            if DEBUG: logger.debug('ITEMGROUP.get_heap: Adding entry for id=%d (name=%s)' % (item.id, item.name))
            heap[item.id] = (mode, val)
            # Once data is gathered from changed item, mark it as unchanged
            item.unset_changed()
        logger.info('ITEMGROUP.get_heap: Done building heap with HEAP_CNT=%d' % (self.heap_cnt - 1))
        return heap
    def update(self, heap):
        '''Update the state of this ItemGroup using the heap generated by ItemGroup.get_heap().'''
        self.heap_cnt = heap.heap_cnt
        logger.info('ITEMGROUP.update: Updating values from heap with HEAP_CNT=%d' % (self.heap_cnt))
        # Handle any new DESCRIPTORs first
        items = heap.get_items()
        for d in items[DESCRIPTOR_ID]:
            if DEBUG: 
                logger.debug('ITEMGROUP.update: Processing descriptor')
                logger.debug(readable_binpacket(d, prepend='ITEMGROUP.update:'))
            self.add_item(from_string=d)
        # Now propagate changed values for known items (unknown ones are ignored)
        for id in self.ids():
            if DEBUG: logger.debug('ITEMGROUP.update: Updating value for id=%d, name=%s' % (id, self._items[id].name))
            try: self._items[id].from_value_string(items[id])
            except(KeyError): continue

#  ____  ____  _____    _    ____    ____  __  __   _______  __
# / ___||  _ \| ____|  / \  |  _ \  |  _ \ \ \/ /  |_   _\ \/ /
# \___ \| |_) |  _|   / _ \ | | | | | |_) | \  /_____| |  \  / 
#  ___) |  __/| |___ / ___ \| |_| | |  _ <  /  \_____| |  /  \ 
# |____/|_|   |_____/_/   \_\____/  |_| \_\/_/\_\    |_| /_/\_\

def iter_genpackets(heap, max_pkt_size=MAX_PACKET_LEN):
    '''Provided a heap (dictionary of IDs and binary string values),
    iterate over the set of binary SPEAD packets that propagate this data
    to a receiver.  The stream will be broken into packets of the specified maximum size.'''
    assert(heap.has_key(HEAP_CNT_ID))  # Every heap has to have a HEAP_CNT
    pkt = SpeadPacket()
    descriptors = heap.pop(DESCRIPTOR_ID, [])
    items, heap_pyld, offset = [], [], 0
    logger.info('itergenpackets: Converting a heap into packets')
    # Add descriptors
    for d in descriptors:
        if DEBUG: logger.debug('itergenpackets: Adding a descriptor to header')
        dlen = len(d)
        items.append((DIRECTADDR, DESCRIPTOR_ID, offset))
        heap_pyld.append(d); offset += dlen
    # Add other items
    for id,(mode,val) in heap.iteritems():
        vlen = len(val)
        if mode == DIRECTADDR:
            if DEBUG: logger.debug('itergenpackets: Adding extension item to header, id=%d, len(val)=%d' % (id, len(val)))
            items.append((DIRECTADDR, id, offset))
            heap_pyld.append(val); offset += vlen
        # Pad out to ADDRLEN for bits < ADDRSIZE
        else:
            if DEBUG: logger.debug('itergenpackets: Adding standard item to header, id=%d, len(val)=%d' % (id, len(val)))
            items.append((IMMEDIATEADDR, id, unpack(DEFAULT_FMT, (ADDRNULL+val)[-ADDRLEN:])[0][0]))
    heap_pyld = ''.join(heap_pyld)
    heap_len, payload_cnt, offset = len(heap_pyld), 0, 0
    while True:
        # The first packet contains all of the header entries for the items that changed
        # Subsequent packets are continuations that increment payload_cnt until all data is sent
        # XXX Need to check that # of changed items fits in MAX_PACKET_LEN.
        if payload_cnt == 0: h = items
        else: h = [(IMMEDIATEADDR, HEAP_CNT_ID, unpack(DEFAULT_FMT, heap[HEAP_CNT_ID][1])[0][0])]
        hlen = ITEMLEN * (len(h) + 4) # 4 for the spead hdr, heap_len, payload_len and payload_off
        payload_len = min(MAX_PACKET_LEN - hlen, heap_len - offset)
        h.append((IMMEDIATEADDR, HEAP_LEN_ID, heap_len))
        h.append((IMMEDIATEADDR, PAYLOAD_LEN_ID, payload_len))
        h.append((IMMEDIATEADDR, PAYLOAD_OFF_ID, offset))
        pkt.items = h
        pkt.payload = heap_pyld[offset:offset+payload_len]
        if DEBUG: logger.debug('itergenpackets: Made packet with hlen=%d, payoff=%d, paylen=%d' \
            % (len(h), offset, payload_len))
        yield pkt.pack()
        offset += payload_len ; payload_cnt += 1
        if offset >= heap_len: break
    logger.info('itergenpackets: Done converting a heap into packets')
    return

#  _____                                     _   
# |_   _| __ __ _ _ __  ___ _ __   ___  _ __| |_ 
#   | || '__/ _` | '_ \/ __| '_ \ / _ \| '__| __|
#   | || | | (_| | | | \__ \ |_) | (_) | |  | |_ 
#   |_||_|  \__,_|_| |_|___/ .__/ \___/|_|   \__|
#                          |_|                   

class TransportString:
    def __init__(self, s='', allow_junk=False):
        self.offset = 0
        self.data = s
        self.allow_junk = allow_junk
        self.got_term_sig = False
    def iterpackets(self):
        '''Iterate over all valid packets in string until the string ends or STREAM_CTRL = TERM is received.'''
        while not self.got_term_sig:
            pkt = SpeadPacket()
            try:
                self.offset += pkt.unpack(self.data[self.offset:])
                # Check if this pkt has a stream terminator
                if pkt.is_stream_ctrl_term:
                    self.got_term_sig = True
                    break
                if DEBUG: logger.debug('TRANSPORTSTRING.iterpackets: Yielding packet, offset=%d/%d' % (self.offset, len(self.data)))
                yield pkt
            except(ValueError):
                if self.offset >= len(self.data) - ITEMLEN:
                    if DEBUG: logger.debug('TRANSPORTSTRING.iterpackets: Reached end of string')
                    break
                elif self.allow_junk:
                    if DEBUG: logger.debug('TRANSPORTSTRING.iterpackets: Skipping a byte')
                    self.offset += 1
                else: break
        return
    def seek(self, val=0):
        '''Set the reading offset of this string to the specified value.'''
        self.offset = val
        self.got_term_sig = False

class TransportFile(file):
    def __init__(self, *args, **kwargs):
        self._file = None
        # Allow for an open file (like sys.stdin or sys.stdout) to be in the arguments
        if type(args[0]) == file: self._file = args[0]
        else: file.__init__(self, *args, **kwargs)
    def iterpackets(self):
        if self._file: self = self._file
        ts = TransportString(self.read(MAX_PACKET_LEN))
        while True:
            for pkt in ts.iterpackets(): yield pkt
            if not ts.got_term_sig:
                if DEBUG: logger.debug('TRANSPORTFILE.iterpackets: Reading more data')
                s = self.read(MAX_PACKET_LEN)
                if len(s) == 0:
                    if DEBUG: logger.debug('TRANSPORTFILE.iterpackets: End of file')
                    break
                else: ts = TransportString(ts.data[ts.offset:]+s)
            else: break
        return
    def write(self, s):
        if DEBUG: logger.debug('TRANSPORTFILE.write: Writing %d bytes' % len(s))
        if self._file: return self._file.write(s)
        else: return file.write(self, s)

class TransportUDPtx:
    def __init__(self, ip, port):
        self._udp_out = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self._tx_ip_port = (ip, port)
    def write(self, data):
        self._udp_out.sendto(data, self._tx_ip_port)

class TransportUDPrx(BufferSocket):
    def __init__(self, port, pkt_count=128, buffer_size=0):
        BufferSocket.__init__(self, pkt_count)
        self.pkts = []
        def callback(pkt): self.pkts.insert(0, pkt)
        self.set_callback(callback)
        self.start(port, buffer_size)
    def iterpackets(self):
        while self.is_running():
            if len(self.pkts) > 0:
                try:
                    while True: yield self.pkts.pop()
                except IndexError:
                    pass # we have handled current packet queue
            time.sleep(0.00001)
        logger.info('TRANSPORTUDPRX: Stream was shut down')
        return

#  _____                              _ _   _            
# |_   _| __ __ _ _ __  ___ _ __ ___ (_) |_| |_ ___ _ __ 
#   | || '__/ _` | '_ \/ __| '_ ` _ \| | __| __/ _ \ '__|
#   | || | | (_| | | | \__ \ | | | | | | |_| ||  __/ |   
#   |_||_|  \__,_|_| |_|___/_| |_| |_|_|\__|\__\___|_|   

class Transmitter:
    '''A Transmitter converts a heap into a series of packets that are fed to Transport.write().'''
    def __init__(self, transport):
        self.t = transport
    def send_heap(self, heap, max_pkt_size=MAX_PACKET_LEN):
        '''Convert a heap from an ItemGroup into a series of packets (each of the specified
        maximum packet size) and write those packets to this Transmitter's Transport.  If not
        all ids in a heap are to be sent, ids_to_send should contain the ones to be transmitted.'''
        if DEBUG: logger.debug(readable_heap(heap, prepend='TX.send_heap:'))
        for cnt, p in enumerate(iter_genpackets(heap, max_pkt_size=max_pkt_size)):
            logger.info('TX.send_heap: Sending heap packet %d' % (cnt))
            if DEBUG: logger.debug(readable_binpacket(p, prepend='TX.send_heap,pkt=%d:' % (cnt)))
            self.t.write(p)

    def send_halt(self):
        '''Send a halt packet without stopping the transmitter.'''
        heap = { HEAP_CNT_ID: (IMMEDIATEADDR, '\xff\xff\xff\xff\xff\xff'),
            STREAM_CTRL_ID: (IMMEDIATEADDR, pack(DEFAULT_FMT, ((STREAM_CTRL_TERM_VAL,),))) }
        logger.info('TX.end: Sending stream terminator')
        self.send_heap(heap)

    def end(self):
        '''Send a packet signalling the end of this stream.'''
        self.send_halt()
        del(self.t) # Prevents any further activity

#  ____               _                
# |  _ \ ___  ___ ___(_)_   _____ _ __ 
# | |_) / _ \/ __/ _ \ \ \ / / _ \ '__|
# |  _ <  __/ (_|  __/ |\ V /  __/ |   
# |_| \_\___|\___\___|_| \_/ \___|_|   

def iterheaps(tport):
    '''Iterate over all valid heaps received through the Transport tport.iterheaps(), assembling heaps 
    from contiguous packets from iterpackets() that have the same HEAP_CNT.  Set heap's ID/values 
    from constituent packets, with packets having higher PAYLOAD_CNTs taking precedence.  Assemble heap's
    heap from the _PAYLOAD of each packet, ordered by PAYLOAD_CNT.  Finally, resolve all IDs with
    extension clauses, replacing them with binary strings from the heap.'''
    heap = SpeadHeap()
    heaps = {}
     # keep track of our currently active heaps
    heap_times = {}
     # keep track of when the first packet arrived for this heap in order to age things.
    logger.info('iterheaps: Getting packets')
    for pkt in tport.iterpackets():
        logger.debug('iterheaps: Packet with HEAP_CNT=%d, HEAP_LEN=%d, PAYLOAD_LEN=%d, PAYLOAD_OFF=%d' % (pkt.heap_cnt, pkt.heap_len, pkt.payload_len, pkt.payload_off))
        if DEBUG: logger.debug(readable_speadpacket(pkt, show_payload=False, prepend='iterheaps:'))
         # get the heap for this packet
        heap_cnt = pkt.heap_cnt
        if not heaps.has_key(heap_cnt):
             # check if we have space...
            while len(heaps) >= MAX_CONCURRENT_HEAPS:
                # choose the oldest stale heap to replace
                pop_idx = [x for x in heap_times.items() if x[1] == min(heap_times.values())][0][0]
                partial_heap = heaps.pop(pop_idx)
                logger.info('iterheaps: Removing stale heap (and attempting unpack) with HEAP_CNT=%d (created at %s) to make space for new heaps.' % (pop_idx, time.ctime(heap_times.pop(pop_idx))))
                partial_heap.finalize()
                if partial_heap.is_valid: yield partial_heap
                else: logger.warning('iterheaps: Invalid spead heap %d found (SpeadHeap.has_all_packets=%d)' % (pop_idx,partial_heap.has_all_packets))
            heaps[heap_cnt] = SpeadHeap()
            heap_times[heap_cnt] = time.time()
            logger.info('iterheaps: Creating new heap for HEAP_CNT=%d. Currently %d active heaps.' % (heap_cnt,heaps.__len__()))
        heap = heaps[heap_cnt]
        # Check if we have finished a heap
        try:
            heapdone = heap.add_packet(pkt) # If heap_len is set, we can know heap is done before next heap starts
            pkt = None # If no error was raised, we're done with this packet
        except(ValueError): heapdone = True
        if heapdone:
            logger.info('iterheaps: Heap %d completed, attempting to unpack heap' % heap.heap_cnt)
            heap.finalize()
            logger.info('iterheaps: SpeadHeap.is_valid=%d' % heap.is_valid)
            if heap.is_valid: yield heap
            else: logger.warning('iterheaps: Invalid spead heap %d found (SpeadHeap.has_all_packets=%d)' % (heap.heap_cnt,heap.has_all_packets))
            logger.info('iterheaps: Starting new heap')
            heaps.pop(heap_cnt)
            heap_times.pop(heap_cnt)
             # we are done with this heap...
            #if not pkt is None: heap.add_packet(pkt) # If pkt was rejected, add it to the next heap
             # packets should not be rejected as they are added to the heap identified by their internal count
    logger.info('iterheaps: Last packet in stream received, processing any stale heaps.')
    for heap in heaps.itervalues():
        logger.info('iterheaps: Attempting to unpack stale heap %d' % heap.heap_cnt)
        heap.finalize()
        logger.info('iterheaps: SpeadHeap.is_valid=%d' % heap.is_valid)
        if heap.is_valid: yield heap
    logger.info('iterheaps: Finished all heaps')
    return

