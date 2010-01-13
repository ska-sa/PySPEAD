'''
Data packet:
[ SPEAD #    (16b)     | Ver (16b) | 0 (16b) | # Items (16b) ]
[ Ext (1b) | ID1 (15b) |           Value (48b)               ]
[ Ext (1b) | ID2 (15b) | Ext Start (24b) | Ext Length (24b)  ]
...
[ Payload (heap) .............................................
.............................................................]
'''
import socket, bitstring, math, numpy, logging, sys

logger = logging.getLogger('spead')

#   ____                _              _       
#  / ___|___  _ __  ___| |_ __ _ _ __ | |_ ___ 
# | |   / _ \| '_ \/ __| __/ _` | '_ \| __/ __|
# | |__| (_) | | | \__ \ || (_| | | | | |_\__ \
#  \____\___/|_| |_|___/\__\__,_|_| |_|\__|___/

SPEAD_MAGIC = 0x4b52
VERSION = 3
MAX_PACKET_SIZE = 9200
MAX_PAYLOADS_IN_FRAME = 4096
UNRESERVED_OPTION = 2**12

FRAME_CNT_ID = 0x01
PAYLOAD_CNTLEN_ID = 0x02
HEAP_LENOFF_ID = 0x03
DESCRIPTOR_ID = 0x04
STREAM_CTRL_ID = 0x05
NAME_ID = 0x06
DESCRIPTION_ID = 0x07
SHAPE_ID = 0x08
FORMAT_ID = 0x09
ID_ID = 0x10
_PAYLOAD_ID = 0x00

DEFAULT_FMT = (('u',48),)
HDR_FMT = (('u',16),('u',16),('u',16),('u',16))
RAW_ITEM_FMT = (('u',1),('u',15),('c',48))
ITEM_FMT = (('u',1),('u',15),('u',48))
EXTITEM_FMT = (('u',1),('u',15),('u',24),('u',24))
IEXT_FMT = (('u',24),('u',24))
ID_FMT = (('u',32),('u',16))
SHAPE_FMT = (('u',8),('u',56))
FORMAT_FMT = (('c',8),('u',16))
HEAP_LENOFF_FMT =  (('u',24),('u',24))    # Heap length, Heap offset
PAYLOAD_CNTLEN_FMT =  (('u',24),('u',24)) # Payload counter, payload length
STR_FMT = (('c',8),)

ITEM = {
    'PAYLOAD_CNTLEN': {'ID':PAYLOAD_CNTLEN_ID, 'FMT':PAYLOAD_CNTLEN_FMT, 'CNT':1},
    'FRAME_CNT':      {'ID':FRAME_CNT_ID,      'FMT':DEFAULT_FMT,        'CNT':1},
    'DESCRIPTOR':     {'ID':DESCRIPTOR_ID,     'FMT':SPEAD_MAGIC,        'CNT':1},
    'STREAM_CTRL':    {'ID':STREAM_CTRL_ID,    'FMT':DEFAULT_FMT,        'CNT':1},
    'NAME':           {'ID':NAME_ID,           'FMT':STR_FMT,            'CNT':-1},
    'SHAPE':          {'ID':SHAPE_ID,          'FMT':SHAPE_FMT,          'CNT':-1},
    'FORMAT':         {'ID':FORMAT_ID,         'FMT':FORMAT_FMT,         'CNT':-1},
    'DESCRIPTION':    {'ID':DESCRIPTION_ID,    'FMT':STR_FMT,            'CNT':-1},
    'ID':             {'ID':ID_ID,             'FMT':ID_FMT,             'CNT':1},
    'HEAP_LENOFF':    {'ID':HEAP_LENOFF_ID,    'FMT':HEAP_LENOFF_FMT,    'CNT':1},
    '_PAYLOAD':       {'ID':_PAYLOAD_ID,       'FMT':None,               'CNT':0},
                            # Used carry payload data before assembly into heap
}

NAME = {}
for name, d in ITEM.iteritems(): NAME[d['ID']] = name

ITEM_BITS = 64
ITEM_BYTES = ITEM_BITS / 8
IVAL_BITS = 48
IVAL_BYTES = IVAL_BITS / 8
IVAL_NULL = '\x00'*6
STREAM_CTRL_TERM_VAL = 0x2

pack_types = {
    'i': lambda b: 'int:%d' % b,
    'u': lambda b: 'uint:%d' % b,
    'f': lambda b: 'float:%d' % b,
    'c': lambda b: 'bytes:%d' % (b/8), # bitstring specifies 'bytes' in bytes, not bits
    'b': lambda b: 'bin:%d' % b,
}

#  _   _ _   _ _ _ _         
# | | | | |_(_) (_) |_ _   _ 
# | | | | __| | | | __| | | |
# | |_| | |_| | | | |_| |_| |
#  \___/ \__|_|_|_|\__|\__, |
#                      |___/ 

def calcsize(fmt):
    return sum([f[1] for f in fmt])

def conv_format(fmt):
    return ','.join([pack_types[f[0]](f[1]) for f in fmt])
    
def pack_to_bitstring(fmt, *args):
    return bitstring.pack(conv_format(fmt), *args)

def pack(fmt, *args):
    return pack_to_bitstring(fmt, *args).bytes

def unpack_iter(fmt, data, cnt=1, offset=0):
    if not type(data) == bitstring.BitString: data = bitstring.BitString(bytes=data)
    data.pos = offset
    cfmt = conv_format(fmt)
    if cnt < 0:
        # Read a dynamic number of entries
        try:
            while True:
                p = data.pos
                d = data.readlist(cfmt)
                if data.pos == p: return  # End iterator if no data was actually read
                yield d
        except(ValueError): return
    else:
        # Read a static number of entries
        for c in range(cnt): yield data.readlist(cfmt)
        return

def unpack(fmt, data, cnt=1, offset=0):
    return [u for u in unpack_iter(fmt, data, cnt=cnt, offset=offset)]

def readable_header(h, prepend=''):
    is_ext, id, raw_val = unpack(RAW_ITEM_FMT, h)[0]
    bs = bitstring.BitString(bytes=raw_val)
    if is_ext: val = 'EXT OFF=%s LEN=%s' % (bs.hex[2:8], bs.hex[8:14])
    else: val = '     RAW_VAL=%s' % (bs.hex[2:])
    try: return prepend+'[ IS_EXT=%d | NAME=%16s | %s ]' % (is_ext, NAME[id], val)
    except(KeyError): return prepend+'[ IS_EXT=%d | ID=%18d | %s ]' % (is_ext, id, val)

def readable_packet(pkt, prepend=''):
    o, rv = 0, ['', 'vvv PACKET ' + 'v'*(59-len(prepend))]
    magic, version, junk, n_options = unpack(HDR_FMT, pkt[o:o+ITEM_BYTES])[0] ; o += ITEM_BYTES
    rv.append(' HEADER:[ SPEAD-CODE=%d | VERSION=%d | --- | N_OPTIONS=%d ]' % (magic, version, n_options))
    for cnt in range(n_options):
        rv.append(readable_header(pkt[o:o+ITEM_BYTES], prepend='ITEM%02d:' % (cnt)))
        o += ITEM_BYTES
    rv.append('PAYLOAD: BYTES=%d' % (len(pkt[o:])))
    rv.append('^'*(70-len(prepend)))
    return '\n'.join([prepend+r for r in rv])

def readable_frame(frame, prepend=''):
    rv = ['', 'vvv FRAME ' + 'v'*60]
    for id in frame:
        try:
            name = NAME[id]
            if name == 'DESCRIPTOR':
                for cnt, d in enumerate(frame[id]):
                    rv += readable_packet(d, prepend='DESCRIPTOR%d:' % (cnt)).split('\n')
            else:
                fmt, cnt = ITEM[name]['FMT'], ITEM[name]['CNT']
                val = unpack(fmt, frame[id][1], cnt=cnt)
                try:
                    while type(val) != str and len(val) == 1: val = val[0]
                except(TypeError): pass
                s = '%16s: %s' % (name, val)
                if len(s) > (70 - len(prepend)): s = s[:(70-len(prepend)-3)]+'...'
                rv.append(s)
        except(KeyError):
            val = bitstring.BitString(bytes=frame[id][1])
            s = '%16d: %s' % (id, val.hex)
            if len(s) > (70 - len(prepend)): s = s[:(70-len(prepend)-3)]+'...'
            rv.append(s)
    rv.append('^'*70)
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
    A shape of -1 creates a dynamically-sized 1D array.'''
    def __init__(self, from_string=None, id=None, name='', description='', shape=[], fmt=DEFAULT_FMT):
        if from_string: self.from_descriptor_string(from_string)
        else:
            self.id = id
            self.name = name
            self.description = description
            self.shape = shape
            self.format = fmt
            self._calcsize()
    def _calcsize(self):
        '''Generate self.size, which says how many repetitions of self.format are in a vector.  A size
        of -1 signifies a 1D dynamically sized array.'''
        if self.shape == -1: self.size = -1
        else:
            try: self.size = reduce(lambda x,y: x*y, self.shape)
            except(TypeError): self.size = 1
        self.nbits = calcsize(self.format) * self.size
        # If nbits is smaller than IVAL_BITS, generate offset needed for reading IVAL_BITS
        if self.nbits > 0 and self.nbits < IVAL_BITS: self._offset = IVAL_BITS - self.nbits
        else: self._offset = 0
    def pack(self, *val):
        '''Convert a series of values into a binary string according to the format of this Descriptor.
        Multi-dimensonal arrays are serialized in C-like order (as opposed to Fortran-like).'''
        if len(self.shape) == 0: rv = pack(self.format, *val)
        else:
            dim = len(self.format)
            if self.shape == -1: val = numpy.reshape(val, (val.size/dim,dim))
            else: val = numpy.reshape(val, (self.size, dim))
            rv = ''.join([pack(self.format, *v) for v in val])
        return rv
    def unpack(self, s):
        '''Convert a binary string into a value based on the format and shape of this Descriptor.'''
        # Use self._offset to skip bits if this item has less than IVAL_BITS bits
        if len(self.shape) == 0:
            if len(self.format) == 1: return unpack(self.format, s, cnt=self.size, offset=self._offset)[0][0]
            else: return unpack(self.format, s, cnt=self.size, offset=self._offset)[0]
        else:
            v = numpy.array(unpack(self.format, s, cnt=self.size, offset=self._offset))
            if self.shape != -1: v.shape = self.shape
            return v
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
        if self.size == -1: shape = pack(SHAPE_FMT, 2, 0)
        else: shape = ''.join([pack(SHAPE_FMT, 0, s) for s in self.shape])
        frame = {
            ID_ID: (0, pack(ID_FMT, 0, self.id)),
            SHAPE_ID: (1, shape),
            FORMAT_ID: (1, ''.join([pack(FORMAT_FMT, *f) for f in self.format])),
            NAME_ID: (1, self.name),
            DESCRIPTION_ID: (1, self.description),
            FRAME_CNT_ID: (0, IVAL_NULL),
        }
        return ''.join([p for p in iterpackets(frame)])
    def from_descriptor_string(self, s):
        '''Set the attributes of this descriptor from a string generated by to_descriptor_string().'''
        for frame in Receiver(TransportString(s)).iterframes():
            self.id = unpack(ID_FMT, frame[ID_ID][1])[0][-1]
            shape = unpack(SHAPE_FMT, frame[SHAPE_ID][1], cnt=-1)
            # Check if we have a dynamically sized value
            try:
                if shape[0][0] == 2: self.shape = -1
                else: self.shape = [s[1] for s in shape]
            except(IndexError,TypeError): self.shape = []
            self.format = unpack(FORMAT_FMT, frame[FORMAT_ID][1], cnt=-1)
            self.name = ''.join([f[0] for f in frame[NAME_ID][1]])
            self.description = ''.join([f[0] for f in frame[DESCRIPTION_ID][1]])
            self._calcsize()

#  ___ _                 
# |_ _| |_ ___ _ __ ___  
#  | || __/ _ \ '_ ` _ \ 
#  | || ||  __/ | | | | |
# |___|\__\___|_| |_| |_|

class Item(Descriptor):
    '''An Item inherits from a Descriptor, and adds a value that can be set, retrieved, an converted
    into a binary string.  An Item also keeps track of when its value has changed.'''
    def __init__(self, name='', id=None, description='', 
            shape=[], fmt=DEFAULT_FMT, from_string=None, init_val=None):
        Descriptor.__init__(self, from_string=from_string, id=id,
            name=name, description=description, shape=shape, fmt=fmt)
        self.set_value(init_val)
    def set_value(self, v):
        '''Directly set the value of this Item to the provided value, and mark this Item as changed.'''
        self._value = v
        self._changed = True
    def from_value_string(self, s):
        '''Set the value of this Item by unpacking the provided binary string.'''
        #if len(self.shape) == 0: self.set_value(self.unpack(s)[0])
        #else: self.set_value(self.unpack(s))
        self.set_value(self.unpack(s))
    def get_value(self):
        '''Directly return the value of this Item.'''
        return self._value
    def to_value_string(self):
        '''Return the value of this Item encoded as a binary string.'''
        if len(self.shape) == 0 and len(self.format) == 1: return self.pack(self._value)
        else: return self.pack(*self._value)
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
    instance of an ItemGroup via frames that are encoded as SPEAD packets.'''
    def __init__(self):
        self.frame_cnt = 1  # We start frame_cnt at 1 b/c control packets have frame_cnt = 0
        self._items = {}
        self._names = {}
        self._new_names = []
    def add_item(self, *args, **kwargs):
        '''Add an Item to the group.  The state of this Item will be propagated through the frames
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
    def get_frame(self, frame=None):
        '''Return the frame that must be transmitted to propagate the change in the state of 
        this ItemGroup since the last time this function was called.  An existing frame
        (a dictionary) can be provided as a starting point, if desired.'''
        # Inject an automatically generated frame count
        logger.info('ITEMGROUP.get_frame: Building frame with FRAME_CNT=%d' % self.frame_cnt)
        if frame is None: frame = {}
        frame[FRAME_CNT_ID] = (0, pack(DEFAULT_FMT, self.frame_cnt))
        self.frame_cnt += 1
        # Process descriptors for any items that have been added. Since there can 
        # be multiple ITEM_DESCRIPTORs, it will be a list that is specially handled.
        frame[DESCRIPTOR_ID] = []
        while len(self._new_names) > 0:
            id = self._names[self._new_names.pop()]
            item = self._items[id]
            logger.debug('ITEMGROUP.get_frame: Adding descriptor for id=%d (name=%s)' % (item.id, item.name))
            frame[DESCRIPTOR_ID].append(item.to_descriptor_string())
        # Add entries for any items that have changed
        for item in self._items.itervalues():
            if not item.has_changed(): continue
            val = item.to_value_string()
            is_ext = len(val) > IVAL_BYTES or item.size < 0
            logger.debug('ITEMGROUP.get_frame: Adding entry for id=%d (name=%s)' % (item.id, item.name))
            frame[item.id] = (is_ext, val)
            # Once data is gathered from changed item, mark it as unchanged
            item.unset_changed()
        logger.info('ITEMGROUP.get_frame: Done building frame with FRAME_CNT=%d' % (self.frame_cnt - 1))
        return frame
    def update(self, frame):
        '''Update the state of this ItemGroup using the frame generated by ItemGroup.get_frame().'''
        self.frame_cnt = unpack(DEFAULT_FMT, frame[FRAME_CNT_ID][1])[0][0]
        logger.info('ITEMGROUP.update: Updating values from frame with FRAME_CNT=%d' % (self.frame_cnt))
        # Handle any new ITEM_DESCRIPTORs first
        for d in frame[DESCRIPTOR_ID]:
            logger.debug('ITEMGROUP.update: Processing descriptor')
            logger.debug(readable_packet(d, prepend='ITEMGROUP.update:'))
            self.add_item(from_string=d)
        # Now propagate any changed values for known Items (unknown ones are ignored)
        for id in self.ids():
            logger.debug('ITEMGROUP.update: Updating value for id=%d, name=%s' % (id, self._items[id].name))
            try: self._items[id].from_value_string(frame[id][1])
            except(KeyError): continue

#  ____  ____  _____    _    ____    ____  __  __   _______  __
# / ___||  _ \| ____|  / \  |  _ \  |  _ \ \ \/ /  |_   _\ \/ /
# \___ \| |_) |  _|   / _ \ | | | | | |_) | \  /_____| |  \  / 
#  ___) |  __/| |___ / ___ \| |_| | |  _ <  /  \_____| |  /  \ 
# |____/|_|   |_____/_/   \_\____/  |_| \_\/_/\_\    |_| /_/\_\

def iterpackets(frame, use_heap_lenoff=True, max_pkt_size=MAX_PACKET_SIZE):
    '''Provided a frame (dictionary of IDs and binary string values),
    iterate over the set of binary SPEAD packets that propagate this data
    to a receiver.  The stream will be broken into packets of the specified maximum size.'''
    assert(frame.has_key(FRAME_CNT_ID))  # Every frame has to have a FRAME_CNT
    descriptors = frame.pop(DESCRIPTOR_ID, [])
    hdr, heap, offset = [], [], 0
    logger.info('iterpackets: Converting a frame into packets')
    # Add descriptors
    for d in descriptors:
        logger.debug('iterpackets: Adding a descriptor to header')
        dlen = len(d)
        hdr.append(pack(EXTITEM_FMT, 1, DESCRIPTOR_ID, offset, dlen))
        heap.append(d); offset += dlen
    # Add other items
    for id,(is_ext,val) in frame.iteritems():
        vlen = len(val)
        if is_ext:
            logger.debug('iterpackets: Adding extension item to header, id=%d, len(val)=%d' % (id, len(val)))
            hdr.append(pack(EXTITEM_FMT, 1, id, offset, vlen))
            heap.append(val); offset += vlen
        # Pad out to IVAL_BYTES for bits < IVAL_BITS
        else:
            logger.debug('iterpackets: Adding standard item to header, id=%d, len(val)=%d' % (id, len(val)))
            hdr.append(pack(RAW_ITEM_FMT, 0, id, (IVAL_NULL + val)[-IVAL_BYTES:]))
    heap = ''.join(heap)
    heaplen, payload_cnt, offset = len(heap), 0, 0
    while True:
        # The first packet contains all of the header entries for the items that changed
        # Subsequent packets are continuations that increment payload_cnt until all data is sent
        # XXX Need to check that # of changed items fits in MAX_PACKET_SIZE.
        if payload_cnt == 0: h = hdr
        else: h = [pack(RAW_ITEM_FMT, 0, FRAME_CNT_ID, frame[FRAME_CNT_ID][1])]
        # Heap_lenoff makes it possible to tolerate missed packets on rx
        if use_heap_lenoff: h.append(pack(RAW_ITEM_FMT, 0, HEAP_LENOFF_ID, pack(HEAP_LENOFF_FMT, heaplen, offset)))
        h.insert(0, pack(HDR_FMT, SPEAD_MAGIC, VERSION, 0, len(h)+1))
        hdrlen = ITEM_BYTES * (len(h) + 1)
        payload_len = min(MAX_PACKET_SIZE - hdrlen, heaplen - offset)
        h.append(pack(RAW_ITEM_FMT, 0, PAYLOAD_CNTLEN_ID, pack(PAYLOAD_CNTLEN_FMT, payload_cnt, payload_len)))
        h = ''.join(h)
        logger.debug('iterpackets: Made packet with hdrlen=%d, heapoff=%d, paylen=%d, heaplen=%d' \
            % (len(h), offset, payload_len, heaplen))
        yield h + heap[offset:offset+payload_len]
        offset += payload_len ; payload_cnt += 1
        if offset >= heaplen: break
    logger.info('iterpackets: Done converting a frame into packets')
    return

#  _____                                     _   
# |_   _| __ __ _ _ __  ___ _ __   ___  _ __| |_ 
#   | || '__/ _` | '_ \/ __| '_ \ / _ \| '__| __|
#   | || | | (_| | | | \__ \ |_) | (_) | |  | |_ 
#   |_||_|  \__,_|_| |_|___/ .__/ \___/|_|   \__|
#                          |_|                   

class TransportString:
    def __init__(self, s=''):
        self.offset = 0
        self.data = s
    def read(self, num):
        logger.debug('TRANSPORT(str).read: Reading %d bytes' % num)
        if self.offset + num > len(self.data): raise StopIteration()
        self.offset += num
        return self.data[self.offset-num:self.offset]

class TransportFile(file):
    def read(self, num):
        logger.debug('TRANSPORTFILE.read: Reading %d bytes' % num)
        return file.read(self, num)
    def write(self, s):
        logger.debug('TRANSPORTFILE.write: Writing %d bytes' % len(s))
        return file.write(self, s)

class TransportUDP:
    def __init__(self, tx_ip=None, port=None, rx_buflen=512000, mode='r'):
        if mode == 'w': self._init_tx_socket(tx_ip, port)
        elif mode == 'r': self._init_rx_socket(port, rx_buflen)
        else: raise ValueError('Socket can be only "r" or "w" (got %s)' % mode)
    def _init_tx_socket(self, ip, port):
        self._udp_out = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self._tx_ip_port = (ip, port)
    def _init_rx_socket(self, port, rx_buflen):
        self._udp_in = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self._udp_in.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, rx_buflen)
        self._udp_in.bind(('', port))
        self._udp_in.setblocking(True)
    def write(self, data):
        self._udp_out.sendto(data, self._tx_ip_port)
    def read(self, recv_len=9200):
        data, self._last_rx_ip = self._udp_in.recvfrom(recv_len)
        return data

#  _____                              _ _   _            
# |_   _| __ __ _ _ __  ___ _ __ ___ (_) |_| |_ ___ _ __ 
#   | || '__/ _` | '_ \/ __| '_ ` _ \| | __| __/ _ \ '__|
#   | || | | (_| | | | \__ \ | | | | | | |_| ||  __/ |   
#   |_||_|  \__,_|_| |_|___/_| |_| |_|_|\__|\__\___|_|   

class Transmitter:
    '''A Transmitter converts a frame into a series of packets that are fed to Transport.write().'''
    def __init__(self, transport):
        self.t = transport
    def send_frame(self, frame, max_pkt_size=MAX_PACKET_SIZE):
        '''Convert a frame from an ItemGroup into a series of packets (each of the specified
        maximum packet size) and write those packets to this Transmitter's Transport.  If not
        all ids in a frame are to be sent, ids_to_send should contain the ones to be transmitted.'''
        cnt = 0
        logger.debug(readable_frame(frame, prepend='TX.send_frame:'))
        for p in iterpackets(frame, max_pkt_size=max_pkt_size):
            logger.info('TX.send_frame: Sending frame packet %d' % (cnt)); cnt += 1
            logger.debug(readable_packet(p, prepend='TX.send_frame,pkt=%d:' % (cnt)))
            self.t.write(p)
    def end(self):
        '''Send a packet signalling the end of this stream.'''
        frame = { FRAME_CNT_ID: (0, IVAL_NULL),
            STREAM_CTRL_ID: (0, pack(DEFAULT_FMT, STREAM_CTRL_TERM_VAL)) }
        logger.info('TX.end: Terminating stream')
        self.send_frame(frame)
        del(self.t) # Prevents any further activity
            
#  ____               _                
# |  _ \ ___  ___ ___(_)_   _____ _ __ 
# | |_) / _ \/ __/ _ \ \ \ / / _ \ '__|
# |  _ <  __/ (_|  __/ |\ V /  __/ |   
# |_| \_\___|\___\___|_| \_/ \___|_|   

class Receiver:
    def __init__(self, transport):
        self.t = transport
    def iterpackets(self):
        '''Iterate over all valid packets received through this receiver's transport.  Return packets 
        as dictionaries with item IDs mapped to raw 48-bit values or (24-bit,24-bit) extention clauses.
        Place the payload of each packet (each piece of a frame's heap) under '_PAYLOAD'.
        Call transport.read(), requesting data on an as-needed basis.  When all data from
        transport is exhausted, transport.read() should throw a StopIteration exception.'''
        # XXX should make use of heap_lenoff to permit missing packets
        try:
            while True:
                data = []
                try:
                    logger.info('RX.iterpackets: Attempting to read new packet')
                    try:
                        data.append(self.t.read(ITEM_BYTES))
                        magic, version, unused, n_options = unpack(HDR_FMT, data[-1])[0]
                    except(ValueError):
                        logger.info('RX.iterpackets: No packets available, ending stream')
                        raise StopIteration
                    assert(magic == SPEAD_MAGIC)        # This packet doesn't belong to SPEAD
                    assert(version == VERSION)    # This packet doesn't match this version of SPEAD
                    pkt = {}
                    for i in range(n_options):
                        data.append(self.t.read(ITEM_BYTES))
                        is_ext, id, raw_val = unpack(RAW_ITEM_FMT, data[-1])[0]
                        if id == DESCRIPTOR_ID: pkt[id] = pkt.get(id, []) + [raw_val]
                        else: pkt[id] = (is_ext, raw_val)
                    # Check for a signal that this stream is being terminated
                    if pkt.has_key(STREAM_CTRL_ID) and unpack(DEFAULT_FMT, pkt[STREAM_CTRL_ID][1])[0][0] == STREAM_CTRL_TERM_VAL:
                        logger.info('RX.iterpackets: STREAM_CTRL=TERM, terminating stream')
                        raise StopIteration
                    cnt, length = unpack(PAYLOAD_CNTLEN_FMT, pkt[PAYLOAD_CNTLEN_ID][1])[0]
                    data.append(self.t.read(length))
                    pkt[_PAYLOAD_ID] = (cnt, data[-1])
                    assert(len(pkt[_PAYLOAD_ID][1]) == length) # We ran out of data before the packet ended
                    logger.info('RX.iterpackets: Successfully read packet')
                    logger.debug(readable_packet(''.join(data), prepend='RX.iterpackets:'))
                    yield pkt
                except(AssertionError,KeyError):
                    logger.warning('RX.iterpackets: Got an invalid packet')
        except(StopIteration): return
    def iterframes(self, max_payloads_in_frame=MAX_PAYLOADS_IN_FRAME):
        '''Iterate over all valid frames received through this receiver's transport, assembling frames 
        from contiguous packets from iterpackets() that have the same FRAME_CNT.  Set frame's ID/values 
        from constituent packets, with packets having higher PAYLOAD_CNTs taking precedence.  Assemble frame's
        heap from the _PAYLOAD of each packet, ordered by PAYLOAD_CNT.  Finally, resolve all IDs with
        extension clauses, replacing them with binary strings from the heap.'''
        frame_cnt = -1
        for pkt in self.iterpackets():
            logger.info('RX.iterframes: Packet with FRAME_CNT=%d' % (unpack(DEFAULT_FMT, pkt[FRAME_CNT_ID][1])[0][0]))
            # Check if we have finished a frame
            if pkt[FRAME_CNT_ID][1] != frame_cnt:
                try:
                    assert(frame_cnt != -1)
                    logger.info('RX.iterframes: Frame completed, attempting to unpack heap')
                    # Throws TypeError if a packet is missing
                    heap = ''.join(payload[:max_payload_cnt+1])
                    descriptors = frame.pop(DESCRIPTOR_ID)
                    for i, d in enumerate(descriptors):
                        o,length = unpack(IEXT_FMT, d)[0]
                        descriptors[i] = heap[o:o+length]
                    for id,(is_ext, val) in frame.iteritems():
                        if id == DESCRIPTOR_ID: continue
                        if is_ext:
                            o,length = unpack(IEXT_FMT, val)[0]
                            # Throws IndexError if data is somehow corrupted:
                            frame[id] = (is_ext, heap[o:o+length])
                    frame[DESCRIPTOR_ID] = descriptors
                    logger.info('RX.iterframes: Heap successfully unpacked')
                    logger.debug(readable_frame(frame, prepend='RX.iterframes:'))
                    yield frame
                except(AssertionError,TypeError,IndexError): pass
                finally:
                    logger.info('RX.iterframes: Starting new frame')
                    frame = {}
                    payload = [None] * max_payloads_in_frame
                    max_payload_cnt = -1
            try:
                frame_cnt = pkt[FRAME_CNT_ID][1]    # No need to decode here b/c it's just an equality check
                # XXX In the future, use HEAP_LENOFF to allow missing packets
                #hlen, hoff = unpack(HEAP_LENOFF_FMT, pkt.pop(HEAP_LENOFF_ID, [None,IVAL_NULL])[1])[0]
                cnt, data = pkt.pop(_PAYLOAD_ID)
                max_payload_cnt = max(max_payload_cnt, cnt)
                # Throws IndexError if invalid payload cnt/max_payloads_in_frame combo
                payload[cnt] = data
                frame[DESCRIPTOR_ID] = frame.get(DESCRIPTOR_ID, []) + pkt.get(DESCRIPTOR_ID, [])
                frame.update(pkt)
            except(IndexError):
                logger.warning('RX.iterframes: Invalid payload cnt in packet, tossing frame')
                frame_cnt = -1
        try:
            assert(frame_cnt != -1)
            logger.info('RX.iterframes: Frame completed, attempting to unpack heap')
            # Throws TypeError if a packet is missing
            heap = ''.join(payload[:max_payload_cnt+1])
            descriptors = frame.pop(DESCRIPTOR_ID)
            for i, d in enumerate(descriptors):
                o,length = unpack(IEXT_FMT, d)[0]
                descriptors[i] = heap[o:o+length]
            for id,(is_ext, val) in frame.iteritems():
                if id == DESCRIPTOR_ID: continue
                if is_ext:
                    o,length = unpack(IEXT_FMT, val)[0]
                    # Throws IndexError if data is somehow corrupted:
                    frame[id] = (is_ext, heap[o:o+length])
            frame[DESCRIPTOR_ID] = descriptors
            logger.info('RX.iterframes: Heap successfully unpacked')
            logger.debug(readable_frame(frame, prepend='RX.iterframes:'))
            yield frame
        except(AssertionError,TypeError,IndexError): pass
        logger.info('RX.iterframes: Finished all frames')
        return

