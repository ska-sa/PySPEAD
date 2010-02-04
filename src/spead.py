'''
Data packet:
[ SPEAD #    (24b)     | Ver  (8b) |           # Items (32b) ]
[ Ext (1b) | ID1 (23b) |           Value (40b)               ]
[ Ext (1b) | ID1 (23b) |      Ext  Offset(40b)               ]
...
[ Payload (heap) .............................................
.............................................................]
'''
import socket, bitstring, math, numpy, logging, sys
import _spead, time

logger = logging.getLogger('spead')

#   ____                _              _       
#  / ___|___  _ __  ___| |_ __ _ _ __ | |_ ___ 
# | |   / _ \| '_ \/ __| __/ _` | '_ \| __/ __|
# | |__| (_) | | | \__ \ || (_| | | | | |_\__ \
#  \____\___/|_| |_|___/\__\__,_|_| |_|\__|___/

SPEAD_MAGIC = 0x4b5254
VERSION = 3
MAX_PACKET_SIZE = 9200
MAX_PAYLOADS_IN_FRAME = 4096
UNRESERVED_OPTION = 2**12

FRAME_CNT_ID = 0x01
PAYLOAD_OFFSET_ID = 0x02
PAYLOAD_LENGTH_ID = 0x03
DESCRIPTOR_ID = 0x04
STREAM_CTRL_ID = 0x05
NAME_ID = 0x06
DESCRIPTION_ID = 0x07
SHAPE_ID = 0x08
FORMAT_ID = 0x09
ID_ID = 0x0A

DEFAULT_FMT = (('u',40),)
HDR_FMT = (('u',24),('u',8),('u',32))
RAW_ITEM_FMT = (('u',1),('u',23),('c',40))
ITEM_FMT = (('u',1),('u',23),('u',40))
ID_FMT = (('u',16),('u',24))
SHAPE_FMT = (('u',8),('u',56))
FORMAT_FMT = (('c',8),('u',24))
STR_FMT = (('c',8),)

ITEM = {
    'FRAME_CNT':      {'ID':FRAME_CNT_ID,      'FMT':DEFAULT_FMT,        'CNT':1},
    'PAYLOAD_LEN':    {'ID':PAYLOAD_LENGTH_ID, 'FMT':DEFAULT_FMT,        'CNT':1},
    'PAYLOAD_OFF':    {'ID':PAYLOAD_OFFSET_ID, 'FMT':DEFAULT_FMT,        'CNT':1},
    'DESCRIPTOR':     {'ID':DESCRIPTOR_ID,     'FMT':SPEAD_MAGIC,        'CNT':1},
    'STREAM_CTRL':    {'ID':STREAM_CTRL_ID,    'FMT':DEFAULT_FMT,        'CNT':1},
    'NAME':           {'ID':NAME_ID,           'FMT':STR_FMT,            'CNT':-1},
    'DESCRIPTION':    {'ID':DESCRIPTION_ID,    'FMT':STR_FMT,            'CNT':-1},
    'SHAPE':          {'ID':SHAPE_ID,          'FMT':SHAPE_FMT,          'CNT':-1},
    'FORMAT':         {'ID':FORMAT_ID,         'FMT':FORMAT_FMT,         'CNT':-1},
    'ID':             {'ID':ID_ID,             'FMT':ID_FMT,             'CNT':1},
}

NAME = {}
for name, d in ITEM.iteritems(): NAME[d['ID']] = name

ITEM_BITS = 64
ITEM_BYTES = ITEM_BITS / 8
IVAL_BITS = 40
IVAL_BYTES = IVAL_BITS / 8
IVAL_NULL = '\x00'*IVAL_BYTES
STREAM_CTRL_TERM_VAL = 0x2

DEBUG = False

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

def readable_payload(payload, prepend=''):
    bs = bitstring.BitString(bytes=payload)
    return prepend + bs.hex[2:]

def readable_header(h, prepend=''):
    is_ext, id, raw_val = unpack(RAW_ITEM_FMT, h)[0]
    bs = bitstring.BitString(bytes=raw_val)
    if is_ext: val = 'OFF=%s' % (bs.hex[2:])
    else: val = 'VAL=%s' % (bs.hex[2:])
    try: return prepend+'[ IS_EXT=%d | NAME=%16s | %s ]' % (is_ext, NAME[id], val)
    except(KeyError): return prepend+'[ IS_EXT=%d |   ID=%16x | %s ]' % (is_ext, id, val)

def readable_binpacket(pkt, prepend='', show_payload=False):
    o, rv = 0, ['', 'vvv PACKET ' + 'v'*(50-len(prepend))]
    magic, version, n_options = unpack(HDR_FMT, pkt[o:o+ITEM_BYTES])[0] ; o += ITEM_BYTES
    rv.append(' HEADER:[ SPEAD-CODE=%06x | VERSION=%d | N_OPTIONS=%d ]' % (magic, version, n_options))
    for cnt in range(n_options):
        rv.append(readable_header(pkt[o:o+ITEM_BYTES], prepend='ITEM%02d:' % (cnt)))
        o += ITEM_BYTES
    rv.append('PAYLOAD: BYTES=%d' % (len(pkt[o:])))
    if show_payload: rv.append('PAYLOAD: ' + readable_payload(pkt[o:]))
    rv.append('^'*(60-len(prepend)))
    return '\n'.join([prepend+r for r in rv])

def readable_speadpacket(pkt, prepend='', show_payload=False):
    o, rv = 0, ['', 'vvv PACKET ' + 'v'*(50-len(prepend))]
    rv.append('FRAME_CNT=%d' % (pkt.frame_cnt))
    for cnt,(is_ext,id,val) in enumerate(pkt.items):
        if is_ext: val = 'OFF=%s' % (hex(val)[2:])
        else: val = 'VAL=%s' % (hex(val)[2:])
        try: rv.append('ITEM%02d: [ IS_EXT=%d | NAME=%16s | %s ]' % (cnt, is_ext, NAME[id], val))
        except(KeyError): rv.append('ITEM%02d: [ IS_EXT=%d |   ID=%16d | %s ]' % (cnt, is_ext, id, val))
    if show_payload: rv.append('PAYLOAD: ' + readable_payload(pkt.get_payload()))
    rv.append('^'*(60-len(prepend)))
    return '\n'.join([prepend+r for r in rv])

def readable_frame(frame, prepend=''):
    rv = ['', 'vvv FRAME ' + 'v'*(50-len(prepend))]
    for id in frame:
        try:
            name = NAME[id]
            if name == 'DESCRIPTOR':
                for cnt, d in enumerate(frame[id]):
                    rv += readable_binpacket(d, prepend='DESCRIPTOR%d:' % (cnt)).split('\n')
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
        return ''.join([p for p in iter_genpackets(frame)])
    def from_descriptor_string(self, s):
        '''Set the attributes of this descriptor from a string generated by to_descriptor_string().'''
        for frame in iterframes(TransportString(s)):
            items = frame.get_items()
            self.id = unpack(ID_FMT, items[ID_ID])[0][-1]
            shape = unpack(SHAPE_FMT, items[SHAPE_ID], cnt=-1)
            # Check if we have a dynamically sized value
            try:
                if shape[0][0] == 2: self.shape = -1
                else: self.shape = [s[1] for s in shape]
            except(IndexError,TypeError): self.shape = []
            self.format = unpack(FORMAT_FMT, items[FORMAT_ID], cnt=-1)
            self.name = ''.join([f[0] for f in items[NAME_ID]])
            self.description = ''.join([f[0] for f in items[DESCRIPTION_ID]])
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
            if DEBUG: logger.debug('ITEMGROUP.get_frame: Adding descriptor for id=%d (name=%s)' % (item.id, item.name))
            frame[DESCRIPTOR_ID].append(item.to_descriptor_string())
        # Add entries for any items that have changed
        for item in self._items.itervalues():
            if not item.has_changed(): continue
            val = item.to_value_string()
            is_ext = len(val) > IVAL_BYTES or item.size < 0
            if DEBUG: logger.debug('ITEMGROUP.get_frame: Adding entry for id=%d (name=%s)' % (item.id, item.name))
            frame[item.id] = (is_ext, val)
            # Once data is gathered from changed item, mark it as unchanged
            item.unset_changed()
        logger.info('ITEMGROUP.get_frame: Done building frame with FRAME_CNT=%d' % (self.frame_cnt - 1))
        return frame
    def update(self, frame):
        '''Update the state of this ItemGroup using the frame generated by ItemGroup.get_frame().'''
        self.frame_cnt = frame.frame_cnt
        logger.info('ITEMGROUP.update: Updating values from frame with FRAME_CNT=%d' % (self.frame_cnt))
        # Handle any new DESCRIPTORs first
        items = frame.get_items()
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

def iter_genpackets(frame, max_pkt_size=MAX_PACKET_SIZE):
    '''Provided a frame (dictionary of IDs and binary string values),
    iterate over the set of binary SPEAD packets that propagate this data
    to a receiver.  The stream will be broken into packets of the specified maximum size.'''
    assert(frame.has_key(FRAME_CNT_ID))  # Every frame has to have a FRAME_CNT
    descriptors = frame.pop(DESCRIPTOR_ID, [])
    hdr, heap, offset = [], [], 0
    logger.info('itergenpackets: Converting a frame into packets')
    # Add descriptors
    for d in descriptors:
        if DEBUG: logger.debug('itergenpackets: Adding a descriptor to header')
        dlen = len(d)
        hdr.append(pack(ITEM_FMT, 1, DESCRIPTOR_ID, offset))
        heap.append(d); offset += dlen
    # Add other items
    for id,(is_ext,val) in frame.iteritems():
        vlen = len(val)
        if is_ext:
            if DEBUG: logger.debug('itergenpackets: Adding extension item to header, id=%d, len(val)=%d' % (id, len(val)))
            hdr.append(pack(ITEM_FMT, 1, id, offset))
            heap.append(val); offset += vlen
        # Pad out to IVAL_BYTES for bits < IVAL_BITS
        else:
            if DEBUG: logger.debug('itergenpackets: Adding standard item to header, id=%d, len(val)=%d' % (id, len(val)))
            hdr.append(pack(RAW_ITEM_FMT, 0, id, (IVAL_NULL + val)[-IVAL_BYTES:]))
    heap = ''.join(heap)
    heaplen, payload_cnt, offset = len(heap), 0, 0
    while True:
        # The first packet contains all of the header entries for the items that changed
        # Subsequent packets are continuations that increment payload_cnt until all data is sent
        # XXX Need to check that # of changed items fits in MAX_PACKET_SIZE.
        if payload_cnt == 0: h = hdr
        else: h = [pack(RAW_ITEM_FMT, 0, FRAME_CNT_ID, frame[FRAME_CNT_ID][1])]
        h.insert(0, pack(HDR_FMT, SPEAD_MAGIC, VERSION, len(h)+2))
        hdrlen = ITEM_BYTES * (len(h) + 2)
        payload_len = min(MAX_PACKET_SIZE - hdrlen, heaplen - offset)
        h.append(pack(ITEM_FMT, 0, PAYLOAD_LENGTH_ID, payload_len))
        h.append(pack(ITEM_FMT, 0, PAYLOAD_OFFSET_ID, offset))
        h = ''.join(h)
        if DEBUG: logger.debug('itergenpackets: Made packet with hdrlen=%d, payoff=%d, paylen=%d' \
            % (len(h), offset, payload_len))
        yield h + heap[offset:offset+payload_len]
        offset += payload_len ; payload_cnt += 1
        if offset >= heaplen: break
    logger.info('itergenpackets: Done converting a frame into packets')
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
            pkt = _spead.SpeadPacket()
            try:
                self.offset += pkt.unpack(self.data[self.offset:])
                # Check if this pkt has a stream terminator
                if pkt.is_stream_ctrl_term:
                    self.got_term_sig = True    
                    break
                if DEBUG: logger.debug('TRANSPORTSTRING.iterpackets: Yielding packet, offset=%d/%d' % (self.offset, len(self.data)))
                yield pkt
            except(ValueError):
                if self.offset >= len(self.data) - ITEM_BYTES:
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
        ts = TransportString(self.read(MAX_PACKET_SIZE))
        while True:
            for pkt in ts.iterpackets(): yield pkt
            if not ts.got_term_sig:
                if DEBUG: logger.debug('TRANSPORTFILE.iterpackets: Reading more data')
                s = self.read(MAX_PACKET_SIZE)
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

class TransportUDPrx(_spead.BufferSocket):
    def __init__(self, port, pkt_count=128):
        _spead.BufferSocket.__init__(self, pkt_count)
        self.pkts = []
        def callback(pkt): self.pkts.insert(0, pkt)
        self.set_callback(callback)
        self.start(port)
    def iterpackets(self):
        while self.is_running() or len(self.pkts) > 0:
            if len(self.pkts) > 0: yield self.pkts.pop()
            else: time.sleep(.01)
        logger.info('TRANSPORTUDPRX: Stream was shut down')
        return

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
        if DEBUG: logger.debug(readable_frame(frame, prepend='TX.send_frame:'))
        for cnt, p in enumerate(iter_genpackets(frame, max_pkt_size=max_pkt_size)):
            logger.info('TX.send_frame: Sending frame packet %d' % (cnt))
            if DEBUG: logger.debug(readable_binpacket(p, prepend='TX.send_frame,pkt=%d:' % (cnt)))
            self.t.write(p)
    def end(self):
        '''Send a packet signalling the end of this stream.'''
        frame = { FRAME_CNT_ID: (0, '\xff\xff\xff\xff\xff\xff'),
            STREAM_CTRL_ID: (0, pack(DEFAULT_FMT, STREAM_CTRL_TERM_VAL)) }
        logger.info('TX.end: Terminating stream')
        self.send_frame(frame)
        del(self.t) # Prevents any further activity
            
#  ____               _                
# |  _ \ ___  ___ ___(_)_   _____ _ __ 
# | |_) / _ \/ __/ _ \ \ \ / / _ \ '__|
# |  _ <  __/ (_|  __/ |\ V /  __/ |   
# |_| \_\___|\___\___|_| \_/ \___|_|   

def iterframes(tport, max_payloads_in_frame=MAX_PAYLOADS_IN_FRAME):
    '''Iterate over all valid frames received through the Transport tport.iterframes(), assembling frames 
    from contiguous packets from iterpackets() that have the same FRAME_CNT.  Set frame's ID/values 
    from constituent packets, with packets having higher PAYLOAD_CNTs taking precedence.  Assemble frame's
    heap from the _PAYLOAD of each packet, ordered by PAYLOAD_CNT.  Finally, resolve all IDs with
    extension clauses, replacing them with binary strings from the heap.'''
    frame = _spead.SpeadFrame()
    for pkt in tport.iterpackets():
        logger.info('iterframes: Packet with FRAME_CNT=%d' % (pkt.frame_cnt))
        if DEBUG: logger.debug(readable_speadpacket(pkt, show_payload=False, prepend='iterframes:'))
        # Check if we have finished a frame
        try: frame.add_packet(pkt)
        except(ValueError):
            logger.info('iterframes: Frame %d completed, attempting to unpack heap' % frame.frame_cnt)
            frame.finalize()
            logger.info('iterframes: SpeadFrame.is_valid=%d' % frame.is_valid)
            yield frame
            logger.info('iterframes: Starting new frame')
            frame = _spead.SpeadFrame()
            frame.add_packet(pkt)
    logger.info('iterframes: Last packet in stream received, processing final frame.')
    logger.info('iterframes: Frame %d completed, attempting to unpack heap' % frame.frame_cnt)
    frame.finalize()
    logger.info('iterframes: SpeadFrame.is_valid=%d' % frame.is_valid)
    yield frame
    logger.info('iterframes: Finished all frames')
    return

