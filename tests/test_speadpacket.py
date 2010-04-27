import unittest, spead as S, spead._spead as _S, struct, sys, os

ex_pkts = {
    '2-pkt-heap+next-pkt': [
        ''.join([
            S.pack(S.HDR_FMT , ((S.MAGIC, S.VERSION, S.ITEMSIZE, S.ADDRSIZE, 0, 5),)),
            S.pack(S.ITEM_FMT, ((S.IMMEDIATEADDR, S.HEAP_CNT_ID, 3),)),
            S.pack(S.ITEM_FMT, ((S.DIRECTADDR, 0x3333, 0),)),
            S.pack(S.ITEM_FMT, ((S.DIRECTADDR, 0x3334, 16),)),
            S.pack(S.ITEM_FMT, ((S.IMMEDIATEADDR, S.PAYLOAD_OFF_ID, 0),)),
            S.pack(S.ITEM_FMT, ((S.IMMEDIATEADDR, S.PAYLOAD_LEN_ID, 8),)),
            struct.pack('>d', 3.1415)]),
        ''.join([
            S.pack(S.HDR_FMT , ((S.MAGIC, S.VERSION, S.ITEMSIZE, S.ADDRSIZE, 0, 3),)),
            S.pack(S.ITEM_FMT, ((S.IMMEDIATEADDR, S.HEAP_CNT_ID, 3),)),
            S.pack(S.ITEM_FMT, ((S.IMMEDIATEADDR, S.PAYLOAD_OFF_ID, 8),)),
            S.pack(S.ITEM_FMT, ((S.IMMEDIATEADDR, S.PAYLOAD_LEN_ID, 16),)),
            struct.pack('>d', 2.7182),
            struct.pack('>d', 1.4)]),
        ''.join([
            S.pack(S.HDR_FMT , ((S.MAGIC, S.VERSION, S.ITEMSIZE, S.ADDRSIZE, 0, 3),)),
            S.pack(S.ITEM_FMT, ((S.IMMEDIATEADDR, S.HEAP_CNT_ID, 4),)),
            S.pack(S.ITEM_FMT, ((S.DIRECTADDR, 0x3333, 0),)),
            S.pack(S.ITEM_FMT, ((S.IMMEDIATEADDR, S.PAYLOAD_LEN_ID, 8),)),
            struct.pack('>d', 1.57)]),],
    'normal': ''.join([
        S.pack(S.HDR_FMT , ((S.MAGIC, S.VERSION, S.ITEMSIZE, S.ADDRSIZE, 0, 3),)),
        S.pack(S.ITEM_FMT, ((S.IMMEDIATEADDR, S.HEAP_CNT_ID, 3),)),
        S.pack(S.ITEM_FMT, ((S.DIRECTADDR, 0x3333, 0),)),
        S.pack(S.ITEM_FMT, ((S.IMMEDIATEADDR, S.PAYLOAD_LEN_ID, 8),)),
        struct.pack('>d', 3.1415)]),
    '0-len-items-at-back': ''.join([
        S.pack(S.HDR_FMT , ((S.MAGIC, S.VERSION, S.ITEMSIZE, S.ADDRSIZE, 0, 5),)),
        S.pack(S.ITEM_FMT, ((S.IMMEDIATEADDR, S.HEAP_CNT_ID, 3),)),
        S.pack(S.ITEM_FMT, ((S.DIRECTADDR, 0x3333, 0),)),
        S.pack(S.ITEM_FMT, ((S.DIRECTADDR, 0x3334, 8),)),
        S.pack(S.ITEM_FMT, ((S.DIRECTADDR, 0x3335, 8),)),
        S.pack(S.ITEM_FMT, ((S.IMMEDIATEADDR, S.PAYLOAD_LEN_ID, 8),)),
        struct.pack('>d', 3.1415)]),
    '0-len-items-at-front-and-back': ''.join([
        S.pack(S.HDR_FMT , ((S.MAGIC, S.VERSION, S.ITEMSIZE, S.ADDRSIZE, 0, 5),)),
        S.pack(S.ITEM_FMT, ((S.IMMEDIATEADDR, S.HEAP_CNT_ID, 3),)),
        S.pack(S.ITEM_FMT, ((S.DIRECTADDR, 0x3333, 0),)),
        S.pack(S.ITEM_FMT, ((S.DIRECTADDR, 0x3334, 0),)),
        S.pack(S.ITEM_FMT, ((S.DIRECTADDR, 0x3335, 8),)),
        S.pack(S.ITEM_FMT, ((S.IMMEDIATEADDR, S.PAYLOAD_LEN_ID, 8),)),
        struct.pack('>d', 3.1415)]),
    '0-len-items-at-front': ''.join([
        S.pack(S.HDR_FMT , ((S.MAGIC, S.VERSION, S.ITEMSIZE, S.ADDRSIZE, 0, 5),)),
        S.pack(S.ITEM_FMT, ((S.IMMEDIATEADDR, S.HEAP_CNT_ID, 3),)),
        S.pack(S.ITEM_FMT, ((S.DIRECTADDR, 0x3333, 0),)),
        S.pack(S.ITEM_FMT, ((S.DIRECTADDR, 0x3334, 0),)),
        S.pack(S.ITEM_FMT, ((S.DIRECTADDR, 0x3335, 0),)),
        S.pack(S.ITEM_FMT, ((S.IMMEDIATEADDR, S.PAYLOAD_LEN_ID, 8),)),
        struct.pack('>d', 3.1415)]),
}

class TestSpeadMethods(unittest.TestCase):
    def test_unpack_sanity(self):
        self.assertRaises(ValueError, _S.unpack, '', '')
        self.assertRaises(ValueError, _S.unpack, 'abc', 'def')
        self.assertRaises(ValueError, _S.unpack, 'f\x00\x00\xff', 'abcdefgh')
        self.assertRaises(ValueError, _S.unpack, 'f\x00\x00\x20', 'abc')
        self.assertRaises(ValueError, _S.unpack, 'u\x00\x00\x20', '\x00\x00\x00\x00', offset=1)
        self.assertRaises(ValueError, _S.unpack, 'u\x00\x00\x20', '\x00\x00\x00\x00', offset=8)
        self.assertRaises(ValueError, _S.unpack, 'u\x00\x00\x03', '\x00', offset=6)
    def test_unpack_unsigned(self):
        self.assertEqual(_S.unpack('u\x00\x00\x01', '\x80'), ((1,),))
        self.assertEqual(_S.unpack('u\x00\x00\x01', '\x80', offset=1), ((0,),))
        for i in range(2,65):
            fmt = 'u\x00' + struct.pack('>H', i)
            val = '\xc0' + '\x00' * 8
            self.assertEqual(_S.unpack(fmt, val), ((2**(i-1) + 2**(i-2),),))
            self.assertEqual(_S.unpack(fmt, val, offset=1), ((2**(i-1),),))
    def test_unpack_signed(self):
        self.assertEqual(_S.unpack('i\x00\x00\x01', '\x80'), ((-1,),))
        self.assertEqual(_S.unpack('i\x00\x00\x01', '\x80', offset=1), ((0,),))
        for i in range(2,65):
            fmt = 'i\x00' + struct.pack('>H', i)
            val1 = '\xff' * 8
            val2 = '\x40' + '\x00' * 8
            val3 = '\x80' + '\x00' * 7
            self.assertEqual(_S.unpack(fmt, val1), ((-1,),))
            self.assertEqual(_S.unpack(fmt, val2), ((2**(i-2),),))
            self.assertEqual(_S.unpack(fmt, val2, offset=1), _S.unpack(fmt, val3))
    def test_unpack_float(self):
        fmt32 = 'f\x00\x00\x20'
        fmt64 = 'f\x00\x00\x40'
        self.assertAlmostEqual(_S.unpack(fmt32, struct.pack('>f', 3.1415))[0][0], 3.1415, 8)
        self.assertEqual(_S.unpack(fmt64, struct.pack('>d', 3.1415)), ((3.1415,),))
        data1 = '\x01\x23\x45\x67'
        data2 = '\x00\x12\x34\x56\x78'
        self.assertEqual(_S.unpack(fmt32, data1), _S.unpack(fmt32, data2, offset=4))
    def test_unpack_char(self):
        fmt = 'c\x00\x00\x08'
        self.assertEqual(_S.unpack(fmt, '\x67')[0][0], 'g')
        self.assertEqual(_S.unpack(fmt, '\x06\x70', offset=4)[0][0], 'g')
        self.assertEqual(_S.unpack(fmt, 'abcdefgh', cnt=4), (('a',),('b',),('c',),('d',)))
    def test_long_fmt(self):
        fmt = 'c\x00\x00\x08u\x00\x00\x20f\x00\x00\x40'
        data = []
        for i in range(8): data += ['z', i, 3.1]
        data = struct.pack('>'+'cId'*8, *data)
        for i, (c,u,d) in enumerate(_S.unpack(fmt, data)):
            self.assertEqual(c, 'z')
            self.assertEqual(i, u)
            self.assertEqual(d, 3.1)
    def test_pack_sanity(self):
        fmt = 'c\x00\x00\x08'
        self.assertRaises(ValueError, _S.pack, fmt, 1)
        self.assertRaises(ValueError, _S.pack, '', '')
        self.assertRaises(ValueError, _S.pack, 'abc', 'def')
        self.assertRaises(ValueError, _S.pack, fmt, ([1],[2],[3]))
    def test_pack_char(self):
        fmt = 'c\x00\x00\x08'
        self.assertRaises(ValueError, _S.pack, fmt, (('',),('',)))
        self.assertEqual(_S.pack(fmt, (('a',),('b',))), 'ab')
        self.assertEqual(_S.pack(fmt, 'abcd'), 'abcd')
        self.assertEqual(_S.pack(fmt, '\x7f\x80\x7f\x80\x00', offset=7)[1:5], '\xff\x00\xff\x00')
        self.assertEqual(_S.pack(fmt, '\x3f\xc0\x3f\xc0\x00', offset=6)[1:5], '\xff\x00\xff\x00')
        self.assertEqual(_S.pack(fmt, '\x1f\xe0\x1f\xe0\x00', offset=5)[1:5], '\xff\x00\xff\x00')
        self.assertEqual(_S.pack(fmt, '\x0f\xf0\x0f\xf0\x00', offset=4)[1:5], '\xff\x00\xff\x00')
        self.assertEqual(_S.pack(fmt, '\x07\xf8\x07\xf8\x00', offset=3)[1:5], '\xff\x00\xff\x00')
        self.assertEqual(_S.pack(fmt, '\x03\xfc\x03\xfc\x00', offset=2)[1:5], '\xff\x00\xff\x00')
        self.assertEqual(_S.pack(fmt, '\x01\xfe\x01\xfe\x00', offset=1)[1:5], '\xff\x00\xff\x00')
    def test_pack_float(self):
        fmt1 = 'f\x00\x00\x20'
        fmt2 = 'f\x00\x00\x40'
        self.assertEqual(_S.pack(fmt1, ((1.,),(2.,))), struct.pack('>ff', 1., 2.))
        self.assertEqual(_S.pack(fmt2, ((1.,),(2.,))), struct.pack('>dd', 1., 2.))
        self.assertEqual(_S.pack(fmt1, ((1,),(2,))), struct.pack('>ff', 1., 2.))
        self.assertEqual(_S.pack(fmt2, ((1,),(2,))), struct.pack('>dd', 1., 2.))
        self.assertRaises(ValueError, _S.pack, fmt2, (('a',),(2,)))
    def test_pack_unsigned(self):
        self.assertEqual(_S.pack('u\x00\x00\x08', ((1,),(2,),(3,))), '\x01\x02\x03')
        fmt = 'u\x00\x00\x01' * 8
        self.assertEqual(_S.pack(fmt, ((1,0)*4,)), '\xaa')
        v = _S.pack(fmt, ((1,0)*4,), offset=4)
        self.assertEqual(ord(v[0]) & 15, ord('\x0a'))
        self.assertEqual(ord(v[1]) & (15<<4), ord('\xa0'))
        fmt = 'u\x00\x00\x02u\x00\x00\x04u\x00\x00\x0fu\x00\x00\x03'
        self.assertEqual(_S.pack(fmt, ((1,2,3,4),)), '\x48\x00\x1c')
        self.assertEqual(_S.pack(fmt, ((1.,2.,3.,4.),)), '\x48\x00\x1c')
        self.assertRaises(ValueError, _S.pack, 'u\x00\x00\x08', (('a',),(2,)))
        fmt = 'u\x00\x00\x28'
        self.assertEqual(_S.pack(fmt, ((2**32+2**8,),)), '\x01\x00\x00\x01\x00')
    def test_pack_signed(self):
        self.assertEqual(_S.pack('i\x00\x00\x08', ((-1,),(2,),(-3,))), '\xff\x02\xfd')
        fmt = 'i\x00\x00\x02' * 4
        self.assertEqual(_S.pack(fmt, ((1,-1)*2,)), '\x77')
        v = _S.pack(fmt, ((1,-1)*4,), offset=4)
        self.assertEqual(ord(v[0]) & 15, 7)
        self.assertEqual(ord(v[1]) & (15<<4), 7<<4)
        self.assertRaises(ValueError, _S.pack, 'i\x00\x00\x08', (('a',),(2,)))
    def test_pack_mixed(self):
        fmt = 'c\x00\x00\x08u\x00\x00\x18'
        self.assertEqual(_S.pack(fmt, (('c',8),('u',24))), fmt)
        

class TestSpeadPacket(unittest.TestCase):
    def setUp(self):
        self.pkt = _S.SpeadPacket()
    def test_attributes(self):
        pkt = _S.SpeadPacket()
        self.assertEqual(pkt.heap_cnt, S.ERR)
        self.assertEqual(pkt.n_items, 0)
        self.assertFalse(pkt.is_stream_ctrl_term)
        self.assertEqual(pkt.payload_len,0)
        self.assertEqual(pkt.payload_off,0)
        self.assertEqual(pkt.payload,'')
        self.assertEqual(pkt.items,())
        def f1(): pkt.heap_cnt = 5
        self.assertRaises(AttributeError, f1)
        pkt.items = [(S.IMMEDIATEADDR,S.HEAP_CNT_ID, 5), (S.IMMEDIATEADDR,S.PAYLOAD_LEN_ID,8), (S.IMMEDIATEADDR,S.PAYLOAD_OFF_ID,8)]
        pkt.payload = 'abcdefgh'
        self.assertEqual(pkt.n_items, 3)
        self.assertEqual(pkt.heap_cnt, 5)
        self.assertFalse(pkt.is_stream_ctrl_term)
        self.assertEqual(pkt.payload_len,8)
        self.assertEqual(pkt.payload_off,8)
        self.assertEqual(pkt.payload,'abcdefgh')
        self.assertEqual(pkt.items,((S.IMMEDIATEADDR,S.HEAP_CNT_ID,5), (S.IMMEDIATEADDR,S.PAYLOAD_LEN_ID,8), (S.IMMEDIATEADDR,S.PAYLOAD_OFF_ID,8)))
    def test_unpack_piecewise(self):
        # Read header
        p = ex_pkts['normal']
        self.assertRaises(ValueError, lambda: self.pkt.unpack_header(''))
        self.assertRaises(ValueError, lambda: self.pkt.unpack_header('abcdefgh'))
        self.assertEqual(self.pkt.unpack_header(p), 8)
        self.assertEqual(self.pkt.n_items, 3)
        # Read items
        self.assertRaises(ValueError, lambda: self.pkt.unpack_items(''))
        self.assertEqual(self.pkt.unpack_items(p[8:]), 24)
        self.assertEqual(self.pkt.heap_cnt, 3)
        self.assertEqual(self.pkt.payload_len, 8)
        self.assertEqual(self.pkt.items, ((S.IMMEDIATEADDR,S.HEAP_CNT_ID,3),(S.DIRECTADDR,0x3333,0),(S.IMMEDIATEADDR,S.PAYLOAD_LEN_ID,8)))
        # Read payload
        def f1(): self.pkt.payload = ''
        self.assertRaises(ValueError, f1)
        self.pkt.payload = p[8+24:]
        self.assertEqual(self.pkt.payload, struct.pack('>d', 3.1415))
    def test_unpack(self):
        p = ex_pkts['normal']
        self.assertRaises(ValueError, lambda: self.pkt.unpack(''))
        self.assertRaises(ValueError, lambda: self.pkt.unpack('abcdefgh'))
        self.assertEqual(self.pkt.unpack(p), len(p))
        self.assertEqual(self.pkt.payload, struct.pack('>d', 3.1415))
    def test_pack(self):
        p = ex_pkts['normal']
        self.assertEqual(self.pkt.unpack(p), len(p))
        self.assertEqual(self.pkt.pack(), p)
    
class TestSpeadHeap(unittest.TestCase):
    def setUp(self):
        self.pkts = []
        for p in ex_pkts['2-pkt-heap+next-pkt']:
            self.pkts.append(_S.SpeadPacket())
            self.pkts[-1].unpack(p)
    def test_attributes(self):
        heap = _S.SpeadHeap()
        self.assertEqual(heap.heap_cnt, -1)
        self.assertFalse(heap.is_valid)
    def test_add_packet(self):
        heap = _S.SpeadHeap()
        self.assertRaises(TypeError, lambda: heap.add_packet('test'))
        self.assertRaises(ValueError, lambda: heap.add_packet(_S.SpeadPacket()))
        heap.add_packet(self.pkts[0])
        self.assertEqual(heap.heap_cnt, 3)
        heap.add_packet(self.pkts[1])
        self.assertEqual(heap.heap_cnt, 3)
        self.assertRaises(ValueError, lambda: heap.add_packet(self.pkts[2]))
    def test_finalize(self):
        heap = _S.SpeadHeap()
        heap.add_packet(self.pkts[0])
        heap.finalize()
        self.assertFalse(heap.is_valid)
        heap = _S.SpeadHeap()
        heap.add_packet(self.pkts[0])
        heap.add_packet(self.pkts[1])
        heap.finalize()
        self.assertTrue(heap.is_valid)
    def test_get_items(self):
        heap = _S.SpeadHeap()
        self.assertRaises(RuntimeError, heap.get_items)
        heap.add_packet(self.pkts[0])
        heap.finalize()
        items = heap.get_items()
        self.assertEqual(len(items), 1)
        self.assertEqual(items[S.DESCRIPTOR_ID], [])
        heap = _S.SpeadHeap()
        heap.add_packet(self.pkts[0])
        heap.add_packet(self.pkts[1])
        heap.finalize()
        items = heap.get_items()
        self.assertEqual(len(items), 3)
        self.assertEqual(items[S.DESCRIPTOR_ID], [])
        self.assertEqual(items[0x3333], 
            struct.pack('>d', 3.1415) + struct.pack('>d', 2.7182))
        self.assertEqual(items[0x3334], struct.pack('>d', 1.4))
    def test_zero_len_items_at_back(self):
        pkt = _S.SpeadPacket()
        pkt.unpack(ex_pkts['0-len-items-at-back'])
        heap = _S.SpeadHeap()
        heap.add_packet(pkt)
        heap.finalize()
        self.assertTrue(heap.is_valid)
        items = heap.get_items()
        self.assertEqual(len(items), 4)
        self.assertEqual(items[S.DESCRIPTOR_ID], [])
        self.assertEqual(items[0x3333], struct.pack('>d', 3.1415))
        self.assertEqual(items[0x3334], '')
        self.assertEqual(items[0x3335], '')
    def test_zero_len_items_at_front(self):
        pkt = _S.SpeadPacket()
        pkt.unpack(ex_pkts['0-len-items-at-front'])
        heap = _S.SpeadHeap()
        heap.add_packet(pkt)
        heap.finalize()
        self.assertTrue(heap.is_valid)
        items = heap.get_items()
        self.assertEqual(len(items), 4)
        self.assertEqual(items[S.DESCRIPTOR_ID], [])
        self.assertEqual(items[0x3333], '')
        self.assertEqual(items[0x3334], '')
        self.assertEqual(items[0x3335], struct.pack('>d', 3.1415))
    def test_zero_len_items_at_front_and_back(self):
        pkt = _S.SpeadPacket()
        pkt.unpack(ex_pkts['0-len-items-at-front-and-back'])
        heap = _S.SpeadHeap()
        heap.add_packet(pkt)
        heap.finalize()
        self.assertTrue(heap.is_valid)
        items = heap.get_items()
        self.assertEqual(len(items), 4)
        self.assertEqual(items[S.DESCRIPTOR_ID], [])
        self.assertEqual(items[0x3333], '')
        self.assertEqual(items[0x3334], struct.pack('>d', 3.1415))
        self.assertEqual(items[0x3335], '')
    
if __name__ == '__main__':
    unittest.main()
