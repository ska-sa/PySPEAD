import unittest, spead as S, spead._spead as _S, numpy as n
import struct, sys, os, time, socket
#import logging; logging.basicConfig(level=logging.DEBUG)

example_pkt = ''.join([
    S.pack(S.HDR_FMT, ((S.MAGIC, S.VERSION, S.ITEMSIZE, S.ADDRSIZE, 0, 3),)),
    S.pack(S.ITEM_FMT, ((S.IMMEDIATEADDR, S.HEAP_CNT_ID, 3),)),
    S.pack(S.ITEM_FMT, ((S.DIRECTADDR, 0x3333, 0),)),
    S.pack(S.ITEM_FMT, ((S.IMMEDIATEADDR, S.PAYLOAD_LEN_ID, 8),)),
    struct.pack('>d', 3.1415)])

term_pkt = ''.join([
    S.pack(S.HDR_FMT, ((S.MAGIC, S.VERSION, S.ITEMSIZE, S.ADDRSIZE, 0, 2),)),
    S.pack(S.ITEM_FMT, ((S.IMMEDIATEADDR, S.HEAP_CNT_ID, 0),)),
    S.pack(S.ITEM_FMT, ((S.IMMEDIATEADDR, S.STREAM_CTRL_ID, S.STREAM_CTRL_TERM_VAL),)),])

example_heap = {
    S.HEAP_CNT_ID: (S.IMMEDIATEADDR, '\x00\x00\x00\x00\x03'),
    0x3333: (S.DIRECTADDR, struct.pack('>d', 3.1415)),
}

class RawUDPrx:
    def __init__(self, port, rx_buflen=8192):
        self._udp_in = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self._udp_in.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, rx_buflen)
        self._udp_in.bind(('', port))
        self._udp_in.setblocking(True)
    def read(self, recv_len=9200):
        data, self._last_rx_ip = self._udp_in.recvfrom(recv_len)
        return data

class TestMethods(unittest.TestCase):
    def test_calcsize(self):
        self.assertEqual(S.calcsize(S.DEFAULT_FMT), S.ADDRSIZE)
        self.assertEqual(S.calcsize(S.ITEM_FMT), S.ITEMSIZE)
        self.assertEqual(S.calcsize(S.FORMAT_FMT), 32)
    def test_pack(self):
        self.assertEqual(S.pack(S.DEFAULT_FMT, ((2**32+2**8,),)), 
            '\x01\x00\x00\x01\x00')
        self.assertEqual(S.pack(S.ITEM_FMT, ((0, 4, 8),)), 
            '\x00\x00\x04\x00\x00\x00\x00\x08')
        self.assertEqual(S.pack(S.FORMAT_FMT, (('u', 8),)), 'u\x00\x00\x08')
    def test_unpack(self):
        self.assertEqual(S.unpack(S.DEFAULT_FMT,
            '\x01\x00\x00\x01\x00')[0][0], 2**32+2**8)
        self.assertEqual(list(S.unpack(S.ITEM_FMT,
            '\x00\x00\x04\x00\x00\x00\x00\x08')[0]), [0, 4, 8]) 
        self.assertEqual(list(S.unpack(S.FORMAT_FMT, 'u\x00\x00\x08')[0]), ['u', 8]) 
        self.assertEqual(''.join([a[0] for a in S.unpack(S.STR_FMT, 'abcde', cnt=4)]), 'abcd')
        self.assertEqual(''.join([a[0] for a in S.unpack(S.STR_FMT, 'abcde', cnt=-1)]), 'abcde')
    def test_readable_header(self):
        for o in range(8, 32, 8):
            h = example_pkt[o:o+8]
            s = S.readable_header(h)
            self.assertEqual(type(s), str)
            s = S.readable_header(h, prepend='PREFIX:')
            self.assertTrue(s.startswith('PREFIX:'))
    def test_readable_binpacket(self):
        s = S.readable_binpacket(example_pkt)
        self.assertEqual(type(s), str)
        self.assertEqual(len(s.split('\n')), 8)
        s = S.readable_binpacket(example_pkt, prepend='PREFIX:')
        for L in s.split('\n'): self.assertTrue(L.startswith('PREFIX:'))
    def test_readable_speadpacket(self):
        pkt = _S.SpeadPacket()
        pkt.unpack(example_pkt)
        s = S.readable_speadpacket(pkt, prepend='PREFIX:')
        for L in s.split('\n'): self.assertTrue(L.startswith('PREFIX:'))
    def test_readable_heap(self):
        s = S.readable_heap(example_heap)
        self.assertEqual(type(s), str)
        self.assertEqual(len(s.split('\n')), 5)
        s = S.readable_heap(example_heap, prepend='PREFIX:')
        for L in s.split('\n'): self.assertTrue(L.startswith('PREFIX:'))
    def test_iter_genpackets(self):
        heap = {0x1234: (S.DIRECTADDR,'abcdefgh'), S.HEAP_CNT_ID: (S.IMMEDIATEADDR, S.ADDRNULL)}
        pkts = [p for p in S.iter_genpackets(heap)]
        self.assertEqual(len(pkts), 1)
        pkt = pkts[0]
        self.assertEqual(list(S.unpack(S.HDR_FMT, pkt[:8])[0]), 
            [S.MAGIC, S.VERSION, S.ITEMSIZE, S.ADDRSIZE, 0, 5])
        for i in range(1,5):
            rv = S.unpack(S.RAW_ITEM_FMT, pkt[8*i:8*i+8])[0]
            mode, id = rv[:2]
            raw_val = ''.join(rv[2:])
            if id == 0x1234:
                self.assertEqual(mode, S.DIRECTADDR)
                self.assertEqual(S.unpack(S.DEFAULT_FMT, raw_val)[0][0], 0)
            elif id == S.HEAP_CNT_ID:
                self.assertEqual(mode, S.IMMEDIATEADDR)
                self.assertEqual(raw_val, S.ADDRNULL)
            elif id == S.HEAP_LEN_ID:
                self.assertEqual(mode, S.IMMEDIATEADDR)
                self.assertEqual(raw_val, '\x00\x00\x00\x00\x08')
            elif id == S.PAYLOAD_LEN_ID:
                self.assertEqual(mode, S.IMMEDIATEADDR)
                self.assertEqual(S.unpack(S.DEFAULT_FMT, raw_val)[0][0], 8)
            elif id == S.PAYLOAD_OFF_ID:
                self.assertEqual(mode, S.IMMEDIATEADDR)
                self.assertEqual(S.unpack(S.DEFAULT_FMT, raw_val)[0][0], 0)
            else: self.assertTrue(False)
        self.assertEqual(pkt[48:], 'abcdefgh')

        heap[0x1234] = (S.DIRECTADDR, 'abcdefgh' * 4000)
        pkts = [p for p in S.iter_genpackets(heap)]
        self.assertEqual(len(pkts), 4)
        payloads = []
        for cnt, pkt in enumerate(pkts):
            if cnt == 0:
                self.assertEqual(list(S.unpack(S.HDR_FMT, pkt[:8])[0]), 
                    [S.MAGIC, S.VERSION, S.ITEMSIZE, S.ADDRSIZE, 0, 5])
                for i in range(1,5):
                    rv = S.unpack(S.RAW_ITEM_FMT, pkt[8*i:8*i+8])[0]
                    mode, id = rv[:2]
                    raw_val = ''.join(rv[2:])
                    if id == 0x1234:
                        self.assertEqual(mode, S.DIRECTADDR)
                        self.assertEqual(S.unpack(S.DEFAULT_FMT, raw_val)[0][0], 0)
                    elif id == S.HEAP_CNT_ID:
                        self.assertEqual(mode, S.IMMEDIATEADDR)
                        self.assertEqual(raw_val, S.ADDRNULL)
                    elif id == S.HEAP_LEN_ID:
                        self.assertEqual(mode, S.IMMEDIATEADDR)
                        self.assertEqual(raw_val, '\x00\x00\x00\x7d\x00')
                    elif id == S.PAYLOAD_LEN_ID:
                        self.assertEqual(mode, S.IMMEDIATEADDR)
                        self.assertEqual(S.unpack(S.DEFAULT_FMT, raw_val)[0][0], S.MAX_PACKET_LEN - S.ITEMLEN*6)
                    elif id == S.PAYLOAD_OFF_ID:
                        self.assertEqual(mode, S.IMMEDIATEADDR)
                        self.assertEqual(S.unpack(S.DEFAULT_FMT, raw_val)[0][0], 0)
                    else: self.assertTrue(False)
                payloads.append(pkt[6*S.ITEMLEN:])
            else:
                self.assertEqual(list(S.unpack(S.HDR_FMT, pkt[:8])[0]), 
                    [S.MAGIC, S.VERSION, S.ITEMSIZE, S.ADDRSIZE, 0, 4])
                for i in range(1,4):
                    rv = S.unpack(S.RAW_ITEM_FMT, pkt[8*i:8*i+8])[0]
                    mode, id = rv[:2]
                    raw_val = ''.join(rv[2:])
                    if id == S.HEAP_CNT_ID:
                        self.assertEqual(mode, S.IMMEDIATEADDR)
                        self.assertEqual(raw_val, S.ADDRNULL)
                    elif id == S.HEAP_LEN_ID:
                        self.assertEqual(mode, S.IMMEDIATEADDR)
                        self.assertEqual(raw_val, '\x00\x00\x00\x7d\x00')
                    elif id == S.PAYLOAD_LEN_ID:
                        self.assertEqual(mode, S.IMMEDIATEADDR)
                        if cnt < 3: self.assertEqual(S.unpack(S.DEFAULT_FMT, raw_val)[0][0], S.MAX_PACKET_LEN - S.ITEMLEN*5)
                    elif id == S.PAYLOAD_OFF_ID:
                        self.assertEqual(mode, S.IMMEDIATEADDR)
                        self.assertEqual(S.unpack(S.DEFAULT_FMT, raw_val)[0][0], (S.MAX_PACKET_LEN-S.ITEMLEN*5)+(cnt-1)*(S.MAX_PACKET_LEN-S.ITEMLEN*4))
                    else: self.assertTrue(False)
                payloads.append(pkt[5*S.ITEMLEN:])
        heap = ''.join(payloads)
        self.assertEqual(len(heap), len('abcdefgh' * 4000))
        self.assertEqual(heap, 'abcdefgh'*4000)

class TestDescriptor(unittest.TestCase):
    def setUp(self):
        self.d = S.Descriptor(id=33000, name='varname', 
            description='Description')
    def test_attributes(self):
        self.assertEqual(self.d.id, 33000)
        self.assertEqual(self.d.name, 'varname')
        self.assertEqual(self.d.description, 'Description')
        self.assertEqual(self.d.shape, [])
        self.assertEqual(self.d.format, 'u\x00\x00\x28')
        self.assertEqual(self.d.nbits, 40)
        self.assertEqual(self.d.size, 1)
    def test_to_from_descriptor_string(self):
        s = self.d.to_descriptor_string()
        d = S.Descriptor(from_string=s)
        self.assertEqual(d.id, 33000)
        self.assertEqual(d.name, 'varname')
        self.assertEqual(d.description, 'Description')
        self.assertEqual(d.shape, [])
        self.assertEqual(d.format, 'u\x00\x00\x28')
        self.assertEqual(d.nbits, 40)
        self.assertEqual(d.size, 1)

class TestItem(unittest.TestCase):
    def setUp(self):
        self.i32 = S.Item(id=2**15+2**14, name='var', fmt='u\x00\x00\x20')
        self.i40 = S.Item(id=2**15+2**14, name='var')
        self.i64 = S.Item(id=2**15+2**14, name='var', fmt='f\x00\x00\x40')
        #self.u1  = S.Item(id=2**15+2**14, name='var', fmt=[('u',1)], shape=-1)
    def test_get_set_value(self):
        self.i32.set_value(53)
        self.assertEqual(self.i32._value[0][0], 53)
        self.assertEqual(self.i32.get_value(), 53)
        self.i40.set_value(53)
        self.assertEqual(self.i40._value[0][0], 53)
        self.assertEqual(self.i40.get_value(), 53)
        self.i64.set_value(3.1415)
        self.assertEqual(self.i64._value[0][0], 3.1415)
        self.assertEqual(self.i64.get_value(), 3.1415)
        #v = n.array([1, 0, 0, 1, 0, 1, 0, 1], dtype=n.bool)
        #self.u1.set_value(v)
        #self.assertTrue(n.all(self.u1.get_value() == v))
    def test_has_changed(self):
        self.i40._changed = False
        self.assertEqual(self.i40.has_changed(), False)
        self.i40.set_value(77)
        self.assertEqual(self.i40.has_changed(), True)
    def test_unset_changed(self):
        self.i40._changed = True
        self.i40.unset_changed()
        self.assertEqual(self.i40._changed, False)
    def test_to_from_value_string(self):
        self.i32.set_value(5)
        self.assertEqual(self.i32.to_value_string(), '\x00\x00\x00\x05')
        self.i32.from_value_string('\x00'*5)
        self.assertEqual(self.i32.get_value(), 0)
        self.i40.set_value(5)
        self.assertEqual(self.i40.to_value_string(), '\x00\x00\x00\x00\x05')
        self.i40.from_value_string('\x00'*5)
        self.assertEqual(self.i40.get_value(), 0)
        self.i64.set_value(6.28)
        self.assertEqual(self.i64.to_value_string(), '@\x19\x1e\xb8Q\xeb\x85\x1f')
        self.i64.from_value_string('\x00'*8)
        self.assertEqual(self.i64.get_value(), 0)
        #v = n.array([1, 0, 0, 1, 0, 1, 0, 1], dtype=n.bool)
        #self.u1.set_value(v)
        #self.assertEqual(self.u1.to_value_string(), '\x95')
        #self.u1.from_value_string('\xf0')
        #self.assertTrue(n.all(self.u1.get_value() == n.array([1,1,1,1,0,0,0,0], dtype=n.bool)))
        

class TestItemGroup(unittest.TestCase):
    def setUp(self):
        self.ig = S.ItemGroup()
        self.ig.add_item(name='var1')
        self.ig.add_item(name='var2')
        self.ig.add_item(name='var3', id=45678, fmt='f\x00\x00\x40')
        self.id1 = S.UNRESERVED_OPTION
        self.id2 = S.UNRESERVED_OPTION + 1
        self.id3 = 45678
    def test_add_item(self):
        self.assertEqual(self.ig._names['var1'], self.id1)
        self.assertEqual(self.ig._items[self.id1].name, 'var1')
        self.assertEqual(self.ig._names['var2'], self.id2)
        self.assertEqual(self.ig._items[self.id2].name, 'var2')
        self.assertEqual(self.ig._names['var3'], self.id3)
        self.assertEqual(self.ig._items[self.id3].name, 'var3')
    def test_keys(self):
        keys = self.ig.keys()
        self.assertTrue('var1' in keys)
        self.assertTrue('var2' in keys)
        self.assertTrue('var3' in keys)
        self.assertEqual(len(keys), 3)
    def test_getitem(self):
        self.ig._items[self.id1].set_value(1)
        self.ig._items[self.id2].set_value(2)
        self.ig._items[self.id3].set_value(3.14)
        self.assertEqual(self.ig['var1'], 1)
        self.assertEqual(self.ig['var2'], 2)
        self.assertEqual(self.ig['var3'], 3.14)
    def test_setitem(self):
        self.ig['var1'] = 123
        self.ig['var2'] = 456
        self.ig['var3'] = 2.718
        self.assertEqual(self.ig._items[self.id1].get_value(), 123)
        self.assertEqual(self.ig._items[self.id2].get_value(), 456)
        self.assertEqual(self.ig._items[self.id3].get_value(), 2.718)
    def test_get_heap(self):
        self.ig.heap_cnt = 5
        self.ig['var1'] = 1    
        self.ig['var2'] = 2    
        self.ig['var3'] = 3.1415
        heap = self.ig.get_heap()
        # Test that HEAP_CNT is present
        self.assertEqual(heap[S.HEAP_CNT_ID], (S.IMMEDIATEADDR,'\x00\x00\x00\x00\x05'))
        # Test values
        self.assertEqual(heap[self.id1], (S.IMMEDIATEADDR,'\x00\x00\x00\x00\x01'))
        self.assertEqual(heap[self.id2], (S.IMMEDIATEADDR,'\x00\x00\x00\x00\x02'))
        self.assertEqual(heap[self.id3], (S.DIRECTADDR,struct.pack('>d', 3.1415)))
        # Test descriptors
        descriptors = heap[S.DESCRIPTOR_ID]
        self.assertEqual(len(descriptors), 3)
        self.assertTrue(self.ig.get_item('var1').to_descriptor_string() in descriptors)
        self.assertTrue(self.ig.get_item('var2').to_descriptor_string() in descriptors)
        self.assertTrue(self.ig.get_item('var3').to_descriptor_string() in descriptors)
    def test_update(self):
        ig2 = S.ItemGroup()
        ig2.add_item('var1', id=0x3333, fmt='f\x00\x00\x40')
        ig2.add_item('var2', id=0x3334)
        ig2['var1'] = 10
        ig2['var2'] = 10
        heap = _S.SpeadHeap()
        p = _S.SpeadPacket()
        p.unpack(example_pkt)
        heap.add_packet(p)
        heap.finalize()
        #heap = {
        #    S.HEAP_CNT_ID: (S.IMMEDIATEADDR, '\x00\x00\x00\x00\x0f'),
        #    S.DESCRIPTOR_ID: [self.ig.get_item(name).to_descriptor_string() for name in self.ig.keys()],
        #    self.id1: (S.IMMEDIATEADDR, '\x00\x00\x00\x00\x0f'),
        #    self.id2: (S.IMMEDIATEADDR, '\x00\x00\x00\x00\x0f'),
        #    self.id3: (S.DIRECTADDR, struct.pack('>d', 15.15)),
        #}
        ig2.update(heap)
        self.assertEqual(ig2.heap_cnt, 3)
        #self.assertEqual(len(ig2.keys()), 3)
        self.assertEqual(ig2['var1'], 3.1415)
        self.assertEqual(ig2['var2'], 10)
        #self.assertEqual(ig2['var3'], 15.15)

class TestTransportString(unittest.TestCase):
    def setUp(self):
        self.t_str = S.TransportString(example_pkt*5 + 'junk' + example_pkt*5, allow_junk=True)
    def test_iterpackets(self):
        pkts = [pkt for pkt in self.t_str.iterpackets()]
        self.assertEqual(len(pkts), 10)

class TestTransportFile(unittest.TestCase):
    def setUp(self):
        self.filename1 = 'junkspeadtestfile1'
        self.filename2 = 'junkspeadtestfile2'
        open(self.filename1,'w').write(example_pkt*5000 + term_pkt)
        self.t_file1 = S.TransportFile(self.filename1)
        self.t_file2 = S.TransportFile(self.filename2, 'w')
    def test_iterpackets(self):
        pkts = [pkt for pkt in self.t_file1.iterpackets()]
        self.assertEqual(len(pkts), 5000)
    #def test_read(self):
    #    self.assertEqual(self.t_str.read(4), 'abcd')
    #    self.assertEqual(self.t_str.read(4), 'efgh')
    #    self.assertEqual(self.t_file1.read(4), 'abcd')
    #    self.assertEqual(self.t_file1.read(4), 'efgh')
    def test_write(self):
        self.assertRaises(IOError, self.t_file1.write, 'abcd')
        self.t_file2.write('abcd')
    def tearDown(self):
        del(self.t_file1)
        del(self.t_file2)
        try: os.remove(self.filename1)
        except(OSError): pass
        try: os.remove(self.filename2)
        except(OSError): pass

class TestTransportUDPtx(unittest.TestCase):
    def setUp(self):
        self.t_tx = S.TransportUDPtx(ip='127.0.0.1', port=50001)
        self.t_rx = RawUDPrx(port=50001)
    def test_read_write(self):
        self.t_tx.write('abcd')
        self.assertEqual(self.t_rx.read(4), 'abcd')
        def f(): self.t_rx.write('abcd')
        self.assertRaises(AttributeError, f)
        def f(): self.t_tx.read(4)
        self.assertRaises(AttributeError, f)

class TestTransportUDPrx(unittest.TestCase):
    def setUp(self):
        self.t_tx = S.TransportUDPtx(ip='127.0.0.1', port=50000)
    def test_get_packets_term(self):
        t_rx = S.TransportUDPrx(50000)
        self.t_tx.write(example_pkt)
        self.t_tx.write(example_pkt)
        self.assertTrue(t_rx.is_running())
        self.t_tx.write(term_pkt)
        while t_rx.is_running():
            print 'Waiting for TERM in test_get_packets_term'
            time.sleep(.01)
        self.assertFalse(t_rx.is_running())
        self.assertEqual(len(t_rx.pkts), 3)
        pkts = [pkt for pkt in t_rx.iterpackets()]
        self.assertEqual(len(pkts), 3)
        self.assertFalse(t_rx.is_running())

class TestTransmitter(unittest.TestCase):
    def setUp(self):
        self.filename = 'junkspeadtestfile'
        self.tx = S.Transmitter(S.TransportFile(self.filename,'w'))
        self.heap = {
            S.HEAP_CNT_ID: (S.IMMEDIATEADDR, '\x00\x00\x00\x00\x00\x0f'),
            0x123: (S.IMMEDIATEADDR, '\x00\x00\x00\x00\x00\x0f'),
            0x124: (S.IMMEDIATEADDR, '\x00\x00\x00\x00\x00\x0f'),
            0x125: (S.DIRECTADDR, struct.pack('>d', 15.15)),
        }
    def test_send_heap(self):
        self.tx.send_heap(self.heap)
    def test_end(self):
        self.tx.end()
        def f(): self.tx.send_heap(self.heap)
        self.assertRaises(AttributeError, f)
    def tearDown(self):
        del(self.tx)
        try: os.remove(self.filename)
        except(OSError): pass

class Testiterheaps(unittest.TestCase):
    def setUp(self):
        self.filename = 'junkspeadtestfile'
        ig = S.ItemGroup()
        ig.add_item(name='var1'); ig['var1'] = 1
        ig.add_item(name='var2'); ig['var2'] = 2
        tx = S.Transmitter(S.TransportFile(self.filename,'w'))
        heap = ig.get_heap()
        tx.send_heap(heap)
        ig['var2'] = 3
        heap = ig.get_heap()
        tx.send_heap(heap)
        tx.end()
    def tearDown(self):
        try: os.remove(self.filename)
        except(OSError): pass
    def test_iterheaps(self):
        rx_tport = S.TransportFile(self.filename,'r')
        heaps = [f for f in S.iterheaps(rx_tport)]
        self.assertEqual(len(heaps), 2)
        heap = heaps[0]
        ig = S.ItemGroup()
        ig.update(heap)
        self.assertEqual(ig['var1'], 1)
        self.assertEqual(ig['var2'], 2)
    def test_heaplen(self):
        data = open(self.filename).read()
        rx_tport = S.TransportString(data)
        for h in S.iterheaps(rx_tport):
            self.assertFalse(rx_tport.got_term_sig)
        self.assertTrue(rx_tport.got_term_sig)
    
if __name__ == '__main__':
    unittest.main()
