import unittest, spead as S, bitstring, struct, sys, os

example_pkt = ''.join([
    S.pack(S.HDR_FMT, S.SPEAD_MAGIC, S.VERSION, 0, 3),
    S.pack(S.ITEM_FMT, 0, S.FRAME_CNT_ID, 3),
    S.pack(S.EXTITEM_FMT, 1, 0x3333, 0, 8),
    S.pack(S.RAW_ITEM_FMT, 0, S.PAYLOAD_CNTLEN_ID,
        S.pack(S.PAYLOAD_CNTLEN_FMT, 0, 8)),
    struct.pack('>d', 3.1415)])

example_frame = {
    S.FRAME_CNT_ID: '\x00\x00\x00\x00\x00\x03',
    0x3333: struct.pack('>d', 3.1415)
}

class TestMethods(unittest.TestCase):
    def test_calcsize(self):
        self.assertEqual(S.calcsize(S.DEFAULT_FMT), 48)
        self.assertEqual(S.calcsize(S.ITEM_FMT), 64)
        self.assertEqual(S.calcsize(S.FORMAT_FMT), 24)
    def test_conv_format(self):
        self.assertEqual(S.conv_format(S.DEFAULT_FMT), 'uint:48')
        self.assertEqual(S.conv_format(S.ITEM_FMT), 'uint:1,uint:15,uint:48')
        self.assertEqual(S.conv_format(S.FORMAT_FMT), 'bytes:1,uint:16')
    def test_pack(self):
        self.assertEqual(S.pack(S.DEFAULT_FMT, 2**40+2**8), 
            '\x01\x00\x00\x00\x01\x00')
        self.assertEqual(S.pack(S.ITEM_FMT, 0, 4, 8), 
            '\x00\x04\x00\x00\x00\x00\x00\x08')
        self.assertEqual(S.pack(S.FORMAT_FMT, 'u', 8), 'u\x00\x08')
    def test_pack_to_bitstring(self):
        self.assertEqual(S.pack_to_bitstring(S.DEFAULT_FMT, 2**40+2**8).bytes, 
            '\x01\x00\x00\x00\x01\x00')
        self.assertEqual(S.pack_to_bitstring(S.ITEM_FMT, 0, 4, 8).bytes, 
            '\x00\x04\x00\x00\x00\x00\x00\x08')
        self.assertEqual(S.pack_to_bitstring(S.FORMAT_FMT, 'u', 8).bytes, 
            'u\x00\x08')
    def test_unpack(self):
        self.assertEqual(S.unpack(S.DEFAULT_FMT,
            '\x01\x00\x00\x00\x01\x00'), [[2**40+2**8]])
        self.assertEqual(S.unpack(S.ITEM_FMT,
            '\x00\x04\x00\x00\x00\x00\x00\x08'), [[0, 4, 8]]) 
        self.assertEqual(S.unpack(S.FORMAT_FMT, 'u\x00\x08'), [['u', 8]]) 
        bs = bitstring.BitString(bytes='\x01\x00\x00\x00\x01\x00')
        self.assertEqual(S.unpack(S.DEFAULT_FMT, bs), [[2**40+2**8]])
        self.assertEqual(S.unpack(S.STR_FMT, 'abcde', cnt=4), [[c] for c in 'abcd'])
        self.assertEqual(S.unpack(S.STR_FMT, 'abcde', cnt=-1), [[c] for c in 'abcde'])
    def test_readable_header(self):
        for o in range(8, 32, 8):
            h = example_pkt[o:o+8]
            s = S.readable_header(h)
            self.assertEqual(type(s), str)
            s = S.readable_header(h, prepend='PREFIX:')
            self.assertTrue(s.startswith('PREFIX:'))
    def test_readable_packet(self):
        s = S.readable_packet(example_pkt)
        self.assertEqual(type(s), str)
        self.assertEqual(len(s.split('\n')), 8)
        s = S.readable_packet(example_pkt, prepend='PREFIX:')
        for L in s.split('\n'): self.assertTrue(L.startswith('PREFIX:'))
    def test_readable_frame(self):
        s = S.readable_frame(example_frame)
        self.assertEqual(type(s), str)
        self.assertEqual(len(s.split('\n')), 5)
        s = S.readable_frame(example_frame, prepend='PREFIX:')
        for L in s.split('\n'): self.assertTrue(L.startswith('PREFIX:'))
    def test_iterpackets(self):
        frame = {0x1234: (1,'abcdefgh'), S.FRAME_CNT_ID: (0, '\x00'*6)}
        pkts = [p for p in S.iterpackets(frame, use_heap_lenoff=False)]
        self.assertEqual(len(pkts), 1)
        pkt = pkts[0]
        self.assertEqual(struct.unpack('>HHHH', pkt[:8]), 
            (S.SPEAD_MAGIC, S.VERSION, 0, 3))
        for i in range(1,4):
            is_ext, id, raw_val = S.unpack(S.RAW_ITEM_FMT, pkt[8*i:8*i+8])[0]
            if id == 0x1234:
                self.assertEqual(is_ext, 1)
                self.assertEqual(S.unpack(S.IEXT_FMT, raw_val)[0], [0, 8])
            elif id == S.FRAME_CNT_ID:
                self.assertEqual(is_ext, 0)
                self.assertEqual(raw_val, '\x00'*6)
            elif id == S.PAYLOAD_CNTLEN_ID:
                self.assertEqual(is_ext, 0)
                self.assertEqual(S.unpack(S.PAYLOAD_CNTLEN_FMT, raw_val)[0], 
                        [0, 8])
            else: self.assertTrue(False)
        self.assertEqual(pkt[32:], 'abcdefgh')

        frame[0x1234] = (1, 'abcdefgh' * 4000)
        pkts = [p for p in S.iterpackets(frame, use_heap_lenoff=True)]
        self.assertEqual(len(pkts), 4)
        payloads = []
        for cnt, pkt in enumerate(pkts):
            if cnt == 0:
                self.assertEqual(struct.unpack('>HHHH', pkt[:8]), 
                    (S.SPEAD_MAGIC, S.VERSION, 0, 4))
                for i in range(1,5):
                    is_ext, id, raw_val = S.unpack(S.RAW_ITEM_FMT, 
                        pkt[8*i:8*i+8])[0]
                    if id == 0x1234:
                        self.assertEqual(is_ext, 1)
                        self.assertEqual(S.unpack(S.IEXT_FMT, raw_val)[0], 
                                [0, 32000])
                    elif id == S.FRAME_CNT_ID:
                        self.assertEqual(is_ext, 0)
                        self.assertEqual(raw_val, '\x00'*6)
                    elif id == S.PAYLOAD_CNTLEN_ID:
                        self.assertEqual(is_ext, 0)
                        self.assertEqual(S.unpack(S.PAYLOAD_CNTLEN_FMT, raw_val)[0], 
                                [0, S.MAX_PACKET_SIZE - 40])
                    elif id == S.HEAP_LENOFF_ID:
                        self.assertEqual(is_ext, 0)
                        self.assertEqual(S.unpack(S.HEAP_LENOFF_FMT, raw_val)[0], 
                                [32000, 0])
                    else: self.assertTrue(False)
                payloads.append(pkt[40:])
            else:
                self.assertEqual(struct.unpack('>HHHH', pkt[:8]), 
                    (S.SPEAD_MAGIC, S.VERSION, 0, 3))
                for i in range(1,4):
                    is_ext, id, raw_val = S.unpack(S.RAW_ITEM_FMT, 
                        pkt[8*i:8*i+8])[0]
                    if id == S.FRAME_CNT_ID:
                        self.assertEqual(is_ext, 0)
                        self.assertEqual(raw_val, '\x00'*6)
                    elif id == S.PAYLOAD_CNTLEN_ID:
                        self.assertEqual(is_ext, 0)
                        if cnt != 3:
                            self.assertEqual(S.unpack(S.PAYLOAD_CNTLEN_FMT, raw_val)[0], 
                                [cnt, S.MAX_PACKET_SIZE - 32])
                    elif id == S.HEAP_LENOFF_ID:
                        self.assertEqual(is_ext, 0)
                        self.assertEqual(S.unpack(S.HEAP_LENOFF_FMT, raw_val)[0], 
                                [32000, (S.MAX_PACKET_SIZE-40)+(cnt-1)*(S.MAX_PACKET_SIZE-32)])
                    else: self.assertTrue(False)
                payloads.append(pkt[32:])
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
        self.assertEqual(self.d.format, (('u',48),))
        self.assertEqual(self.d.nbits, 48)
        self.assertEqual(self.d.size, 1)
    def test_to_from_descriptor_string(self):
        s = self.d.to_descriptor_string()
        d = S.Descriptor(from_string=s)
        self.assertEqual(d.id, 33000)
        self.assertEqual(d.name, 'varname')
        self.assertEqual(d.description, 'Description')
        self.assertEqual(d.shape, [])
        self.assertEqual(d.format, [['u',48]])
        self.assertEqual(d.nbits, 48)
        self.assertEqual(d.size, 1)

class TestItem(unittest.TestCase):
    def setUp(self):
        self.i48 = S.Item(id=2**15+2**14, name='var')
        self.i64 = S.Item(id=2**15+2**14, name='var', fmt=[('f',64)])
    def test_get_set_value(self):
        self.i48.set_value(53)
        self.assertEqual(self.i48._value, 53)
        self.assertEqual(self.i48.get_value(), 53)
        self.i64.set_value(3.1415)
        self.assertEqual(self.i64._value, 3.1415)
        self.assertEqual(self.i64.get_value(), 3.1415)
    def test_has_changed(self):
        self.i48._changed = False
        self.assertEqual(self.i48.has_changed(), False)
        self.i48.set_value(77)
        self.assertEqual(self.i48.has_changed(), True)
    def test_unset_changed(self):
        self.i48._changed = True
        self.i48.unset_changed()
        self.assertEqual(self.i48._changed, False)
    def test_to_from_value_string(self):
        self.i48.set_value(5)
        self.assertEqual(self.i48.to_value_string(), '\x00\x00\x00\x00\x00\x05')
        self.i48.from_value_string('\x00'*6)
        self.assertEqual(self.i48.get_value(), 0)
        self.i64.set_value(6.28)
        self.assertEqual(self.i64.to_value_string(), '@\x19\x1e\xb8Q\xeb\x85\x1f')
        self.i64.from_value_string('\x00'*8)
        self.assertEqual(self.i64.get_value(), 0)

class TestItemGroup(unittest.TestCase):
    def setUp(self):
        self.ig = S.ItemGroup()
        self.ig.add_item(name='var1')
        self.ig.add_item(name='var2')
        self.ig.add_item(name='var3', id=45678, fmt=[('f',64)])
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
    def test_get_frame(self):
        self.ig.frame_cnt = 5
        self.ig['var1'] = 1    
        self.ig['var2'] = 2    
        self.ig['var3'] = 3.1415
        frame = self.ig.get_frame()
        # Test that FRAME_CNT is present
        self.assertEqual(frame[S.FRAME_CNT_ID], (0,'\x00\x00\x00\x00\x00\x05'))
        # Test values
        self.assertEqual(frame[self.id1], (0,'\x00\x00\x00\x00\x00\x01'))
        self.assertEqual(frame[self.id2], (0,'\x00\x00\x00\x00\x00\x02'))
        self.assertEqual(frame[self.id3], (1,struct.pack('>d', 3.1415)))
        # Test descriptors
        descriptors = frame[S.DESCRIPTOR_ID]
        self.assertEqual(len(descriptors), 3)
        self.assertTrue(self.ig.get_item('var1').to_descriptor_string() in descriptors)
        self.assertTrue(self.ig.get_item('var2').to_descriptor_string() in descriptors)
        self.assertTrue(self.ig.get_item('var3').to_descriptor_string() in descriptors)
    def test_update(self):
        ig2 = S.ItemGroup()
        frame = {
            S.FRAME_CNT_ID: (0, '\x00\x00\x00\x00\x00\x0f'),
            S.DESCRIPTOR_ID: [self.ig.get_item(name).to_descriptor_string() for name in self.ig.keys()],
            self.id1: (0, '\x00\x00\x00\x00\x00\x0f'),
            self.id2: (0, '\x00\x00\x00\x00\x00\x0f'),
            self.id3: (1, struct.pack('>d', 15.15)),
        }
        ig2.update(frame)
        self.assertEqual(ig2.frame_cnt, 15)
        self.assertEqual(len(ig2.keys()), 3)
        self.assertEqual(ig2['var1'], 15)
        self.assertEqual(ig2['var2'], 15)
        self.assertEqual(ig2['var3'], 15.15)

class TestTransportStringFile(unittest.TestCase):
    def setUp(self):
        self.t_str = S.TransportString('abcdefgh')
        self.filename1 = 'junkspeadtestfile1'
        self.filename2 = 'junkspeadtestfile2'
        open(self.filename1,'w').write('abcdefgh')
        self.t_file1 = S.TransportFile(self.filename1)
        self.t_file2 = S.TransportFile(self.filename2, 'w')
    def test_read(self):
        self.assertEqual(self.t_str.read(4), 'abcd')
        self.assertEqual(self.t_str.read(4), 'efgh')
        self.assertEqual(self.t_file1.read(4), 'abcd')
        self.assertEqual(self.t_file1.read(4), 'efgh')
    def test_write(self):
        def f(s): self.t_str.write(s)
        self.assertRaises(AttributeError, f, 'abcd')
        self.assertRaises(IOError, self.t_file1.write, 'abcd')
        self.t_file2.write('abcd')
    def tearDown(self):
        del(self.t_file1)
        del(self.t_file2)
        try: os.remove(self.filename1)
        except(OSError): pass
        try: os.remove(self.filename2)
        except(OSError): pass

class TestTransportUDP(unittest.TestCase):
    def setUp(self):
        self.t_tx = S.TransportUDP(tx_ip='127.0.0.1', port=50000, mode='w')
        self.t_rx = S.TransportUDP(port=50000, mode='r')
    def test_read_write(self):
        self.t_tx.write('abcd')
        self.assertEqual(self.t_rx.read(4), 'abcd')
        def f(): self.t_rx.write('abcd')
        self.assertRaises(AttributeError, f)
        def f(): self.t_tx.read(4)
        self.assertRaises(AttributeError, f)

class TestTransmitter(unittest.TestCase):
    def setUp(self):
        self.filename = 'junkspeadtestfile'
        self.tx = S.Transmitter(S.TransportFile(self.filename,'w'))
        self.frame = {
            S.FRAME_CNT_ID: (0, '\x00\x00\x00\x00\x00\x0f'),
            0x123: (0, '\x00\x00\x00\x00\x00\x0f'),
            0x124: (0, '\x00\x00\x00\x00\x00\x0f'),
            0x125: (1, struct.pack('>d', 15.15)),
        }
    def test_send_frame(self):
        self.tx.send_frame(self.frame)
    def test_end(self):
        self.tx.end()
        def f(): self.tx.send_frame(self.frame)
        self.assertRaises(AttributeError, f)
    def tearDown(self):
        del(self.tx)
        try: os.remove(self.filename)
        except(OSError): pass

class TestReceiver(unittest.TestCase):
    def setUp(self):
        self.filename = 'junkspeadtestfile'
        ig = S.ItemGroup()
        ig.add_item(name='var1'); ig['var1'] = 1
        ig.add_item(name='var2'); ig['var2'] = 2
        tx = S.Transmitter(S.TransportFile(self.filename,'w'))
        tx.send_frame(ig.get_frame())
        tx.end()
        self.rx = S.Receiver(S.TransportFile(self.filename,'r'))
    def tearDown(self):
        try: os.remove(self.filename)
        except(OSError): pass
    def test_iterframes(self):
        frames = [f for f in self.rx.iterframes()]
        self.assertEqual(len(frames), 1)
        frame = frames[0]
        ig = S.ItemGroup()
        ig.update(frame)
        self.assertEqual(ig['var1'], 1)
        self.assertEqual(ig['var2'], 2)
    
if __name__ == '__main__':
    unittest.main()
