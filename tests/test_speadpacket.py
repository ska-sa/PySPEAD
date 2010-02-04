import unittest, spead as S, spead._spead as _S, bitstring, struct, sys, os

ex_pkts = {
    '2-pkt-frame+next-pkt': [
        ''.join([
            S.pack(S.HDR_FMT, S.SPEAD_MAGIC, S.VERSION, 5),
            S.pack(S.ITEM_FMT, 0, S.FRAME_CNT_ID, 3),
            S.pack(S.ITEM_FMT, 1, 0x3333, 0),
            S.pack(S.ITEM_FMT, 1, 0x3334, 16),
            S.pack(S.ITEM_FMT, 0, S.PAYLOAD_OFFSET_ID, 0),
            S.pack(S.ITEM_FMT, 0, S.PAYLOAD_LENGTH_ID, 8),
            struct.pack('>d', 3.1415)]),
        ''.join([
            S.pack(S.HDR_FMT, S.SPEAD_MAGIC, S.VERSION, 3),
            S.pack(S.ITEM_FMT, 0, S.FRAME_CNT_ID, 3),
            S.pack(S.ITEM_FMT, 0, S.PAYLOAD_OFFSET_ID, 8),
            S.pack(S.ITEM_FMT, 0, S.PAYLOAD_LENGTH_ID, 16),
            struct.pack('>d', 2.7182),
            struct.pack('>d', 1.4)]),
        ''.join([
            S.pack(S.HDR_FMT, S.SPEAD_MAGIC, S.VERSION, 3),
            S.pack(S.ITEM_FMT, 0, S.FRAME_CNT_ID, 4),
            S.pack(S.ITEM_FMT, 1, 0x3333, 0),
            S.pack(S.ITEM_FMT, 0, S.PAYLOAD_LENGTH_ID, 8),
            struct.pack('>d', 1.57)]),],
    'normal': ''.join([
        S.pack(S.HDR_FMT, S.SPEAD_MAGIC, S.VERSION, 3),
        S.pack(S.ITEM_FMT, 0, S.FRAME_CNT_ID, 3),
        S.pack(S.ITEM_FMT, 1, 0x3333, 0),
        S.pack(S.ITEM_FMT, 0, S.PAYLOAD_LENGTH_ID, 8),
        struct.pack('>d', 3.1415)]),
    '0-len-items-at-back': ''.join([
        S.pack(S.HDR_FMT, S.SPEAD_MAGIC, S.VERSION, 5),
        S.pack(S.ITEM_FMT, 0, S.FRAME_CNT_ID, 3),
        S.pack(S.ITEM_FMT, 1, 0x3333, 0),
        S.pack(S.ITEM_FMT, 1, 0x3334, 8),
        S.pack(S.ITEM_FMT, 1, 0x3335, 8),
        S.pack(S.ITEM_FMT, 0, S.PAYLOAD_LENGTH_ID, 8),
        struct.pack('>d', 3.1415)]),
    '0-len-items-at-front-and-back': ''.join([
        S.pack(S.HDR_FMT, S.SPEAD_MAGIC, S.VERSION, 5),
        S.pack(S.ITEM_FMT, 0, S.FRAME_CNT_ID, 3),
        S.pack(S.ITEM_FMT, 1, 0x3333, 0),
        S.pack(S.ITEM_FMT, 1, 0x3334, 0),
        S.pack(S.ITEM_FMT, 1, 0x3335, 8),
        S.pack(S.ITEM_FMT, 0, S.PAYLOAD_LENGTH_ID, 8),
        struct.pack('>d', 3.1415)]),
    '0-len-items-at-front': ''.join([
        S.pack(S.HDR_FMT, S.SPEAD_MAGIC, S.VERSION, 5),
        S.pack(S.ITEM_FMT, 0, S.FRAME_CNT_ID, 3),
        S.pack(S.ITEM_FMT, 1, 0x3333, 0),
        S.pack(S.ITEM_FMT, 1, 0x3334, 0),
        S.pack(S.ITEM_FMT, 1, 0x3335, 0),
        S.pack(S.ITEM_FMT, 0, S.PAYLOAD_LENGTH_ID, 8),
        struct.pack('>d', 3.1415)]),
}

class TestSpeadPacket(unittest.TestCase):
    def setUp(self):
        self.pkt = _S.SpeadPacket()
    def test_attributes(self):
        pkt = _S.SpeadPacket()
        self.assertEqual(pkt.n_items, 0)
        self.assertEqual(pkt.frame_cnt, -1)
        self.assertFalse(pkt.is_stream_ctrl_term)
        self.assertEqual(pkt.payload_len,0)
        self.assertEqual(pkt.payload_off,0)
        self.assertEqual(pkt.payload,'')
        self.assertEqual(pkt.items,())
        def f1(): pkt.frame_cnt = 5
        self.assertRaises(AttributeError, f1)
        pkt.items = [(0,S.FRAME_CNT_ID, 5), (0,S.PAYLOAD_LENGTH_ID,8), (0,S.PAYLOAD_OFFSET_ID,8)]
        pkt.payload = 'abcdefgh'
        self.assertEqual(pkt.n_items, 3)
        self.assertEqual(pkt.frame_cnt, 5)
        self.assertFalse(pkt.is_stream_ctrl_term)
        self.assertEqual(pkt.payload_len,8)
        self.assertEqual(pkt.payload_off,8)
        self.assertEqual(pkt.payload,'abcdefgh')
        self.assertEqual(pkt.items,((0,S.FRAME_CNT_ID,5), (0,S.PAYLOAD_LENGTH_ID,8), (0,S.PAYLOAD_OFFSET_ID,8)))
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
        self.assertEqual(self.pkt.frame_cnt, 3)
        self.assertEqual(self.pkt.payload_len, 8)
        self.assertEqual(self.pkt.items, ((0,S.FRAME_CNT_ID,3),(1,0x3333,0),(0,S.PAYLOAD_LENGTH_ID,8)))
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
    
class TestSpeadFrame(unittest.TestCase):
    def setUp(self):
        self.pkts = []
        for p in ex_pkts['2-pkt-frame+next-pkt']:
            self.pkts.append(_S.SpeadPacket())
            self.pkts[-1].unpack(p)
    def test_attributes(self):
        frame = _S.SpeadFrame()
        self.assertEqual(frame.frame_cnt, -1)
        self.assertFalse(frame.is_valid)
    def test_add_packet(self):
        frame = _S.SpeadFrame()
        self.assertRaises(TypeError, lambda: frame.add_packet('test'))
        self.assertRaises(ValueError, lambda: frame.add_packet(_S.SpeadPacket()))
        frame.add_packet(self.pkts[0])
        self.assertEqual(frame.frame_cnt, 3)
        frame.add_packet(self.pkts[1])
        self.assertEqual(frame.frame_cnt, 3)
        self.assertRaises(ValueError, lambda: frame.add_packet(self.pkts[2]))
    def test_finalize(self):
        frame = _S.SpeadFrame()
        frame.add_packet(self.pkts[0])
        frame.finalize()
        self.assertFalse(frame.is_valid)
        frame.add_packet(self.pkts[1])
        frame.finalize()
        self.assertTrue(frame.is_valid)
    def test_get_items(self):
        frame = _S.SpeadFrame()
        self.assertRaises(RuntimeError, frame.get_items)
        frame.add_packet(self.pkts[0])
        frame.finalize()
        items = frame.get_items()
        self.assertEqual(len(items), 1)
        self.assertEqual(items[S.DESCRIPTOR_ID], [])
        frame.add_packet(self.pkts[1])
        frame.finalize()
        items = frame.get_items()
        self.assertEqual(len(items), 3)
        self.assertEqual(items[S.DESCRIPTOR_ID], [])
        self.assertEqual(items[0x3333], 
            struct.pack('>d', 3.1415) + struct.pack('>d', 2.7182))
        self.assertEqual(items[0x3334], struct.pack('>d', 1.4))
    def test_zero_len_items_at_back(self):
        pkt = _S.SpeadPacket()
        pkt.unpack(ex_pkts['0-len-items-at-back'])
        frame = _S.SpeadFrame()
        frame.add_packet(pkt)
        frame.finalize()
        self.assertTrue(frame.is_valid)
        items = frame.get_items()
        self.assertEqual(len(items), 4)
        self.assertEqual(items[S.DESCRIPTOR_ID], [])
        self.assertEqual(items[0x3333], struct.pack('>d', 3.1415))
        self.assertEqual(items[0x3334], '')
        self.assertEqual(items[0x3335], '')
    def test_zero_len_items_at_front(self):
        pkt = _S.SpeadPacket()
        pkt.unpack(ex_pkts['0-len-items-at-front'])
        frame = _S.SpeadFrame()
        frame.add_packet(pkt)
        frame.finalize()
        self.assertTrue(frame.is_valid)
        items = frame.get_items()
        self.assertEqual(len(items), 4)
        self.assertEqual(items[S.DESCRIPTOR_ID], [])
        self.assertEqual(items[0x3333], '')
        self.assertEqual(items[0x3334], '')
        self.assertEqual(items[0x3335], struct.pack('>d', 3.1415))
    def test_zero_len_items_at_front_and_back(self):
        pkt = _S.SpeadPacket()
        pkt.unpack(ex_pkts['0-len-items-at-front-and-back'])
        frame = _S.SpeadFrame()
        frame.add_packet(pkt)
        frame.finalize()
        self.assertTrue(frame.is_valid)
        items = frame.get_items()
        self.assertEqual(len(items), 4)
        self.assertEqual(items[S.DESCRIPTOR_ID], [])
        self.assertEqual(items[0x3333], '')
        self.assertEqual(items[0x3334], struct.pack('>d', 3.1415))
        self.assertEqual(items[0x3335], '')
    
if __name__ == '__main__':
    unittest.main()
