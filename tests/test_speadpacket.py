import unittest, spead as S, spead._spead as _S, bitstring, struct, sys, os

example_pkt = ''.join([
    S.pack(S.HDR_FMT, S.SPEAD_MAGIC, S.VERSION, 3),
    S.pack(S.ITEM_FMT, 0, S.FRAME_CNT_ID, 3),
    S.pack(S.ITEM_FMT, 1, 0x3333, 0),
    S.pack(S.ITEM_FMT, 0, S.PAYLOAD_LENGTH_ID, 8),
    struct.pack('>d', 3.1415)])

class TestSpeadPacket(unittest.TestCase):
    def setUp(self):
        self.pkt = _S.SpeadPacket()
    def test_attributes(self):
        pkt = _S.SpeadPacket()
        self.assertEqual(pkt.n_items, 0)
        self.assertEqual(pkt.frame_cnt, -1)
        self.assertEqual(pkt.get_payload(),'')
        self.assertEqual(pkt.get_items(),())
        pkt.frame_cnt = 5
        self.assertEqual(pkt.frame_cnt, 5)
    def test_unpack_piecewise(self):
        # Read header
        self.assertRaises(ValueError, lambda: self.pkt.unpack_header(''))
        self.assertRaises(ValueError, lambda: self.pkt.unpack_header('abcdefgh'))
        self.assertEqual(self.pkt.unpack_header(example_pkt), 8)
        self.assertEqual(self.pkt.n_items, 3)
        # Read items
        self.assertRaises(ValueError, lambda: self.pkt.unpack_items(''))
        self.assertEqual(self.pkt.unpack_items(example_pkt[8:]), 24)
        self.assertEqual(self.pkt.frame_cnt, 3)
        # Read payload
        self.assertRaises(ValueError, lambda: self.pkt.unpack_payload(''))
        self.assertEqual(self.pkt.unpack_payload(example_pkt[8+24:]), 8)
        self.assertEqual(self.pkt.get_payload(), struct.pack('>d', 3.1415))
    def test_unpack(self):
        self.assertRaises(ValueError, lambda: self.pkt.unpack(''))
        self.assertEqual(self.pkt.unpack(example_pkt), len(example_pkt))
        self.assertEqual(self.pkt.get_payload(), struct.pack('>d', 3.1415))
    def test_get_items(self):
        self.assertEqual(self.pkt.unpack(example_pkt), len(example_pkt))
        self.assertEqual(self.pkt.get_items(), ((0,S.FRAME_CNT_ID,3), (1,0x3333,0), (0,S.PAYLOAD_LENGTH_ID,8)))
    
if __name__ == '__main__':
    unittest.main()
