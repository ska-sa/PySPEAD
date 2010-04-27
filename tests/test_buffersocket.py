import unittest, spead._spead as _S, spead as S
import socket, time, struct

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

def loopback(data, port=8888):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 200000)
    sock.connect(('localhost', port))
    sock.send(data)
    sock.close()

PORT = 8888
packet_in_callback = None
data_in_readout = False

class TestBufferSocket(unittest.TestCase):
    def setUp(self):
        self.bs = _S.BufferSocket()
    def test_start_stop(self):
        for i in range(10):
            self.bs.start(PORT)
            self.bs.stop()
    def test_init(self):
        bs = _S.BufferSocket(pkt_count=10)
        bs = _S.BufferSocket(pkt_count=100)
    def test_set_unset_callback(self):
        def callback(pkt): pass
        self.bs.set_callback(callback)
        self.bs.unset_callback()
        self.assertRaises(TypeError, self.bs.set_callback, (None,))
    def test_auto_shutdown(self):
        bs = _S.BufferSocket()
        def callback(s): pass
        bs.set_callback(callback)
        bs.start(PORT)
        for i in range(100): loopback(example_pkt, port=PORT)
        del(bs)
        for i in range(100): loopback(example_pkt, port=PORT)
    def test_get_packets_in_callback(self):
        def callback(pkt):
            #print pkt, pkt.n_items
            global packet_in_callback
            packet_in_callback = pkt
        self.bs.set_callback(callback)
        self.bs.start(PORT)
        for i in range(2):
            loopback(example_pkt, port=PORT)
        while packet_in_callback is None:
            print 'Waiting for packet in callback...'
            time.sleep(.01)
        self.bs.stop()
        self.bs.unset_callback()
        self.assertEqual(packet_in_callback.n_items, 3)
    def test_is_running(self):
        self.assertFalse(self.bs.is_running())
        self.bs.start(PORT)
        self.assertTrue(self.bs.is_running())
        self.bs.stop()
        self.assertFalse(self.bs.is_running())
    def test_term_shutdown(self):
        def callback(s): pass
        self.bs.set_callback(callback)
        self.bs.start(PORT)
        self.assertTrue(self.bs.is_running())
        for i in range(10):
            loopback(example_pkt, port=PORT)
        loopback(term_pkt, port=PORT)
        while self.bs.is_running():
            print 'Waiting for TERM...'
            time.sleep(.01)
        self.assertFalse(self.bs.is_running())
        self.bs.unset_callback()

if __name__ == '__main__':
    unittest.main()
