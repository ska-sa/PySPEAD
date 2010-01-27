import unittest, spead._spead as _S, spead as S
import socket, time, struct

example_pkt = ''.join([
    S.pack(S.HDR_FMT, S.SPEAD_MAGIC, S.VERSION, 3),
    S.pack(S.ITEM_FMT, 0, S.FRAME_CNT_ID, 3),
    S.pack(S.ITEM_FMT, 1, 0x3333, 0),
    S.pack(S.ITEM_FMT, 0, S.PAYLOAD_LENGTH_ID, 8),
    struct.pack('>d', 3.1415)])

term_pkt = ''.join([
    S.pack(S.HDR_FMT, S.SPEAD_MAGIC, S.VERSION, 2),
    S.pack(S.ITEM_FMT, 0, S.FRAME_CNT_ID, 0),
    S.pack(S.ITEM_FMT, 0, S.STREAM_CTRL_ID, S.STREAM_CTRL_TERM_VAL),])

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
        #cb = CollateBuffer(nant=8,npol=1,nchan=2048,nwin=1)
        #self.bs.set_callback(cb)
        #self.bs.unset_callback()
        self.assertRaises(TypeError, self.bs.set_callback, (None,))
    def test_auto_shutdown(self):
        bs = _S.BufferSocket()
        def callback(s): pass
        bs.set_callback(callback)
        bs.start(PORT)
        for i in range(10):
            loopback(example_pkt, port=PORT)
            time.sleep(.0001)
        del(bs)
        loopback(example_pkt, port=PORT)
    def test_get_packets_in_callback(self):
        def callback(pkt):
            #print pkt, pkt.n_items
            global packet_in_callback
            packet_in_callback = pkt
        self.bs.set_callback(callback)
        self.bs.start(PORT)
        for i in range(2):
            loopback(example_pkt, port=PORT)
            time.sleep(.0001)
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
            time.sleep(.0001)
        loopback(term_pkt, port=PORT)
        time.sleep(.0001)
        self.assertFalse(self.bs.is_running())
        self.bs.unset_callback()
    #def test_cb_callback(self):
    #    cb1 = CollateBuffer(nant=NANT,npol=1,nchan=2048,nwin=1)
    #    cb2 = CollateBuffer(nant=NANT,npol=1,nchan=2048,nwin=1)
    #    def callback(i,j,pol,t,data,flags):
    #        global data_in_readout
    #        data_in_readout = True
    #    cb1.set_callback(callback)
    #    bs = BufferSocket()
    #    bs.set_callback(cb1)
    #    bs.start(PORT)
    #    xengs = [sim.XEngine(nant=NANT,npol=1,nchan=2048,engine_id=x) \
    #        for x in range(NANT)]
    #    xstreams = [x.get_pkt_stream() for x in xengs]
    #    timestamp = None
    #    cnt = 0
    #    while True:
    #        for x in xstreams:
    #            pkt = x.next()
    #            pkt.preverr = cnt
    #            cnt += 1
    #            if timestamp is None: timestamp = pkt.timestamp
    #            if pkt.timestamp > timestamp + 2: break
    #            loopback(pkt.pack(), port=PORT)
    #            cb2.collate_packet(pkt)
    #        time.sleep(.0001)
    #        if pkt.timestamp > timestamp + 2: break
    #    bs.stop()
    #    self.assertTrue(data_in_readout)
    #def test_all_data(self):
    #    cb = CollateBuffer(nant=NANT,npol=1,nchan=2048,nwin=1)
    #    def callback(i,j,pol,t,data,flags):
    #        self.assertTrue(n.all(flags == 0))
    #    cb.set_callback(callback)
    #    bs = BufferSocket()
    #    bs.set_callback(cb)
    #    bs.start(PORT)
    #    xengs = [sim.XEngine(nant=NANT,npol=1,nchan=2048,engine_id=x) \
    #        for x in range(NANT)]
    #    xstreams = [x.get_pkt_stream() for x in xengs]
    #    timestamp = None
    #    while True:
    #        for x in xstreams:
    #            pkt = x.next()
    #            if timestamp is None: timestamp = pkt.timestamp
    #            if pkt.timestamp > timestamp + 2: break
    #            loopback(pkt.pack(), port=PORT)
    #        time.sleep(.0001)
    #        if pkt.timestamp > timestamp + 2: break
    #    bs.stop()

if __name__ == '__main__':
    unittest.main()
