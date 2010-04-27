import numpy, spead, logging, sys, time

logging.basicConfig(level=logging.INFO)
PORT = 8888
SHAPE = (4096,4)

def receive():
    print 'RX: initializing'
    tport = spead.TransportUDPrx(PORT)
    ig = spead.ItemGroup()
    print 'RX: listening'
    pv_t1, pv_tx_time = 0, 0
    for heap in spead.iterheaps(tport):
        t1 = time.time()
        ig.update(heap)
        t2 = time.time()
        t_total = t2 - ig['tx_time'] 
        t_update = t2 - t1
        t_rx_heap = pv_t1 - ig['pv_time']
        print 't_total:', t_total
        print 't_update:', t_update
        print 't_rx_heap (prev):', t_rx_heap
        print 't_tx (prev):', ig['pv_time'] - pv_tx_time
        print '-' * 60
        pv_t1 = t1
        pv_tx_time = ig['tx_time']
    print 'RX: stop'
    
def transmit():
    print 'TX: initializing'
    tx = spead.Transmitter(spead.TransportUDPtx('127.0.0.1', PORT))
    ig = spead.ItemGroup()
    print 'TX start'
    for i in range(100):
        ig.add_item(name='var%d' % i, 
            description='Description for var%d' % i,
            init_val=0)
    ig.add_item(name='tx_time', description='Description', fmt='f\x00\x00\x40')
    ig.add_item(name='pv_time', description='Description', fmt='f\x00\x00\x40')
    ig.add_item(name='data', description='Description for data',
        shape=SHAPE, fmt='i\x00\x00\x20')
    data0 = numpy.zeros(SHAPE)
    data1 = numpy.ones(SHAPE)
    ig['pv_time'] = time.time()
    for i in range(20):
        ig['var%d' % i] = 1
        if i % 2 == 0: ig['data'] = data0
        else: ig['data'] = data1
        ig['tx_time'] = time.time()
        tx.send_heap(ig.get_heap())
        ig['pv_time'] = time.time()
        t_tx = ig['pv_time'] - ig['tx_time']
        print 't_tx:', t_tx
    tx.end()
    print 'TX stop'

if sys.argv[-1] == 'tx': transmit()
elif sys.argv[-1] == 'rx': receive()
else: raise ValueError('Argument must be rx or tx')
