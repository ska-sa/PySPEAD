#!/usr/bin/python

import numpy as np, spead, sys, logging, time
from optparse import OptionParser

logging.basicConfig(level=logging.WARNING)

PORT = 8888
iterations = 10
channels = 512
antennas = 80
baselines = (antennas * (antennas-1))/2

def receive():
    while True:
        t = spead.TransportUDPrx(PORT, pkt_count=1024, buffer_size=5120000)
        ig = spead.ItemGroup()
        print "Initializing new item group and waiting for data..."
        s_time = 0
        total_bytes = 0
        for heap in spead.iterheaps(t):
            if s_time == 0: s_time = time.time()
            h_time = time.time()
            ig.update(heap)
            h_time = time.time() - h_time
            total_bytes += heap.heap_len
            print '\nDecoded heap %i of length %i in %f (%f MBps) seconds.' % (heap.heap_cnt, heap.heap_len, h_time, heap.heap_len/(h_time*1024*1024))
            if heap.heap_len == 0: continue
            print 'Items\n====='
            for name in ig.keys():
                item = ig.get_item(name)
                print 'Name:',name,', Transport Type:',(item.dtype is not None and 'numpy' or 'std'),', Shape:',item.shape
                if name == 'data_timestamp':
                    tt = time.time() - (ig[name][0]/1000.0)
                    print 'Transport time for timestamp %i is %f (%f MBps)' % (ig[name][0],tt,heap.heap_len/(tt*1024*1024))
        s_time = time.time() - s_time
        print 'Received stop. Stream processed %i bytes in %f seconds (%f MBps).' % (total_bytes, s_time, total_bytes/(s_time*1024*1024))
        t.stop()
        if options.profile: break
        time.sleep(2)
         # wait for socket to close before accepting new streams

def transmit_numpy():
    print 'TX: Initializing numpy transport TX to IP',options.ip
    tx = spead.Transmitter(spead.TransportUDPtx(options.ip, 8888))
    ig = spead.ItemGroup()
    ig.add_item(name='data_timestamp', description='Timestamp in epoch ms for the current visibility sample',shape=[1], fmt=spead.mkfmt(('u',64)))
    tvis = np.random.normal(size=(channels,baselines,2)).astype(np.float32)
    ig.add_item(name='vis_data', description='The complex visibility spectrum for a single time dump', init_val=tvis)
     # using init_val with a numpy array will use the numpy transport automatically.
    #ig.add_item(name='vis_data', description='The complex visibility spectrum for a single time dump', ndarray=(np.dtype(np.float32), (channels,baselines,2)))
    #ig['vis_data'] = np.random.normal(size=(channels,baselines,2)).astype(np.float32)
     # you can also specify the array type explicitly via a tuple
    t_heap_send = 0
    for x in range(iterations):
        ig['data_timestamp'] = int(time.time() * 1000)
        t_heap_send = time.time()
        tx.send_heap(ig.get_heap())
        print "Sent data for timestamp",ig['data_timestamp'],"in",time.time()-t_heap_send,"s"
        ig['vis_data'] = np.random.normal(size=(channels,baselines,2)).astype(np.float32)
        time.sleep(0.5)
    tx.end()
    print 'TX: Done.'

def transmit_std():
    print 'TX: Initializing standard transport TX to IP',options.ip
    tx = spead.Transmitter(spead.TransportUDPtx(options.ip, 8888))
    ig = spead.ItemGroup()
    ig.add_item(name='data_timestamp', description='Timestamp in epoch ms for the current visibility sample',shape=[1], fmt=spead.mkfmt(('u',64)))
    ig.add_item(name='vis_data', description='The complex visibility spectrum for a single time dump', shape=[channels,baselines,2], fmt=spead.mkfmt(('u',32)))
     # using init_val with a numpy array will use the numpy transport automatically.
    t_heap_send = 0
    for x in range(iterations):
        ig['data_timestamp'] = int(time.time() * 1000)
        ig['vis_data'] = np.random.normal(size=(channels,baselines,2)).astype(np.float32)
        t_heap_send = time.time()
        tx.send_heap(ig.get_heap())
        print "Sent data for timestamp",ig['data_timestamp'],"in",time.time()-t_heap_send,"s"
        time.sleep(15)
    tx.end()
    print 'TX: Done.'

parser = OptionParser()
parser.add_option("-p", "--profile", dest="profile", action="store_true", default=False, help="Use cProfile.")
parser.add_option("-i", "--ip", type="string", default="127.0.0.1", help="Destination IP address. [default=%default]")
(options, args) = parser.parse_args()

if options.profile:
    try:
        import cProfile
    except Exception, e:
        print "Failed to import cProfile. Profiling unavailable...(",e,")"
        sys.exit()

if sys.argv[-1] == 'tx_numpy': cProfile.run('transmit_numpy()') if options.profile else transmit_numpy()
elif sys.argv[-1] == 'tx_std': cProfile.run('transmit_std()') if options.profile else transmit_std()
elif sys.argv[-1] == 'rx': cProfile.run('receive()') if options.profile else receive()
else: print 'Usage: numpy_test.py [options] rx|tx_numpy|tx_std'
