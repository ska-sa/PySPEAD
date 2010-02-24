import numpy, spead, os, logging, sys

def receive():
    print 'RX: Initializing...'
    t = spead.TransportFile(sys.stdin)
    ig = spead.ItemGroup()
    for frame in spead.iterframes(t):
        ig.update(frame)
        print 'Got frame:', ig.frame_cnt
        for name in ig.keys():
            print '   ', name
            item = ig.get_item(name)
            print '      Description: ', item.description
            print '           Format: ', item.format
            print '            Shape: ', item.shape
            print '            Value: ', ig[name]
    print 'RX: Done.'

def transmit():
    #print 'TX: Initializing...'
    tx = spead.Transmitter(spead.TransportFile(sys.stdout))
    ig = spead.ItemGroup()
    ig.add_item(name='Var1', description='Description for Var1',
        shape=[], fmt='u\x00\x00\x10u\x00\x00\x10u\x00\x00\x10',
        init_val=(1,2,3))
    tx.send_frame(ig.get_frame())
    ig['Var1'] = (4,5,6)
    tx.send_frame(ig.get_frame())
    ig.add_item(name='Var2', description='Description for Var2',
        shape=[100,100], fmt='u\x00\x00\x10')
    data = numpy.arange(100*100); data.shape = (100,100)
    ig['Var2'] = data
    tx.send_frame(ig.get_frame())
    tx.end()
    #print 'TX: Done.'

if sys.argv[-1] == 'tx': transmit()
elif sys.argv[-1] == 'rx':
    logging.basicConfig(level=logging.INFO)
    receive()
else: raise ValueError('Argument must be rx or tx')

