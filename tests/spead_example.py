import numpy, spead, os, logging

logging.basicConfig(level=logging.DEBUG)

FILENAME = 'junkspeadfile'

def receive():
    print 'RX: Initializing...'
    rx = spead.Receiver(spead.Transport(from_file=open(FILENAME,'r')))
    ig = spead.ItemGroup()
    for frame in rx.iterframes():
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
    print 'TX: Initializing...'
    tx = spead.Transmitter(spead.Transport(from_file=open(FILENAME,'w')))
    ig = spead.ItemGroup()
    ig.add_item(name='Var1', description='Desciption for Var1',
        shape=[], fmt=(('u',16),('u',16),('u',16)), init_val=(1,2,3))
    tx.send_frame(ig.get_frame())
    ig['Var1'] = (4,5,6)
    tx.send_frame(ig.get_frame())
    ig.add_item(name='Var2', description='Desciption for Var2',
        shape=[100,100], fmt=[('u',16)])
    data = numpy.arange(100*100); data.shape = (100,100)
    ig['Var2'] = data
    tx.send_frame(ig.get_frame())
    tx.end()
    print 'TX: Done.'

transmit()
receive()
os.remove(FILENAME)

