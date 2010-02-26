#! /usr/bin/env python

from spead._spead import *
import sys

cmd = sys.argv[-1]
if   cmd.startswith('SpeadPacket'):
    pass
elif cmd.startswith('SpeadFrame'):
    pass
elif cmd.startswith('BufferSocket'):
    pass
elif cmd.startswith('pack'):
    d = [[0]] * 1024*1024
    while True: s = pack('u\x00\x00\x20', d)
elif cmd.startswith('unpack'):
    s = '\x00' * 1024
    while True: d = unpack('u\x00\x00\x20', s, cnt=-1)
else:
    print 'Unrecognized command:', cmd
