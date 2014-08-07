#! /usr/bin/env python

import spead64_48 as S
import struct
import sys

pkt = ''.join([
    S.pack(S.HDR_FMT, ((S.MAGIC, S.VERSION, 3),)),
    S.pack(S.ITEM_FMT, ((0, S.FRAME_CNT_ID, 3),)),
    S.pack(S.ITEM_FMT, ((1, 0x3333, 0),)),
    S.pack(S.ITEM_FMT, ((0, S.PAYLOAD_LENGTH_ID, 8),)),
    struct.pack('>1024d', *[3.1415]*1024)])

cmd = sys.argv[-1]
if cmd.startswith('SpeadPacket'):
    if cmd == 'SpeadPacket':
        while True:
            p = S._spead.SpeadPacket()
            p.unpack(pkt)
    elif cmd.split('.')[1] == 'unpack':
        p = S._spead.SpeadPacket()
        while True:
            p.unpack(pkt)
    elif cmd.split('.')[1] == 'pack':
        p = S._spead.SpeadPacket()
        p.unpack(pkt)
        while True:
            s = p.pack()
    elif cmd.split('.')[1] == 'set_items':
        p = S._spead.SpeadPacket()
        i = [(0, 5, 3)] * 20
        while True:
            p.items = i
    elif cmd.split('.')[1] == 'payload':
        pass
    else:
        ValueError(cmd)
elif cmd.startswith('SpeadFrame'):
    if cmd == 'SpeadFrame':
        while True:
            f = S._spead.SpeadFrame()
    elif cmd.split('.')[1] == 'add_packet':
        p = S._spead.SpeadPacket()
        p.unpack(pkt)
        while True:
            f = S._spead.SpeadFrame()
            f.add_packet(p)
    elif cmd.split('.')[1] == 'get_items':
        p = S._spead.SpeadPacket()
        p.unpack(pkt)
        while True:
            f = S._spead.SpeadFrame()
            f.add_packet(p)
            f.finalize()
            i = f.get_items()
    else:
        ValueError(cmd)
elif cmd.startswith('BufferSocket'):
    if cmd == 'BufferSocket':
        while True:
            b = S._spead.BufferSocket(pkt_count=8192)
    elif cmd.split('.')[1] == 'callback':
        b = S._spead.BufferSocket(pkt_count=8192)
        def callback(pkt):
            pass
        b.set_callback(callback)
        b.start(53000)
        tx = S.TransportUDPtx('localhost', 53000)
        while True:
            tx.write(pkt)
elif cmd.startswith('pack'):
    d = [[0]] * 1024*1024
    while True:
        s = S._spead.pack('u\x00\x00\x20', d)
elif cmd.startswith('unpack'):
    s = '\x00' * 1024
    while True:
        d = S._spead.unpack('u\x00\x00\x20', s, cnt=-1)
elif cmd.startswith('ItemGroup'):
    ig1, ig2 = S.ItemGroup(), S.ItemGroup()
    ig1.add_item('var1', fmt='f\x00\x00\x40', shape=-1)
    while True:
        ig1['var1'] = [[0]] * 1024
        s = ''.join([p for p in S.iter_genpackets(ig1.get_frame())])
        tport = S.TransportString(s)
        for f in S.iterframes(tport):
            ig2.update(f)
elif cmd.startswith('iter_genpackets'):
    ig1 = S.ItemGroup()
    ig1.add_item('var1', fmt='f\x00\x00\x40', shape=-1)
    ig1['var1'] = [[0]] * 1024
    f = ig1.get_frame()
    while True:
        s = ''.join([p for p in S.iter_genpackets(f)])
else:
    ValueError(cmd)
