import random
import spead
import logging
import time
spead.logger.setLevel(logging.DEBUG)
 # lets be a little verbose

v = []
for x in range(1536): v.append(int(random.random() * x))
 # create a little bit of data to send

transport = spead.SpeadUDPTransport("127.0.0.1",50000,50000)
 # create a back to back localhost UDP transport

freq_count_descriptor = spead.SpeadDescriptor("freq_count","The total number of frequency channels present in any integration.")
freq_count_descriptor.add_unpack_type('uint48','u',48)
freq_count_descriptor.set_unpack_list(['uint48'])
freq_count = spead.SpeadOption(32769, 64, freq_count_descriptor)
 # create a frequency count descriptor and option

baseline_count_descriptor = spead.SpeadDescriptor("baseline_count","The total number of baselines in the data product.")
baseline_count_descriptor.add_unpack_type('uint48','u',48)
baseline_count_descriptor.set_unpack_list(['uint48'])
baseline_count = spead.SpeadOption(32770, 3, baseline_count_descriptor)
 # create a baseline count descriptor and option

complex = spead.SpeadDescriptor("complex","A complex data type that holds two signed 32-bit integers")
complex.add_unpack_type("int32",'i',32)
complex.set_unpack_list(['int32','int32'])
 # create a complex data type

pol = spead.SpeadDescriptor("pol","Holds the four polarisation products for a single baseline")
pol.add_unpack_type('complex','0',complex)
pol.set_unpack_list(['complex'])
pol.set_count('0',4)
 # create a polarisation type

baseline = spead.SpeadDescriptor("baseline","The baselines for a particular frequency channel.")
baseline.add_unpack_type('pol','0',pol)
baseline.set_unpack_list(['pol'])
baseline.set_count('1',baseline_count)
 # create a baseline type

freq = spead.SpeadDescriptor("frequency","A frequency channels for a complete integration.")
freq.add_unpack_type('baseline','0',baseline)
freq.set_unpack_list(['baseline'])
freq.set_count('1',freq_count)
 # create a frequency type

s = spead.SpeadStream(transport,"test","A test spead stream.")
 # create a new spead stream to the specified destination. Giving a name and description.
s.set_payload_descriptor(freq)
 # set the top level data type
s.add_meta_option(freq_count)
s.add_meta_option(baseline_count)
 # add the options that will be sent in the meta packet
 # at least the options referenced in the payload descriptor must be present
s.compile()
 # sorts out inheritence issues and checks for consistency of the payload and option formats

print "Pack / Unpack string:" + s.get_agg_pack()
 # print out the overall pack / unpack string for this stream. Input data must match this format

s.build_payload_meta_packet()
s.build_option_meta_packet()
s.build_start_packet()
s.build_stop_packet()
 # build the various packets. A stream has the following sequence:
 # 1) Meta data packet containig the payload descriptors
 # 2) Meta data packet containing the option descriptors
 # 3) Meta data packet starting the stream (also contains the options)
 # 4 - n-1) Data packets (payload + data options)
 # n) Stop packet

rec = spead.SpeadReceiver(transport)
rec.start()
s.start_stream()
 # send the first three packets
s.send_data(v)
s.send_data(v)
 # send some data
s.stop_stream()
 # all done

time.sleep(1)
 # wait for packets to finish...
raw_input("Hit enter to finish...")
rec.stop()
