import threading
from struct import pack, unpack
import logging
import sys
import time
import socket

logging.basicConfig(stream=sys.stdout)
logger = logging.getLogger("spead")
logger.setLevel(logging.WARNING)

SPEAD_MAGIC = 0x4b52
SPEAD_VERSION = 3
MAX_PAYLOAD_SIZE = 9200

 # std options
INSTRUMENT_TYPE_ID = 0x1
DATA_PAYLOAD_LENGTH_ID = 0x4
DATA_PAYLOAD_OFFSET_ID = 0x5
STREAM_CONTROL_ID = 0xD
METADATA_PACKET_COUNTER_ID = 0xE
OPTION_DESCRIPTOR_ID = 0x30
PAYLOAD_DESCRIPTOR_ID = 0x31

class SpeadOption(object):
    """A spead option object that stores the option and intrepreted value
       of the option. It also stores history of updated options...
    """
    def __init__(self, id, value, descriptor = None, raw_value = None):
        self.id = id
        self.value = value
        self._descriptor = descriptor
        self._history = {time.time(): value}
        self._raw_history = {time.time(): raw_value}

    def _add_raw_value(self, raw_value):
        self._raw_history[time.time()] = raw_value

    def set_descriptor(self, descriptor):
        self._descriptor = descriptor

    def _update_option(id, value):
        """Update the value of this option. Make the new value the current one
        and store an historical record of the value."""
        self._history[time.time()] = value

class SpeadDescriptor(object):
    """A generic spead descriptor."""
    def __init__(self, name, description):
        self.name = name
        self.description = description
        self._unpack_defs = {}
        self._unpack_list = []
        self._count_string = pack("c","0") + pack("q",1)[:-2]
        self._count_reference = None
        self._assigned_id = 0
         # this id gets assigned by the stream that this payload gets added to

    def add_unpack_type(self, name, data_type, bit_length):
        """Add a std type to the payload description of this stream.
        """
        if self._unpack_defs.has_key(name):
            logger.warn("An std unpack type with this name (" + str(name) + ") already exists. Please choose a unique name.")
        else:
            if data_type == '0':
             # this data type is a reference to another type
                if type(bit_length) == SpeadDescriptor:
                    self._unpack_defs[name] = bit_length
                else:
                    logger.error("Data type 0 requires a SpeadDescriptor reference as it's argument")
            else:
                try:
                    self._unpack_defs[name] = pack('c', data_type) + pack('H', bit_length)
                    # seperate packs required otherwise char is padded to 16 bits
                except Exception, err:
                    logger.error("Failed to pack supplied arguments. Data_type should be a single char, bit_length should be a short integer. (" + str(err) + ")")

    def get_compiled_descriptor(self):
        descriptor = ""
        for u in self._unpack_list:
            if type(u) == SpeadDescriptor:
                descriptor += pack('c','0') + pack('H',u._assigned_id)
            else:
                descriptor += u
        descriptor += '\n'
        if type(self._count_reference) == SpeadOption:
            descriptor += pack('c','1') + pack('q',self._count_reference.id)[:-2] + '\n'
        else:
            descriptor += self._count_string + '\n'
        descriptor += self.name + '\n' + self.description + '\0'
        return descriptor

    def referenced_types(self):
        ref = []
        for u in self._unpack_defs.values():
            if type(u) == SpeadDescriptor:
                ref += [u] + u.referenced_types()
        return ref

    def set_count(self, count_type, count):
        """Set a direct count that indicates the consecutive number of types as described in the unpack string
        to unpack in the data stream.
        """
        if count_type == '1':
            if type(count) == SpeadOption:
                self._count_reference = count
                count = 0
            else:
                logger.error("Referenced count argument is required to be a SpeadOption.")
                return
        self._count_string = pack("c",'0') + pack("q",count)[:-2]

    def set_unpack_list(self, unpack):
        """Sets the unpack string for this stream. This consists of a list of named std and reference types.
        Each std type will be inserted into the overall unpack string directly. The referenced type will interrogate the appropriate sub streams in 
        order to find their unpack string."""
        self._unpack_list = []
        for u in unpack:
            if self._unpack_defs.has_key(u):
                self._unpack_list.append(self._unpack_defs[u])
            else:
                logger.error("Unpack type " + str(u) + " has not yet been defined for this payload.")
                break

class SpeadTransport(object):
    """The basic spead transport object.
    This writes data to stdout. Reads return the data that was last printed.
    """
    def __init__(self):
        self._last_data = ""

    def write(self, data):
        print "SPEAD Write (",time.ctime(),",",len(data),"bytes)"
        print repr(data)
        self._last_data = data

    def read(self):
        return self._last_data


class SpeadUDPTransport(object):
    """An IP spead transport.
    """
    def __init__(self, send_ip = None, send_port = None, receive_port = None, recv_buffer_len=512000):
        self._send_ip = send_ip
        self._send_port = send_port
        self._receive_port = receive_port
        self._recv_buffer_len = recv_buffer_len
        if send_ip is not None and send_port is not None:
            self._init_send_socket()
        if receive_port is not None:
            self._init_receive_socket()

    def _init_send_socket(self):
        self._udp_out = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    def _init_receive_socket(self):
        self._udp_in = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            self._udp_in.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, self._recv_buffer_len)
        except:
            logger.error("Failed to set requested receive buffer size of",self._recv_buffer_len,"bytes")
        self._udp_in.bind(('', self._receive_port))
        self._udp_in.setblocking(True)

    def write(self, data):
        self._udp_out.sendto(data, (self._send_ip, self._send_port))

    def read(self, recv_len=9200):
        data, self._last_receive_ip = self._udp_in.recvfrom(recv_len)
        return data

class SpeadStream(object):
    """All spead streams are instances of this object.
    It encapsulates all the meta information required to construct and send the data packets.
    A simple send method allows sending updated data to the stream destination.

    Parameters
    ----------
    transport : SpeadTransport  
        The transport to be used for sending packets
    name : string
        The display name for this stream
    description : string
        A description of the stream and it's purpose
    """
    def __init__(self, transport, name, description):
        self._transport = transport
        self._name = name
        self._description = description
        self._meta_options = {}
        self._data_options = {}
        self._payload_descriptor = None
        self._payload_descriptors_to_send = {}
         # the complete list of payload descriptors that need to be sent as part of the meta data
        self._payload_descriptor_id = 1
         # used to keep track of the assigned id to each sent payload descriptor
        self._option_descriptor_id = 32768
         # user specified options should have values in the upper half of the id range
        self._meta_packets = {}
         # a dictionary containing the various compiled meta packets in wire form
        self._stream_status = -1
         # stream is stopped

    def add_meta_option(self, option):
        """Add a meta option to the stream. These are sent only once in the stream start packet."""
        self._meta_options[option.id] = option

    def add_data_option(self, id, value):
        """Add a data option to the data stream. These options are transmitted as part of the header
        for each data packet. Generally the user will update the value of the option before sending the packet.
        """
        self._data_options[id] = value

    def add_option_descriptor(self, descriptor):
        """Add one or more descriptors for the various options in this stream."""

    def set_payload_descriptor(self, descriptor):
        """Set the single descriptor that describes the data payload of this stream."""
        self._payload_descriptor = descriptor

    def get_header(self, option_count):
        """Generate a wire ready packet header with the desired number of options set."""
        return pack('HHHH',SPEAD_MAGIC,SPEAD_VERSION,0,option_count)

    def build_stop_packet(self):
        """Create the stream stop packet."""
        packet = self.get_header(1)
        packet += pack('HHI',STREAM_CONTROL_ID, 0, 2)
         # status is stop
        self._meta_packets['stop_packet'] = packet

    def build_start_packet(self):
        """The stream start packet the indicates the start of the stream and contains the
        various meta options for the stream."""
        packet = self.get_header(2 + len(self._meta_options))
        packet += pack('HHI',STREAM_CONTROL_ID, 0, 0)
         # stream start
        packet += pack('HHI',METADATA_PACKET_COUNTER_ID, 0, 2)
        for option in self._meta_options.itervalues():
            packet += pack('H',option.id) + pack('q',option.value)[:-2]
             # cheating for now by assuming unsigned long as option value
        self._meta_packets['start_packet'] = packet

    def build_option_meta_packet(self):
        """Build a wire ready option descriptor meta packet."""
        packet = self.get_header(2 + len(self._meta_options))
        packet += pack('HHI',STREAM_CONTROL_ID, 0, 4)
        packet += pack('HHI',METADATA_PACKET_COUNTER_ID, 0, 0)
         # option descriptor is always first meta data packet
        payload = ""
        payload_start = 0
        for option in self._meta_options.itervalues():
            s = option._descriptor.get_compiled_descriptor()
            payload += s
            packet += pack('HHHH',OPTION_DESCRIPTOR_ID, option.id, payload_start, len(s))
            payload_start += len(s)
        packet += payload
        self._meta_packets['option_descriptor'] = packet

    def build_payload_meta_packet(self):
        """Build a wire ready payload descriptor meta packet based on the current settings."""
        packet = self.get_header(2 + len(self._payload_descriptors_to_send))
         # get a  header with the option field set appropriately
        packet += pack('HHI',STREAM_CONTROL_ID, 0, 4)
        packet += pack('HHI',METADATA_PACKET_COUNTER_ID, 0, 1)
         # payload descriptor is always second meta data packet (option descriptor is first)
        payload = ""
        payload_start = 0
        for id,d in self._payload_descriptors_to_send.iteritems():
            s = d.get_compiled_descriptor()
            payload += s
            packet += pack('HHHH',PAYLOAD_DESCRIPTOR_ID, id, payload_start, len(s))
            payload_start += len(s)
        packet += payload
        self._meta_packets['payload_descriptor'] = packet

    def stop_stream(self):
        logger.info("Sending stop packet...")
        self.send_packet(self._meta_packets['stop_packet'])
        self._stream_status = -1

    def start_stream(self):
        logger.info("Sending option descriptors...")
        self.send_packet(self._meta_packets['option_descriptor'])
        logger.info("Sending payload descriptors...")
        self.send_packet(self._meta_packets['payload_descriptor'])
        logger.info("Sending start packet...")
        self.send_packet(self._meta_packets['start_packet'])
        self._stream_status = 0

    def send_packet(self, packet):
        self._transport.write(packet)

    def format_data(self, data):
        pack_str = self.get_agg_pack()
        if pack_str is not None:
            try:
                return pack(pack_str, *data)
            except Exception, err:
                logger.error("Unable to pack the supplied data. (" + str(err) + ")")
        else:
            logger.error("Unable to produce a proper pack string. See the log for other errors.")
        return None

    def get_agg_pack(self):
        agg = None
        if self._payload_descriptor is not None:
            agg = self.calculate_aggregate_pack(self._payload_descriptor)
        else:
            logger.error("No payload descriptor set for this stream.")
        return agg

    def calculate_aggregate_pack(self, descriptor):
        """Based on the current settings work out an aggregate, python compatible unpack string..."""
        (u,c,n,d) = descriptor.get_compiled_descriptor().split('\n')
        count_type = unpack('c',c[:1])[0]
        if count_type == '0': count = unpack('q',c[1:] + "\x00\x00")[0]
        else:
            count_option_id = unpack('q',c[1:] + "\x00\x00")[0]
            try:
                count = self._meta_options[count_option_id].value
            except KeyError:
                logger.error("Payload descriptor references option id " + str(count_option_id) + " in the count field, but this option is not present in this stream.")
                return
        if len(u) % 3 != 0:
            logger.error("Unpack string for descriptor is not a multiple of 24 bits.")
            return
        unpack_string = ""
        for x in range(0,len(u),3):
            unpack_type = unpack('c',u[x:x+3][:1])[0]
            unpack_val = unpack('H',u[x:x+3][1:])[0]
            if unpack_type == '0':
                sd = self._payload_descriptors_to_send[unpack_val]
                unpack_string += self.calculate_aggregate_pack(sd)
            else:
                unpack_string += unpack_type
                 # for the python sending case we assume the specified types are standard width, so we ignore the bit length field
        return unpack_string * count

    def send_data(self, data):
        if self._stream_status != 0:
            logger.error("Stream has not yet been started. Data cannot be sent until the stream has been started...")
            return
        wire = self.format_data(data)
         # prepare data for the wire
        if wire is None:
            logger.error("Cannot format the supplied data for the wire...")
            return
        offset = 0
        while len(wire) > MAX_PAYLOAD_SIZE:
            # handle data greater than a single packet
            packet = self.get_header(3 + len(self._data_options))
            packet += pack('HHI', DATA_PAYLOAD_LENGTH_ID, 0, MAX_PAYLOAD_SIZE)
            packet += pack('HHI', DATA_PAYLOAD_OFFSET_ID, 0, offset)
            packet += pack('HHI', INSTRUMENT_TYPE_ID, 1, self._payload_descriptor._assigned_id)
            packet += wire[:MAX_PAYLOAD_SIZE]
            self.send_packet(packet)
            wire = wire[MAX_PAYLOAD_SIZE:]
            offset += MAX_PAYLOAD_SIZE
         # send remainder 
        packet = self.get_header(3 + len(self._data_options))
        packet += pack('HHI', DATA_PAYLOAD_LENGTH_ID, 0, len(wire))
        packet += pack('HHI', DATA_PAYLOAD_OFFSET_ID, 0, offset)
        packet += pack('HHI', INSTRUMENT_TYPE_ID, 1, self._payload_descriptor._assigned_id)
        packet += wire
        self.send_packet(packet)

    def compile(self):
        """The compile stage checks through all the set options and descriptors for consistency.
        It builds the meta data packets, assigns ID to the descriptors and informs those objects
        that need to knows about descriptor ID's.
        """
        if self._payload_descriptor is not None:
            self._payload_descriptor_id = 1
            self._payload_descriptor._assigned_id = self._payload_descriptor_id
            self._payload_descriptors_to_send[self._payload_descriptor_id] = self._payload_descriptor
            # we need to compile payload descriptor headers for this top level descriptor and it's referenced children
            for child in self._payload_descriptor.referenced_types():
                self._payload_descriptor_id += 1
                child._assigned_id = self._payload_descriptor_id
                self._payload_descriptors_to_send[self._payload_descriptor_id] = child
            self.build_payload_meta_packet()
        else:
            logger.error("No payload descriptor has been set for this stream.")
        self._option_descriptor_id = 32768
        for option in self._meta_options.itervalues():
            option._descriptor._assigned_id = self._option_descriptor_id
            self._option_descriptor_id += 1

    def resend_metadata(self):
        """Force a resend of the various metadata packets used to describe the stream.
        """

    def register_ref_type(self, id, stream):
        """Register the stream supplied against an ID for intepretation of referenced data types.
        """
        self._known_ref_types[id] = stream

    def connect():
        """Get a handle to the socket required for transmission. In this case a UDP transport.
        """

class SpeadReceiver(threading.Thread):
    """ A class to receive and decode SPEAD streams."""
    def __init__(self, transport):
        self._transport = transport
        self.options = {}
        self._options_unpack_str = {}
        self._running = True
        self._payload_descriptors = {}
        self._option_descriptors = {}
        self._options = {}
        self._to_compile = {}
        self._agg_unpack = {}
         # stores the aggregated unpack strings for various payload id types
        threading.Thread.__init__(self)

    def stop(self):
        self._running = False

    def compile_unpack(self, payload_id):
        """Compile the unpack string for the supplied payload ID.
        """
        agg = self.calculate_aggregate_unpack(self._payload_descriptors[payload_id])
        self._agg_unpack[payload_id] = agg

    def calculate_aggregate_unpack(self, descriptor):
        """Based on the current settings work out an aggregate, python compatible unpack string..."""
        (u,c,n,d) = descriptor.get_compiled_descriptor().split('\n')
        count_type = unpack('c',c[:1])[0]
        if count_type == '0': count = unpack('q',c[1:] + "\x00\x00")[0]
        else:
            count_option_id = unpack('q',c[1:] + "\x00\x00")[0]
            try:
                count = self._options[count_option_id].value
                logger.info("Unpack references option " + str(count_option_id) + " which has value " + str(count))
            except KeyError:
                logger.error("Payload descriptor references option id " + str(count_option_id) + " in the count field, but this option is not present in this stream.")
                return
        if len(u) % 3 != 0:
            logger.error("Unpack string for descriptor is not a multiple of 24 bits.")
            return
        unpack_string = ""
        for x in range(0,len(u),3):
            unpack_type = unpack('c',u[x:x+3][:1])[0]
            unpack_val = unpack('H',u[x:x+3][1:])[0]
            if unpack_type == '0':
                sd = self._payload_descriptors[unpack_val]
                unpack_string += self.calculate_aggregate_unpack(sd)
            else:
                unpack_string += unpack_type
                 # for the python sending case we assume the specified types are standard width, so we ignore the bit length field
        return unpack_string * count


    def compile_descriptors(self):
        """Check through the registered descriptors and make sure that the internal links between the various
        descriptors are sane.
        """
        for d in self._to_compile.itervalues():
            for i, ref in enumerate(d._unpack_list):
                if type(ref) == type(0):
                    try:
                        ref_d = self._payload_descriptors[ref]
                        d._unpack_list[i] = ref_d
                        logger.info("Reference to descriptor id " + str(ref_d) + " added.")
                    except KeyError:
                        logger.error("Option has a reference to descriptor id " + str(ref_d) + ", but this does not exist...")
        self._to_compile = {}
         # should check to make sure that compiles that failed do not get removed...

    def decode_descriptor(self, option_id, option_payload, payload):
        """The option is a descriptor and thus needs to be added to the interpretation table.
           This will need the packet data as well as the header...
        """
        (payload_id, index, length) = unpack("3H", option_payload)
        logger.info("Received " + (option_id == PAYLOAD_DESCRIPTOR_ID and "payload" or "option") + " descriptor for id " + str(payload_id) + ". Descriptor string starts at offset " + str(index) + " and has length " + str(length))
        descriptor_parts = payload[index:index+length].split("\n")
        if len(descriptor_parts) == 4:
            d = SpeadDescriptor(descriptor_parts[2],descriptor_parts[3][:-1])
            d._count_string = descriptor_parts[1]
            d._assigned_id = payload_id
            for u in [descriptor_parts[0][n*3:(n+1)*3] for n in range(len(descriptor_parts[0])/3)]:
                utype = unpack('c',u[:1])[0]
                if utype == '0':
                    ref_id = unpack('H',u[1:])[0]
                    d._unpack_list.append(ref_id)
                    self._to_compile[payload_id] = d
                     # for now we simply insert the desired payload ID reference as it may not have been parsed yet.
                     # once the descriptors have been recieved a compile step will turn these references into SpeadDescriptors. 
                else:
                    d._unpack_list.append(u)
            if option_id == PAYLOAD_DESCRIPTOR_ID:
                self._payload_descriptors[payload_id] = d
            else:
                self._option_descriptors[payload_id] = d
            logger.info("Added descriptor for ID " + str(payload_id) + " to receiver.")
        else:
            logger.warn("Descriptor string for id " + str(payload_id) + " is not well formed.")

    def unpack_data(self, unpack_str, data):
        logger.debug("Unpack string is: " + unpack_str)
        logger.debug("Received: " + str(unpack(unpack_str, data)))

    def decode_option(self, option_id, option_payload, payload):
        """Decode and parse the given option.
           Also builds meta tables based on type 4 packets...
           Option decoding may not be available at a given time...
        """
         # if option is a descriptor than decode otherly
        logger.info("Decoding option " + str(option_id) + " with payload " + repr(option_payload))
        if option_id == OPTION_DESCRIPTOR_ID or option_id == PAYLOAD_DESCRIPTOR_ID:
            self.decode_descriptor(option_id, option_payload, payload)
        elif option_id == INSTRUMENT_TYPE_ID:
            instrument_type = unpack('H',option_payload[:2])[0]
            payload_id = unpack('I',option_payload[2:])[0]
            logger.info("Instrument type is " + str(instrument_type) + " with payload id " + str(payload_id))
            # check if we know how to decode this payload id
            if self._payload_descriptors.has_key(payload_id):
                if not self._agg_unpack.has_key(payload_id):
                    self.compile_unpack(payload_id)
                self.unpack_data(self._agg_unpack[payload_id], payload)
            else:
                logger.error("Packet has payload id " + str(payload_id) + ", but this is not a registered type. Maybe the descriptor got lost...")
        elif option_id == STREAM_CONTROL_ID:
            control = unpack('I',option_payload[-4:])[0]
            logger.info("Control packet is of type " + str(control))
            if control == 2:
                self._running = False
                logger.info("Received stop packet. Halting receiver...")
        else:
            if self._options.has_key(option_id):
                self._options[option_id]._add_raw_value(option_payload)
            else:
                 # temporary value for now. Will convert to actual value once option descriptors properly implemented
                temp_value = unpack('q',option_payload + '\x00\x00')[0]
                self._options[option_id] = SpeadOption(option_id, temp_value, raw_value=option_payload)

    def parse_header(self, packet):
        """

        Parameters
        ----------
        packet : string

        Returns
        -------
        header_values : tuple
            A tuple containing (data_type, data_id, timestamp, packets_per_id, packet_id)
        """
        magic = unpack('2c',packet[:2])
        (version, reserved, option_count) = (0,0,0)
        if magic == ('R','K') and len(packet) > 7:
            (version, reserved, option_count) = unpack('3h', packet[2:8])
            logger.info("SPEAD version " + str(version) + " packet with " + str(option_count) + " options received.")
            if option_count > 0:
                req_length = 8 * (option_count + 1)
                if len(packet) >= req_length:
                    for option in [packet[n*8:(n+1)*8] for n in range(1,option_count + 1)]:
                        option_id = unpack('H',option[:2])[0]
                        self.decode_option(option_id, option[2:], packet[req_length:])
                else:
                    logger.error("SPEAD header has invalid length. Received " + str(len(packet)) + " bytes. Required " + str(req_length) + " bytes")
        else:
            logger.error("Header is not valid SPEAD")
        if len(self._to_compile) > 0:
            self.compile_descriptors()
        return (version, reserved, option_count)

    def stats(self):
        print "Data rate (over last 10 packets):",self.data_rate
        print "Packet process time (us - avg for last 10 packets):",self.process_time
        print "Last packet from IP:",self.last_ip
        print "Number of received frames:",self.packet_count
        print "Number of frames in storage:",(self.storage is None and "N/A" or self.storage._frame_count)


    def run(self):
        """Main receiver loop for a SpeadReceiver instance.
        Will handle all data and metadata for a specific socket. In general port number are used to scope the
        namespace of a spead stream. i.e. all the descriptors and meta data packets on a particular socket are presumed to apply
        to all data received on that particular socket. 
        """
        self.packet_count = 0
        d_start = 0
        while self._running:
            if self.packet_count % 10 == 0:
                d_start = time.time()
            packet = self._transport.read()
            if len(packet) < 8:
                logger.error("Invalid short packet received. (no header)")
                continue
            (spead_version, reserved, option_count) = self.parse_header(packet)
            #self.parse_payload(packet)
