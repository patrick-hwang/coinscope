from struct import pack,unpack
import socket

from common import *

class commands(object):
    COMMAND_GET_CXN = 1;
    COMMAND_DISCONNECT = 2;
    COMMAND_SEND_MSG = 3;

    str_mapping = {
        1 : 'COMMAND_GET_CXN',
        2 : 'COMMAND_DISCONNECT',
        3 : 'COMMAND_SEND_MSG'
    }

class message_types(object):
    BITCOIN_PACKED_MESSAGE = 1;
    COMMAND = 2;
    REGISTER = 3;
    CONNECT = 4;

    str_mapping = {
        1 : 'BITCOIN_PACKED_MESSAGE',
        2 : 'COMMAND',
        3 : 'REGISTER',
        4 : 'CONNECT',
    }

class targets(object):
    BROADCAST = 0xFFFFFFFF;


class message(object): # Just a generic message
    def __init__(self, message_type, payload):
        self.version = 0;
        self.message_type = message_type
        self.payload = payload

    def serialize(self):
        return pack('>BIB', self.version, len(self.payload), self.message_type) + self.payload

    @staticmethod
    def deserialize(serialization):
        version, length, message_type = unpack('>BIB', serialization[:6]);
        payload = serialization[6:]
        if version != 0 or length != len(payload):
            raise Exception("bad message");
        return message(message_type, payload)

class register_msg(message):
    def __init__(self):
        super(register_msg, self).__init__(message_types.REGISTER, b'');

    @staticmethod
    def deserialize(serialization):
        version, length, message_type = unpack('>BIB', serialization[:6]);
        payload = serialization[6:]
        if version != 0 or length != len(payload) or message_type != message_types.REGISTER:
            raise Exception("bad register");
        return register_msg()

class bitcoin_msg(message):
    def __init__(self, payload):
        super(bitcoin_msg,self).__init__(message_types.BITCOIN_PACKED_MESSAGE, payload)

    @staticmethod
    def deserialize(serialization):
        version, length, message_type = unpack('>BIB', serialization[:6]);
        payload = serialization[6:]
        if version != 0 or length != len(payload) or message_type != message_types.BITCOIN_PACKED_MESSAGE:
            raise Exception("bad bitcoin_msg");
        return bitcoin_msg(payload)

    @property
    def bitcoin_msg(self):
        return self.payload

    @bitcoin_msg.setter
    def bitcoin_msg(self,value):
        self.payload = value;

class connect_msg(message):

    def __init__(self, remote_host, remote_port, local_host, local_port):
        self.payload = make_wire_addr(remote_host, remote_port) + make_wire_addr(local_host, local_port)
        if '.onion' in remote_host:
            host_clean = remote_host.replace('.onion', '')
            self.payload += host_clean.encode('utf-8')
        super(connect_msg, self).__init__(message_types.CONNECT, self.payload)

    @staticmethod
    def deserialize(serialization):
        version, length, message_type = unpack('>BIB', serialization[:6]);
        payload = serialization[6:]
        if version != 0 or length != len(payload) or message_type != message_types.CONNECT:
            raise Exception("bad connect_msg");
        if len(payload) < 38:
            raise Exception("payload too short for connect_msg");
        r_host, r_port = parse_wire_addr(payload[:19])
        l_host, l_port = parse_wire_addr(payload[19:38])
        return connect_msg(r_host, r_port, l_host, l_port)

    @property
    def remote_addr(self):
        r_host, r_port = parse_wire_addr(self.payload[:19])
        return r_host

    @property
    def remote_port(self):
        r_host, r_port = parse_wire_addr(self.payload[:19])
        return r_port

    @property
    def local_addr(self):
        l_host, l_port = parse_wire_addr(self.payload[19:38])
        return l_host

    @property
    def local_port(self):
        l_host, l_port = parse_wire_addr(self.payload[19:38])
        return l_port


class command_msg(message):

    def repack(self):
        if (len(self.targets_) > 0):
            packstr = '>BII{0}I'.format(len(self.targets_));
            tl = list(map(socket.htonl, self.targets_))
            return pack(packstr, self.command_, self.message_id_, len(self.targets_), *tl);
        else:
            return pack('>BII', self.command_, self.message_id_, 0)

    def __init__(self, command, message_id, targets_list=()):
        self.command_ = command
        self.message_id_ = message_id
        self.targets_ = targets_list
        super(command_msg, self).__init__(message_types.COMMAND, self.repack())

    @staticmethod
    def deserialize(serialization):
        version, length, message_type = unpack('>BIB', serialization[:6]);
        payload = serialization[6:]
        if version != 0 or length != len(payload) or message_type != message_types.COMMAND:
            raise Exception("bad command_msg");
        if (len(payload) < 9 or (len(payload) - 9) % 4 != 0):
            raise Exception("bad payload", len(payload))
        ints = (len(payload) - 9) // 4
        targets = ()
        if (ints > 0):
            packstr = '>BII{0}I'.format(ints);
        else:
            packstr = '>BII'
        res = unpack(packstr, payload);
        command = res[0]
        message_id = res[1]
        targets = res[3:]
        if res[2] != len(targets):
            raise Exception("target count and target list mismatch")
        return command_msg(command, message_id, targets)

    @property
    def command(self):
        return self.command_

    @command.setter
    def command(self, value):
        self.command_ = value;
        self.payload = self.repack();

    @property
    def message_id(self):
        return self.message_id_

    @message_id.setter
    def message_id(self,value):
        self.message_id_ = value;
        self.payload = self.repack();

    @property
    def targets(self):
        return self.targets_

    @targets.setter
    def targets(self,value):
        self.targets_ = value;
        self.payload = self.repack();


class connection_info(object):
    def __init__(self, handle_id, remote_host, remote_port, local_host, local_port):
        self.handle_id = handle_id
        self.payload = make_wire_addr(remote_host, remote_port) + make_wire_addr(local_host, local_port)

    @staticmethod
    def deserialize(serialization):
        handle_id = unpack('>I', serialization[:4])[0]
        wire_data = serialization[4:]
        if len(wire_data) < 38:
            raise Exception("connection_info too short")
        r_host, r_port = parse_wire_addr(wire_data[:19])
        l_host, l_port = parse_wire_addr(wire_data[19:38])
        return connection_info(handle_id, r_host, r_port, l_host, l_port)

    @property
    def remote_addr(self):
        return parse_wire_addr(self.payload[:19])[0]

    @property
    def remote_port(self):
        return parse_wire_addr(self.payload[:19])[1]

    @property
    def local_addr(self):
        return parse_wire_addr(self.payload[19:38])[0]

    @property
    def local_port(self):
        return parse_wire_addr(self.payload[19:38])[1]


type_to_obj = {
    message_types.BITCOIN_PACKED_MESSAGE : bitcoin_msg,
    message_types.COMMAND : command_msg,
    message_types.REGISTER : register_msg,
    message_types.CONNECT : connect_msg
}
