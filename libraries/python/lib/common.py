from datetime import *
import socket
import struct
import re

def inet_ntoa(num):
    return str(num & 0xff) + '.' + str((num >> 8) & 0xff) + '.' + str((num >> 16) & 0xff) + '.' + str((num >> 24) & 0xff)

def inet_aton(ip):
    i = list(map(int, ip.split('.')))
    return (i[3] << 24) | (i[2] << 16) | (i[1] << 8) | i[0]

def inet_ntoa6(bytes16):
    """Convert 16-byte IPv6 address bytes to string"""
    return socket.inet_ntop(socket.AF_INET6, bytes16)

def inet_aton6(ip6):
    """Convert IPv6 string to 16 raw bytes"""
    return socket.inet_pton(socket.AF_INET6, ip6)

def unix2str(tstamp):
    dt = datetime.fromtimestamp(tstamp)
    return dt.isoformat(' ')

# Wire address family constants
ADDR_FAMILY_IPV4 = 4
ADDR_FAMILY_IPV6 = 6
ADDR_FAMILY_ONION = 10

def make_wire_addr(host, port):
    """Create a wire_addr (19 bytes: family(1) + addr(16) + port(2))"""
    buf = bytearray(19)
    try:
        # Try IPv4
        packed = socket.inet_pton(socket.AF_INET, host)
        buf[0] = ADDR_FAMILY_IPV4
        buf[1:5] = packed
    except socket.error:
        try:
            # Try IPv6
            packed = socket.inet_pton(socket.AF_INET6, host)
            buf[0] = ADDR_FAMILY_IPV6
            buf[1:17] = packed
        except socket.error:
            # Assume .onion — hostname sent as extra payload in connect_msg
            buf[0] = ADDR_FAMILY_ONION
    buf[17] = (port >> 8) & 0xFF
    buf[18] = port & 0xFF
    return bytes(buf)

def parse_wire_addr(data):
    """Parse wire_addr bytes back to (host, port). data must be 19 bytes."""
    fam = data[0]
    port = (data[17] << 8) | data[18]
    addr_bytes = data[1:17]
    if fam == ADDR_FAMILY_IPV4:
        host = socket.inet_ntop(socket.AF_INET, addr_bytes[:4])
    elif fam == ADDR_FAMILY_IPV6:
        host = socket.inet_ntop(socket.AF_INET6, addr_bytes[:16])
    elif fam == ADDR_FAMILY_ONION:
        host = addr_bytes[:16].hex() + '.onion'
    else:
        raise ValueError(f"Unknown address family: {fam}")
    return host, port
