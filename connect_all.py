import json
import socket
import sys
import re
import os

sys.path.append('libraries/python/lib')
from connector import connect_msg

def do_send(sock, data):
    written = 0
    while written < len(data):
        rv = sock.send(data[written:])
        if rv > 0:
            written += rv
        if rv < 0:
            raise Exception("Write error")

with open('../dataset/extend_groundtruth_network.json') as f:
    data = json.load(f)

node_list = list(data["node_list"].keys())

sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM, 0)
sock.connect("/tmp/bitcoin_control")

for entry in node_list:
    # Parse host:port formats:
    #   IPv4:     "1.2.3.4:48333"
    #   IPv6:     "[::1]:48333"
    #   .onion:   "xyz.onion:48333"
    m = re.match(r'^\[(.+)\]:(\d+)$', entry)   # IPv6
    if m:
        host, port = m.group(1), int(m.group(2))
    else:
        m = re.match(r'^(.+):(\d+)$', entry)     # IPv4 or .onion
        if m:
            host, port = m.group(1), int(m.group(2))
        else:
            print(f"Skipping unparseable: {entry}")
            continue

    try:
        msg = connect_msg(host, port, '0.0.0.0', 0)
        do_send(sock, msg.serialize())
        print(f"Sent CONNECT for {host}:{port}")
    except Exception as e:
        print(f"Failed {host}:{port} - {e}")

sock.close()
print(f"Done.")
