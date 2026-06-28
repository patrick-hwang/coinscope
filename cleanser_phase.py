#!/usr/bin/env python3
"""
CLEANSER PHASE - Step 2 of TxProbe (Sec 4.3)
Run INSIDE WSL - calls Windows bitcoin-cli.exe
"""

import json
import socket
import struct
import subprocess
import sys
import hashlib
from pathlib import Path

# Add connector library
sys.path.append(str(Path(__file__).parent / "libraries" / "python" / "lib"))
from connector import connect_msg, bitcoin_msg, message_types

# Configuration - Windows paths for bitcoin-cli.exe
NODE0_DATADIR = r"C:\Users\Dell\AppData\Local\bitcoin-testnet4-0"
NODE0_WALLET = "mywallet"
NODE0_RPCPORT = 48347
NODE0_RPCUSER = "expuser0"
NODE0_RPCPASS = "strongpassword0"

BITCOIN_CLI = r"C:\Program Files\Bitcoin\daemon\bitcoin-cli.exe"

DATASET_FILE = "../dataset/extend_groundtruth_network.json"
CONNECTOR_SOCKET = "/tmp/bitcoin_control"

# Testnet4 magic
MAGIC = 0x283F161C

# Fees
CLEANSER_FEE = 1000      # satoshis
SQUATTER_FEE = 1000      # satoshis per squatter


def bitcoin_cli(*args):
    """Run bitcoin-cli command (Windows binary via WSL) and return parsed JSON."""
    # Running inside WSL, call Windows binary directly
    # Use Windows-style paths for the Windows binary
    datadir = r"C:\Users\Dell\AppData\Local\bitcoin-testnet4-0"
    cmd = [
        r"/mnt/c/Program Files/Bitcoin/daemon/bitcoin-cli.exe",
        f"-datadir={datadir}",
        f"-rpcwallet={NODE0_WALLET}",
        f"-rpcport={NODE0_RPCPORT}",
        f"-rpcuser={NODE0_RPCUSER}",
        f"-rpcpassword={NODE0_RPCPASS}",
    ] + list(args)
    print(f"   DEBUG: Running: {' '.join(cmd)}")
    result = subprocess.run(cmd, capture_output=True, text=True)
    print(f"   DEBUG: stdout: '{result.stdout[:200]}'")
    print(f"   DEBUG: stderr: '{result.stderr}'")
    print(f"   DEBUG: returncode: {result.returncode}")
    if result.returncode != 0:
        print(f"   bitcoin-cli error: {result.stderr}")
    result.check_returncode()
    
    # Some commands return plain text (not JSON) - try to parse as JSON, fallback to raw string
    stdout = result.stdout.strip()
    try:
        return json.loads(stdout)
    except json.JSONDecodeError:
        return stdout


def send_to_connector(msg):
    """Send a message to the connector via Unix socket (run in WSL)."""
    serialized = msg.serialize()
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    sock.connect(CONNECTOR_SOCKET)
    sock.sendall(serialized)
    sock.close()


def make_packed_message(command, payload):
    """Construct a Bitcoin P2P packed_message (magic + command + len + checksum + payload)."""
    magic_bytes = struct.pack("<I", MAGIC)
    cmd_bytes = command.ljust(12, '\x00').encode('ascii')[:12]
    length_bytes = struct.pack("<I", len(payload))
    checksum = hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4]
    return magic_bytes + cmd_bytes + length_bytes + checksum + payload


def parse_address(addr_str):
    """Parse host:port from dataset format."""
    if addr_str.startswith('['):
        host, port = addr_str.split(']:')
        host = host[1:]
    else:
        host, port = addr_str.rsplit(':', 1)
    return host, int(port)


def main():
    print("=" * 60)
    print("CLEANSER PHASE - Step 2 of TxProbe (Sec 4.3)")
    print("=" * 60)

    # Load node list
    with open(DATASET_FILE) as f:
        data = json.load(f)

    node_list = list(data["node_list"].keys())
    print(f"Loaded {len(node_list)} nodes from dataset")

    # Connect Node 0 to connector
    print("\n1. Connecting Node 0 to connector...")
    node0_addr = "127.0.0.1"
    node0_port = 48348

    msg = connect_msg(node0_addr, node0_port, '0.0.0.0', 0)
    send_to_connector(msg)
    print(f"   Sent CONNECT for {node0_addr}:{node0_port}")

    # Get UTXOs
    print("\n2. Fetching UTXOs from Node 0...")
    utxos = bitcoin_cli("listunspent")
    if not utxos:
        print("   ERROR: No UTXOs found!")
        return

    print(f"   Found {len(utxos)} UTXOs:")
    for i, u in enumerate(utxos):
        print(f"     {i}: {u['txid'][:16]}... vout={u['vout']} amount={u['amount']} BTC")

    utxo = utxos[0]
    utxo_txid = utxo['txid']
    utxo_vout = utxo['vout']
    utxo_amount = int(utxo['amount'] * 100000000)

    print(f"   Using UTXO 0: {utxo_txid[:16]}... vout={utxo_vout} ({utxo_amount} sats)")

    # Create Cleanser transaction
    print("\n3. Creating Cleanser transaction...")
    cleanser_addr = bitcoin_cli("getnewaddress")
    print(f"   Cleanser output address: {cleanser_addr}")

    cleanser_amount = utxo_amount - CLEANSER_FEE

    raw_cleanser = bitcoin_cli("createrawtransaction",
        f'[{{"txid":"{utxo_txid}","vout":{utxo_vout}}}]',
        f'{{"{cleanser_addr}":{cleanser_amount / 100000000:.8f}}}'
    )

    try:
        signed_cleanser = bitcoin_cli("signrawtransactionwithwallet", raw_cleanser)
    except subprocess.CalledProcessError:
        print("   ERROR: Failed to sign. Is the UTXO in the wallet?")
        return

    cleanser_hex = signed_cleanser['hex']
    cleanser_txid = bitcoin_cli("decoderawtransaction", cleanser_hex)['txid']
    print(f"   Cleanser TXID: {cleanser_txid}")

    # Create 100 Squatter transactions
    print("\n4. Creating 100 Squatter transactions...")
    squatter_hexes = []
    squatter_addrs = []

    for i in range(100):
        addr = bitcoin_cli("getnewaddress")
        squatter_addrs.append(addr)
    print(f"   Generated 100 squatter addresses")

    squatter_amount = (cleanser_amount - SQUATTER_FEE) // 100

    for i, addr in enumerate(squatter_addrs):
        raw_squatter = bitcoin_cli("createrawtransaction",
            f'[{{"txid":"{cleanser_txid}","vout":0}}]',
            f'{{"{addr}":{squatter_amount / 100000000:.8f}}}'
        )

        try:
            signed_squatter = bitcoin_cli("signrawtransactionwithwallet", raw_squatter)
        except subprocess.CalledProcessError:
            print(f"   ERROR: Failed to sign squatter {i}")
            return

        squatter_hexes.append(signed_squatter['hex'])

        if (i + 1) % 20 == 0:
            print(f"   Created {i + 1}/100 squatters...")

    print(f"   All 100 squatters created (each ~{squatter_amount} sats)")

    # Parse all target nodes
    print("\n5. Parsing target nodes...")
    targets = []
    for node_str in node_list:
        host, port = parse_address(node_str)
        targets.append((host, port))
        print(f"   Target: {host}:{port}")

    # Send squatters to all nodes
    print("\n6. Sending 100 squatters to all nodes...")
    for host, port in targets:
        print(f"   Sending to {host}:{port}...")
        for i, sq_hex in enumerate(squatter_hexes):
            tx_bytes = bytes.fromhex(sq_hex)
            # Create packed_message for "tx" command
            packed_msg = make_packed_message("tx", tx_bytes)
            # Wrap in bitcoin_msg (message_type=BITCOIN_PACKED_MESSAGE)
            btc_msg = bitcoin_msg(packed_msg)
            send_to_connector(btc_msg)

            if (i + 1) % 20 == 0:
                print(f"     Sent {i + 1}/100 squatters...")
        print(f"   Done with {host}:{port}")

    # Send cleanser to all nodes
    print("\n7. Sending Cleanser to all nodes...")
    cleanser_bytes = bytes.fromhex(cleanser_hex)
    packed_cleanser = make_packed_message("tx", cleanser_bytes)
    btc_cleanser = bitcoin_msg(packed_cleanser)

    for host, port in targets:
        print(f"   Sending cleanser to {host}:{port}...")
        send_to_connector(btc_cleanser)

    print("\n" + "=" * 60)
    print("CLEANSER PHASE COMPLETE")
    print("=" * 60)
    print(f"Cleanser TXID: {cleanser_txid}")
    print(f"Squatters: 100 transactions double-spending cleanser output")
    print(f"Targets: {len(targets)} nodes")
    print("\nNext: Wait for cleanser to propagate, then proceed to Step 3")
    print("(Create experiment transactions: TxP1, TxP2, TxF, TxM1, TxM2)")


if __name__ == "__main__":
    main()