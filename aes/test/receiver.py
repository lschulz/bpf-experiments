#!/usr/bin/python3

import argparse
import socket
import struct
from cryptography.hazmat.primitives import cmac
from cryptography.hazmat.primitives.ciphers import algorithms


def printMsg(msg, key):
    mac, time, seq, data = struct.unpack("!16sII16s", msg)
    c = cmac.CMAC(algorithms.AES(key))
    c.update(data)
    expected = c.finalize()
    res = "OK" if mac == expected else "ERR"
    print(f"Seq {seq:>4}  0x{mac.hex()}  {time:>4}  0x{data.hex()}  {res}")


def listen(ip, port, key):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.bind((ip, port))
            while True:
                msg, addr = sock.recvfrom(4096)
                printMsg(msg, key)
    except KeyboardInterrupt:
        print("Interrupted")


def parseKey(raw: str) -> bytes:
    key = bytes.fromhex(raw)
    if len(key) != 16:
        raise ValueError("Invalid key size")
    return key


def main():
    parser = argparse.ArgumentParser(description="Listen for IPv4/UDP packets.")
    parser.add_argument("ip", type=str)
    parser.add_argument("port", type=int)
    parser.add_argument("--key", type=parseKey, required=False,
        default=b"\x2b\x7e\x15\x16\x28\xae\xd2\xa6\xab\xf7\x15\x88\x09\xcf\x4f\x3c")
    args = parser.parse_args()
    print(f"Listening on {args.ip}:{args.port}")
    listen(args.ip, args.port, args.key)


if __name__ == "__main__":
    main()
