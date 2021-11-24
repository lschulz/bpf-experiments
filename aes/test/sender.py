#!/usr/bin/python3

import argparse
import socket
import struct
import time


def createMsg(seq):
    mac = 16*b'\x00'
    time = 0
    data = struct.pack("!QQ", seq, seq)
    return struct.pack("!16sII16s", mac, time, seq, data)


def send(ip, port):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            seq = 0
            while True:
                for _ in range(10):
                    sock.sendto(createMsg(seq), (ip, port))
                    seq += 1
                time.sleep(2)
    except KeyboardInterrupt:
        print("Interrupted")


def main():
    parser = argparse.ArgumentParser(description="Send test packets.")
    parser.add_argument("ip", type=str)
    parser.add_argument("port", type=int)
    args = parser.parse_args()
    print("Sending packets to {}:{}".format(args.ip, args.port))
    send(args.ip, args.port)


if __name__ == "__main__":
    main()
