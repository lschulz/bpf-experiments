#!/usr/bin/python
# Copyright (c) 2022 Lars-Christian Schulz
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

import argparse
import base64

from mac_offload.bridge_header import (BrFlags, BridgeHeader, compute_mac,
                                       make_mac_input)
from scapy.layers.inet import IP, UDP, Ether
from scapy.packet import Raw
from scapy.utils import wrpcap


parser = argparse.ArgumentParser(description="Generate packets containing the SCION bridge header.",
    formatter_class=argparse.ArgumentDefaultsHelpFormatter)
parser.add_argument("key", help="Base64-encoded MAC verification key")
parser.add_argument("output", help="Output pcap file")
parser.add_argument("-n", default=1000, help="Number of packet to generate")
args = parser.parse_args()

key = base64.b64decode(args.key)

pkts = []
for i in range(args.n):
    hf = make_mac_input(beta = i, ts = 1 << 30, exp_time = 100, ingress = 4, egress = 8)
    mac = compute_mac(hf, key)
    pkt = Ether(dst="ff:ff:ff:ff:ff:ff") \
        / BridgeHeader(
            Flags=BrFlags.CHECK_HF1.value,
            MAC1 = int.from_bytes(mac, 'big'),
            HF1 = int.from_bytes(hf, 'big'),
        ) \
        / Ether(dst="ff:ff:ff:ff:ff:ff") \
        / IP(dst="127.0.0.1", src="127.0.0.1") \
        / UDP(dport=50000) \
        / Raw("Payload")
    pkts.append(pkt)
wrpcap(args.output, pkts)
