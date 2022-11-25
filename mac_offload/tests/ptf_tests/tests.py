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

import base64
import copy
import struct

from cryptography.hazmat.primitives import cmac
from cryptography.hazmat.primitives.ciphers import algorithms
from mac_offload.bridge_header import BridgeFlags, BridgeHdr, MacInput
from scapy.layers.inet import IP, UDP, Ether
from scapy.packet import Raw

import ptf
import ptf.mask
import ptf.ptfutils
from ptf.base_tests import BaseTest
from ptf.testutils import send_packet, test_param_get, verify_packet


def make_mac_input(beta, ts, exp_time, ingress, egress):
    return struct.pack("!HHIBBHHH", 0, beta, ts, 0, exp_time, ingress, egress, 0)


def compute_mac(input: bytes, key: bytes) -> bytes:
    c = cmac.CMAC(algorithms.AES(key))
    c.update(input)
    return c.finalize()[:6]


class HopFieldVerificationTest(BaseTest):
    """Test hop field validation"""

    def setUp(self):
        BaseTest.setUp(self)
        self.dataplane = ptf.dataplane_instance

    def tearDown(self):
        return BaseTest.tearDown(self)

    def runTest(self):
        key = base64.b64decode(test_param_get("key"))
        input1 = MacInput(
            Beta_i = 5194, Timestamp = 1 << 30, ExpTime = 100, ConsIngress = 4, ConsEgress = 8)
        mac1 = compute_mac(make_mac_input(
            beta = 5194, ts = 1 << 30, exp_time = 100, ingress = 4, egress = 8
        ), key)
        input2 = MacInput(
            Beta_i = 8362, Timestamp = 1 << 30, ExpTime = 100, ConsIngress = 9, ConsEgress = 2)
        mac2 = compute_mac(make_mac_input(
            beta = 8362, ts = 1 << 30, exp_time = 100, ingress = 9, egress = 2
        ), key)

        # No HF to check
        bridge = BridgeHdr(Flags=0)
        expected_flags = 0
        self.verify(bridge, expected_flags)

        # One valid HF
        flags = BridgeFlags.Check1
        input1.MAC = int.from_bytes(mac1, 'big')
        bridge = BridgeHdr(Flags=flags.value, MAC1=input1)
        expected_flags = (flags | BridgeFlags.Valid1).value
        self.verify(bridge, expected_flags)

        # One invalid HF
        flags = BridgeFlags.Check1
        input1.MAC = int.from_bytes(mac2, 'big')
        bridge = BridgeHdr(Flags=flags.value, MAC1=input1)
        expected_flags = (flags | BridgeFlags.Valid1).value
        expected_flags = (flags).value
        self.verify(bridge, expected_flags)

        # Two valid HFs
        flags = BridgeFlags.Check1 | BridgeFlags.Check2
        input1.MAC = int.from_bytes(mac1, 'big')
        input2.MAC = int.from_bytes(mac2, 'big')
        bridge = BridgeHdr(Flags=flags.value, MAC1 = input1, MAC2 = input2)
        expected_flags = (flags | BridgeFlags.Valid1 | BridgeFlags.Valid2).value
        self.verify(bridge, expected_flags)

        # One valid, one invalid HF
        flags = BridgeFlags.Check1 | BridgeFlags.Check2
        input1.MAC = int.from_bytes(mac1, 'big')
        input2.MAC = int.from_bytes(mac1, 'big')
        bridge = BridgeHdr(Flags=flags.value, MAC1 = input1, MAC2 = input2)
        expected_flags = (flags | BridgeFlags.Valid1).value
        self.verify(bridge, expected_flags)

    def verify(self, bridge: BridgeHdr, expected_flags: int):
        sent_pkt = Ether(dst="ff:ff:ff:ff:ff:ff", src="00:00:00:00:00:00") \
            / bridge \
            / Ether(dst="ff:ff:ff:ff:ff:ff") \
            / IP(dst="127.0.0.1", src="127.0.0.1") \
            / UDP(dport=50000) \
            / Raw("Payload")

        expected_pkt = copy.deepcopy(sent_pkt)
        expected_pkt[Ether].dst = "00:00:00:00:00:00"
        expected_pkt[Ether].src = "ff:ff:ff:ff:ff:ff"
        expected_pkt[BridgeHdr].Flags = expected_flags

        send_packet(self, 0, sent_pkt)
        verify_packet(self, expected_pkt, 0, timeout=1)
