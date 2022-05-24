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

import ptf
import ptf.mask
import ptf.ptfutils
from mac_offload.bridge_header import (BrFlags, BridgeHeader, compute_mac,
                                       make_mac_input)
from ptf.base_tests import BaseTest
from ptf.testutils import send_packet, test_param_get, verify_packet
from scapy.layers.inet import IP, UDP, Ether
from scapy.packet import Raw


class HopFieldVerificationTest(BaseTest):
    """Test hop field validation"""

    def setUp(self):
        BaseTest.setUp(self)
        self.dataplane = ptf.dataplane_instance

    def tearDown(self):
        return BaseTest.tearDown(self)

    def runTest(self):
        key = base64.b64decode(test_param_get("key"))
        hf1 = make_mac_input(beta = 5194, ts = 1 << 30, exp_time = 100, ingress = 4, egress = 8)
        hf2 = make_mac_input(beta = 8362, ts = 1 << 30, exp_time = 100, ingress = 9, egress = 2)

        # No HF to check
        flags = 0
        bridge = BridgeHeader(Flags=0)
        expected_flags = 0
        self.verify(bridge, expected_flags)

        # One valid HF
        flags = BrFlags.CHECK_HF1
        bridge = BridgeHeader(Flags=flags.value,
            MAC1 = int.from_bytes(compute_mac(hf1, key), 'big'),
            HF1 = int.from_bytes(hf1, 'big')
        )
        expected_flags = (flags | BrFlags.HF1_OK).value
        self.verify(bridge, expected_flags)

        # One invalid HF
        flags = BrFlags.CHECK_HF1
        bridge = BridgeHeader(Flags=flags.value,
            HF1 = int.from_bytes(hf1, 'big')
        )
        expected_flags = (flags).value
        self.verify(bridge, expected_flags)

        # Two valid HFs
        flags = BrFlags.CHECK_HF1 | BrFlags.CHECK_HF2
        bridge = BridgeHeader(Flags=flags.value,
            MAC1 = int.from_bytes(compute_mac(hf1, key), 'big'),
            HF1 = int.from_bytes(hf1, 'big'),
            MAC2 = int.from_bytes(compute_mac(hf2, key), 'big'),
            HF2 = int.from_bytes(hf2, 'big')
        )
        expected_flags = (flags | BrFlags.HF1_OK | BrFlags.HF2_OK).value
        self.verify(bridge, expected_flags)

        # One valid, one invalid HF
        flags = BrFlags.CHECK_HF1 | BrFlags.CHECK_HF2
        bridge = BridgeHeader(Flags=flags.value,
            MAC1 = int.from_bytes(compute_mac(hf1, key), 'big'),
            HF1 = int.from_bytes(hf1, 'big'),
            MAC2 = int.from_bytes(compute_mac(hf2, key), 'big'),
        )
        expected_flags = (flags | BrFlags.HF1_OK).value
        self.verify(bridge, expected_flags)

    def verify(self, bridge: BridgeHeader, expected_flags: int):
        sent_pkt = Ether(dst="ff:ff:ff:ff:ff:ff") \
            / bridge \
            / Ether(dst="ff:ff:ff:ff:ff:ff") \
            / IP(dst="127.0.0.1", src="127.0.0.1") \
            / UDP(dport=50000) \
            / Raw("Payload")

        expected_pkt = copy.deepcopy(sent_pkt)
        expected_pkt[BridgeHeader].Flags = expected_flags
        expected_pkt = ptf.mask.Mask(expected_pkt)
        expected_pkt.set_do_not_care_scapy(BridgeHeader, "IngressPort")

        send_packet(self, 0, sent_pkt)
        verify_packet(self, expected_pkt, 0, timeout=1)
