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

import enum
import struct

from cryptography.hazmat.primitives import cmac
from cryptography.hazmat.primitives.ciphers import algorithms
from scapy.fields import (ByteField, FlagsField, IntField, ShortField,
                          XNBytesField, XShortField)
from scapy.layers.inet import Ether
from scapy.packet import Packet, bind_layers


class BrFlags(enum.Flag):
    CHECK_HF1 = (1 << 0)
    CHECK_HF2 = (1 << 1)
    HF1_OK = (1 << 4)
    HF2_OK = (1 << 5)


class BridgeHeader(Packet):
    """Bridge header for submitting work to the accelerator device."""

    name = "Bridge Header"

    fields_desc = [
        FlagsField("Flags", default=0, size=8, names={
            (f.value.bit_length() - 1): f.name for f in BrFlags}
        ),
        ByteField("Reserved", default=0),
        XShortField("SwitchData", default=0),
        IntField("IngressPort", default=0),
        XNBytesField("MAC1", default=0, sz=6),
        ShortField("Zero1", default=0),
        XNBytesField("HF1", default=0, sz=16),
        XNBytesField("MAC2", default=0, sz=6),
        ShortField("Zero2", default=0),
        XNBytesField("HF2", default=0, sz=16),
    ]


bind_layers(Ether, BridgeHeader, type=0x9999)
bind_layers(BridgeHeader, Ether)


def make_mac_input(beta, ts, exp_time, ingress, egress):
    return struct.pack("!HHIBBHHH", 0, beta, ts, 0, exp_time, ingress, egress, 0)


def compute_mac(input: bytes, key: bytes) -> bytes:
    c = cmac.CMAC(algorithms.AES(key))
    c.update(input)
    return c.finalize()[:6]
