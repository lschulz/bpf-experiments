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
from typing import Optional, Tuple

import scapy_scion.layers.id_int as id_int
from scapy.fields import (ByteField, ConditionalField, FlagsField, IntField,
                          PacketField, ShortField, XBitField, XShortField,
                          XStrFixedLenField)
from scapy.layers.inet import Ether
from scapy.packet import Packet, bind_layers


class BridgeFlags(enum.Flag):
    Check1 = (1 << 0)
    Check2 = (1 << 1)
    IDINT  = (1 << 2)
    Valid1 = (1 << 4)
    Valid2 = (1 << 5)


class IdIntBridgeFlags(enum.Flag):
    Auth    = (1 << 0) # Authenticate the telemetry with the given key
    Encrypt = (1 << 1) # Encrypt with the given key


class MacInput(Packet):
    """Input block for SCION hop field verification."""

    name = "Hop MAC verification block"

    fields_desc = [
        ShortField("Zero1", default=0),
        XShortField("Beta_i", default=0),
        IntField("Timestamp", default=0),
        ByteField("Zero2", default=0),
        ByteField("ExpTime", default=0),
        ShortField("ConsIngress", default=0),
        ShortField("ConsEgress", default=1),
        # The 16-byte input block for MAC verification ends with 2 bytes of zeros.
        # To save on space in the bridge header, we overwrite these two bytes with the first two
        # bytes of the expected MAC.
        # ShortField("Zero3", default=0),
        XBitField("MAC", default=0, size=48)
    ]

    def extract_padding(self, s: bytes) -> Tuple[bytes, Optional[bytes]]:
        return b"", s


class IdIntBridge(Packet):
    """Bridge header for ID-INT."""

    name = "ID-INT bridge header"

    fields_desc = [
        FlagsField("Flags", default="Auth", size=8, names={
            flag.value.bit_length() - 1: flag.name for flag in IdIntBridgeFlags
        }),
        # Length is the total length of the header in multiples of 4 bytes
        ByteField("Length", default=None),
        ShortField("Reserved", default=0),
        ConditionalField(XStrFixedLenField("Key", default=16*b"\x00", length=16),
            lambda pkt: pkt.Flags.Encrypt),
        PacketField("Metadata", default=id_int.Metadata(), pkt_cls=id_int.Metadata)
    ]

    def extract_padding(self, s: bytes) -> Tuple[bytes, Optional[bytes]]:
        return b"", s

    def post_build(self, hdr: bytes, payload: bytes):
        if self.Length is None:
            length = len(hdr) // 4
            hdr = hdr[:1] + length.to_bytes(1, byteorder='big') + hdr[2:]
        return hdr + payload


class BridgeHdr(Packet):
    """Bridge header for submitting work to the accelerator."""

    name = "Bridge Header"

    fields_desc = [
        FlagsField("Flags", default=0, size=8, names={
            flag.value.bit_length() - 1: flag.name for flag in BridgeFlags
        }),
        # Length is the total length of the header in multiples of 4 bytes
        ByteField("Length", default=None),
        ShortField("EgressPort", default=0),
        ConditionalField(PacketField("MAC1", default=MacInput(), pkt_cls=MacInput),
            lambda pkt: pkt.Flags.Check1),
        ConditionalField(PacketField("MAC2", default=MacInput(), pkt_cls=MacInput),
            lambda pkt: pkt.Flags.Check2),
        ConditionalField(PacketField("IDINT", default=IdIntBridge(), pkt_cls=IdIntBridge),
            lambda pkt: pkt.Flags.IDINT)
    ]

    def post_build(self, hdr: bytes, payload: bytes):
        if self.Length is None:
            length = len(hdr) // 4
            hdr = hdr[:1] + length.to_bytes(1, byteorder='big') + hdr[2:]
        return hdr + payload


bind_layers(Ether, BridgeHdr, type=0x9999)
bind_layers(BridgeHdr, Ether)
