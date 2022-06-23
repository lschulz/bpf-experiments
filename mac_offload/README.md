MAC Computation Offload to BPF/XDP
==================================
This projects aims to use XDP to perform SCION hop field validation on behalf of P4-programmable
switches that do not support AES.

Introduction
------------
Tofino is an extremely capable packet processing engine, but is missing certain features we need for
SCION, most importantly support for cryptography. SCION (and COLIBRI and EPIC) hop fields have to be
validated at border routers by computing AES-CMACs over header fields, however AES cannot reasonably
be implemented in P4.

A possible workaround is pairing a Tofino switch with another packet processing device as
cryptography accelerator. A subset of ports on the Tofino switch are used for connecting the
validators to the data path. Packets that enter the border router are first processed by the Tofino
switch, then sent to the accelerator, processed on the accelerator, returned to the switch on the
same port, and finally forwarded to the next hop.

```
     +--------+
---->|        |      +-----------+
     |        |<---->|           |
     | Tofino |<---->|    BPF    |
     |        |<---->|           |
<----|        |      +-----------+
     +--------+
```

We have developed an XDP-based hop field validation accelerator that can be run on any commodity
server. The code is based on the XDP SCION Border Router.

### Bridge Header
To avoid duplicating the work of parsing the packet headers, packets sent from the switch to the
hop field validator contain a bridge header with preformatted input blocks for the MAC computation.
