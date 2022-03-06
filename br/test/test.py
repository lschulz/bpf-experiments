#!/usr/bin/env python3

import argparse
import base64
import subprocess
import time

import pyroute2
import utils
from layers.scion import SCION, HopField, InfoField, SCIONPath
from pr2modules.netlink.exceptions import NetlinkError
from scapy.layers.inet import IP, UDP, Ether
from scapy.main import interact as scapy_interact
from scapy.packet import Raw
from scapy.sendrecv import sendp, sniff


class Fixture:
    def create(self):
        ipr = pyroute2.IPRoute()

        # Create namespaces
        self.sw0 = pyroute2.NetNS("sw0")
        self.sw1 = pyroute2.NetNS("sw1")
        self.sw2 = pyroute2.NetNS("sw2")

        # Create veth pairs
        reuse = False
        try:
            ipr.link("add", ifname="veth0", kind="veth", peer="veth1")
            ipr.link("add", ifname="veth2", kind="veth", peer="veth3")
            ipr.link("add", ifname="veth4", kind="veth", peer="veth5")
            ipr.link("add", ifname="veth6", kind="veth", peer="veth7")
            ipr.link("add", ifname="veth8", kind="veth", peer="veth9")
            ipr.link("add", ifname="veth10", kind="veth", peer="veth11")
        except NetlinkError as e:
            if e.code == 17:
                print("Using existing veths")
                reuse = True
            else:
                raise

        self.veth = 12 * [None]
        if reuse:
            for i in [0, 2, 6, 10]:
                self.veth[i] = ipr.link_lookup(ifname="veth%d" % i)[0]
            for i in [1, 3, 5]:
                self.veth[i] = self.sw0.link_lookup(ifname="veth%d" % i)[0]
            for i in [4, 7, 8]:
                self.veth[i] = self.sw1.link_lookup(ifname="veth%d" % i)[0]
            for i in [9, 11]:
                self.veth[i] = self.sw2.link_lookup(ifname="veth%d" % i)[0]
            return

        for i in range(12):
            self.veth[i] = ipr.link_lookup(ifname="veth%d" % i)[0]

        # Make sure MACs are deterministic
        ipr.link("set", index=self.veth[0], addr="3e:fc:20:e7:9c:a1")
        ipr.link("set", index=self.veth[1], addr="7e:e7:86:a8:68:73")
        ipr.link("set", index=self.veth[2], addr="e6:33:98:64:a0:ae")
        ipr.link("set", index=self.veth[3], addr="96:c7:2b:42:25:3f")

        ipr.link("set", index=self.veth[6], addr="5a:3c:33:27:77:85")
        ipr.link("set", index=self.veth[7], addr="f2:b1:c9:79:bc:c8")
        ipr.link("set", index=self.veth[10], addr="52:d9:dc:e2:46:03")
        ipr.link("set", index=self.veth[11], addr="ea:4f:72:b5:59:5f")

        # Move switch side interfaces in corresponding namespaces
        ipr.link("set", index=self.veth[1], net_ns_fd="sw0")
        ipr.link("set", index=self.veth[3], net_ns_fd="sw0")
        ipr.link("set", index=self.veth[5], net_ns_fd="sw0")
        ipr.link("set", index=self.veth[4], net_ns_fd="sw1")
        ipr.link("set", index=self.veth[7], net_ns_fd="sw1")
        ipr.link("set", index=self.veth[8], net_ns_fd="sw1")
        ipr.link("set", index=self.veth[9], net_ns_fd="sw2")
        ipr.link("set", index=self.veth[11], net_ns_fd="sw2")

        # Configure host interfaces in global namespace
        ipr.addr("add", index=self.veth[0], address="10.1.0.1", mask=24)
        ipr.addr("add", index=self.veth[2], address="10.1.1.1", mask=24)
        ipr.addr("add", index=self.veth[6], address="10.1.2.1", mask=24)
        ipr.addr("add", index=self.veth[10], address="10.1.3.1", mask=24)
        ipr.link("set", index=self.veth[0], state="up")
        ipr.link("set", index=self.veth[2], state="up")
        ipr.link("set", index=self.veth[6], state="up")
        ipr.link("set", index=self.veth[10], state="up")

        # Load trivial XDP programs on host side
        subprocess.run("make -C xdp_pass", shell=True, check=True, capture_output=True)
        subprocess.run("make -C xdp_pass attach VETH=veth0",
            shell=True, check=True, capture_output=True)
        subprocess.run("make -C xdp_pass attach VETH=veth2",
            shell=True, check=True, capture_output=True)
        subprocess.run("make -C xdp_pass attach VETH=veth6",
            shell=True, check=True, capture_output=True)
        subprocess.run("make -C xdp_pass attach VETH=veth10",
            shell=True, check=True, capture_output=True)

        # Bring interface on switch side up
        self.sw0.addr("add", index=self.veth[1], address="10.1.0.2", mask=24)
        self.sw0.addr("add", index=self.veth[3], address="10.1.1.2", mask=24)
        self.sw0.link("set", index=self.veth[1], state="up")
        self.sw0.link("set", index=self.veth[3], state="up")
        self.sw1.addr("add", index=self.veth[7], address="10.1.2.2", mask=24)
        self.sw1.link("set", index=self.veth[7], state="up")
        self.sw2.addr("add", index=self.veth[11], address="10.1.3.2", mask=24)
        self.sw2.link("set", index=self.veth[11], state="up")

        # Configure links between switches
        self.sw0.addr("add", index=self.veth[5], address="10.2.0.1", mask=24)
        self.sw1.addr("add", index=self.veth[4], address="10.2.0.2", mask=24)
        self.sw0.link("set", index=self.veth[5], state="up")
        self.sw1.link("set", index=self.veth[4], state="up")
        self.sw1.addr("add", index=self.veth[8], address="10.3.0.1", mask=24)
        self.sw2.addr("add", index=self.veth[9], address="10.3.0.2", mask=24)
        self.sw1.link("set", index=self.veth[8], state="up")
        self.sw2.link("set", index=self.veth[9], state="up")

        # Configure AS internal routing
        subprocess.run("ip netns exec sw1 sysctl -w net.ipv4.ip_forward=1",
            shell=True, check=True, capture_output=True)
        self.sw0.route("add", dst="10.3.0.0/24", gateway="10.2.0.2", index=self.veth[5])
        self.sw2.route("add", dst="10.2.0.0/24", gateway="10.3.0.1", index=self.veth[9])

    def destroy(self):
        subprocess.run("make -C xdp_pass detach VETH=veth0",
            shell=True, check=True, capture_output=True)
        subprocess.run("make -C xdp_pass detach VETH=veth2",
            shell=True, check=True, capture_output=True)
        subprocess.run("make -C xdp_pass detach VETH=veth6",
            shell=True, check=True, capture_output=True)
        subprocess.run("make -C xdp_pass detach VETH=veth10",
            shell=True, check=True, capture_output=True)
        for sw in [self.sw0, self.sw1, self.sw2]:
            if sw:
                sw.close()
                sw.remove()


def gen_test_cases(ingress: int, enc_ig: Ether, egress: int, enc_eg: Ether):
    # AS keys
    local_key = base64.b64encode(8*b"ff")
    dont_care = base64.b64encode(8*b"00")

    # Payload
    payload = UDP(sport=6500, dport=6500)/Raw("TEST")

    test_case = []
    pkts = []
    resp = []

    # Down-segment alone
    test_case.append("Down-segment")
    path = SCIONPath(
        Seg0Len=3, Seg1Len=0, Seg2Len=0,
        InfoFields=[
            InfoField(Flags="C")
        ],
        HopFields=[
            HopField(ConsIngress=0, ConsEgress=1),
            HopField(ConsIngress=ingress, ConsEgress=egress),
            HopField(ConsIngress=1, ConsEgress=0),
        ]
    )
    path.init_path(keys=[dont_care, local_key, dont_care], seeds=[bytes(0xffff)])
    path.egress(dont_care)
    path = SCIONPath(bytes(path))
    expected = path.copy()
    expected.ingress(local_key)
    expected.egress(local_key)
    pkts.append(enc_ig/SCION(Path=path)/payload)
    resp.append(Ether(bytes(enc_eg/SCION(Path=expected)/payload)))

    # Up-segment alone
    test_case.append("Up-segment")
    path = SCIONPath(
        Seg0Len=3, Seg1Len=0, Seg2Len=0,
        InfoFields=[
            InfoField()
        ],
        HopFields=[
            HopField(ConsIngress=1, ConsEgress=0),
            HopField(ConsIngress=egress, ConsEgress=ingress),
            HopField(ConsIngress=0, ConsEgress=1),
        ]
    )
    path.init_path(keys=[dont_care, local_key, dont_care], seeds=[bytes(0xffff)])
    path.egress(dont_care)
    path = SCIONPath(bytes(path))
    expected = path.copy()
    expected.ingress(local_key)
    expected.egress(local_key)
    pkts.append(enc_ig/SCION(Path=path)/payload)
    resp.append(Ether(bytes(enc_eg/SCION(Path=expected)/payload)))

    # Core-segment alone
    test_case.append("Core-segment")
    path = SCIONPath(
        Seg0Len=3, Seg1Len=0, Seg2Len=0,
        InfoFields=[
            InfoField()
        ],
        HopFields=[
            HopField(ConsIngress=1, ConsEgress=0),
            HopField(ConsIngress=egress, ConsEgress=ingress),
            HopField(ConsIngress=0, ConsEgress=1),
        ]
    )
    path.init_path(keys=[dont_care, local_key, dont_care], seeds=[bytes(0xffff)])
    path.egress(dont_care)
    path = SCIONPath(bytes(path))
    expected = path.copy()
    expected.ingress(local_key)
    expected.egress(local_key)
    pkts.append(enc_ig/SCION(Path=path)/payload)
    resp.append(Ether(bytes(enc_eg/SCION(Path=expected)/payload)))

    # Path segment switch at core
    test_case.append("Segment switch at core")
    path = SCIONPath(
        Seg0Len=2, Seg1Len=3, Seg2Len=0,
        InfoFields=[
            InfoField(),
            InfoField(Flags="C")
        ],
        HopFields=[
            # Up-segment
            HopField(ConsIngress=1, ConsEgress=0),
            HopField(ConsIngress=0, ConsEgress=ingress),
            # Down-segment
            HopField(ConsIngress=0, ConsEgress=egress),
            HopField(ConsIngress=1, ConsEgress=2),
            HopField(ConsIngress=1, ConsEgress=0),
        ]
    )
    path.init_path(keys=[
        dont_care, local_key, local_key, dont_care, dont_care, dont_care],
        seeds=[bytes(0xffff), bytes(0xffff)])
    path.egress(dont_care)
    path = SCIONPath(bytes(path))
    expected = path.copy()
    expected.ingress(local_key)
    expected.egress(local_key)
    pkts.append(enc_ig/SCION(Path=path)/payload)
    resp.append(Ether(bytes(enc_eg/SCION(Path=expected)/payload)))

    return test_case, pkts, resp


def compare_packets(packet1, packet2):
    layers1, layers2 = packet1.layers(), packet2.layers()
    for i, (layer1, layer2) in enumerate(zip(layers1, layers2)):
        if layer1 is not layer2:
            yield ("Layer", str(i), packet1[i].name, packet2[i].name)
        for field, a, b in utils.compare_layers(packet1[i], packet2[i]):
            yield (packet1[i].name, field, a, b)


def check(test_case, expected, received):
    for name, expect, recvd in zip(test_case, expected, received):
        diff = list(compare_packets(expect, recvd))
        print("PASS" if len(diff) == 0 else "FAIL", name)
        if len(diff):
            print("{:<8} {:<25} {:>8} {:>8}".format("Layer", "Field", "Expected", "Actual"))
            for layer, field, a, b in diff:
                a = "None" if a is None else a
                b = "None" if b is None else b
                print("{:<8} {:<25} {:>8} {:>8}".format(layer, field, a, b))


def test_forwarding():
    # Ingress in interface 1
    ingress = 1
    enc_ig = Ether(src="7e:e7:86:a8:68:73", dst="3e:fc:20:e7:9c:a1")/ \
            IP(src="10.1.0.1", dst="10.1.0.2")/UDP(sport=30043, dport=30042)

    print("### Test forwarding (1 hop)")
    # Egress from interface 2
    egress = 2
    enc_eg = Ether(src="96:c7:2b:42:25:3f", dst="e6:33:98:64:a0:ae")/ \
            IP(src="10.1.1.2", dst="10.1.1.1")/UDP(sport=30044, dport=30045)
    test_case, pkts, expected = gen_test_cases(ingress, enc_ig, egress, enc_eg)

    received = sniff(iface="veth2", count=len(expected), timeout=2,
        filter="udp", lfilter=lambda pkt: pkt.haslayer(SCION),
        started_callback=lambda: sendp(pkts, iface="veth0"))
    check(test_case, expected, received)

    print("### Test forwarding (2 hops)")
    # Egress from interface 3
    egress = 3
    enc_eg = Ether(src="f2:b1:c9:79:bc:c8", dst="5a:3c:33:27:77:85")/ \
            IP(src="10.1.2.2", dst="10.1.2.1")/UDP(sport=30042, dport=30042)
    test_case, pkts, expected = gen_test_cases(ingress, enc_ig, egress, enc_eg)

    received = sniff(iface="veth6", count=len(expected), timeout=2,
        filter="udp", lfilter=lambda pkt: pkt.haslayer(SCION),
        started_callback=lambda: sendp(pkts, iface="veth0"))
    check(test_case, expected, received)

    print("### Test forwarding (3 hops)")
    # Egress from interface 3
    egress = 4
    enc_eg = Ether(src="ea:4f:72:b5:59:5f", dst="52:d9:dc:e2:46:03")/ \
            IP(src="10.1.3.2", dst="10.1.3.1")/UDP(sport=30042, dport=30042)
    test_case, pkts, expected = gen_test_cases(ingress, enc_ig, egress, enc_eg)

    received = sniff(iface="veth10", count=len(expected), timeout=2,
        filter="udp", lfilter=lambda pkt: pkt.haslayer(SCION),
        started_callback=lambda: sendp(pkts, iface="veth0"))
    check(test_case, expected, received)


def main():
    parser = argparse.ArgumentParser(description="Test the BPF border router")
    parser.add_argument("-i", "--interactive", action='store_true',
        help="Drop into an interactive scapy shell")
    parser.add_argument("-k", "--keep", action='store_true',
        help="Do not delete the network namespaces and virtual interfaces after running the tests")
    args = parser.parse_args()

    # Create namespaces and veth pairs
    fixture = Fixture()
    fixture.create()

    br = 3*[None]
    try:
        # Start border routers
        br[0] = subprocess.Popen(
            "ip netns exec sw0 ../build/int ../build/xdp_combined.o config0.json veth1 veth3 veth5",
            shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, encoding="utf-8"
        )
        br[1] = subprocess.Popen(
            "ip netns exec sw1 ../build/int ../build/xdp_combined.o config1.json veth7 veth4 veth8",
            shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, encoding="utf-8"
        )
        br[2] = subprocess.Popen(
            "ip netns exec sw2 ../build/int ../build/xdp_combined.o config2.json veth11 veth9",
            shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, encoding="utf-8"
        )
        time.sleep(0.5)

        for i, router in enumerate(br):
            if router.poll():
                print(f"Border router {i} did not start correctly:")
                print(br.communicate()[0])

        if args.interactive:
            scapy_interact(argv=[], mydict=dict(globals(), **locals()))
        else:
            test_forwarding()

    finally:
        for router in br:
            if router:
                router.terminate()
        if not args.keep:
            fixture.destroy()


if __name__ == "__main__":
    main()
