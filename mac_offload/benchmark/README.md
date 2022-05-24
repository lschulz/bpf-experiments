XDP MAC Offload Benchmark
=========================

```bash
PROJECT_DIR=<root of the repository>
KEY="MTExMTExMTExMTExMTExMQ=="
CPU_MASK=0xff
# Create virtual links
sudo ./veth_setup.bash
# Generate packets
PYTHONPATH="$PROJECT_DIR/mac_offload/python" ./gen_packets.py "$KEY" br_pkts.pcap
# Attach XDP programs
sudo $PROJECT_DIR/build/mac_offload/mac-offload \
    $PROJECT_DIR/build/mac_offload/xdp_mac.o "$KEY" "$CPU_MASK" veth1
sudo ./count_and_drop.py -i veth0
# Generate packets
sudo tcpreplay -i veth0 --topspeed -K --loop=10000 br_pkts.pcap
# Delete veths
sudo ./veth_teardown.bash
```
