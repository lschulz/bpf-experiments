#!/bin/bash

sudo ip netns add sw0
sudo ip netns add sw1
sudo ip netns add sw2

# Create veth pairs
sudo ip link add veth0 type veth peer name veth1 netns sw0
sudo ip link add veth2 type veth peer name veth3 netns sw0
sudo ip link add veth4 netns sw1 type veth peer name veth5 netns sw0
sudo ip link add veth6 type veth peer name veth7 netns sw1
sudo ip link add veth9 netns sw2 type veth peer name veth8 netns sw1
sudo ip link add veth10 type veth peer name veth11 netns sw2

# Make sure MACs are deterministic
sudo ip link set dev veth0 addr 3e:fc:20:e7:9c:a1
sudo ip netns exec sw0 ip link set dev veth1 addr 7e:e7:86:a8:68:73
sudo ip link set dev veth2 addr e6:33:98:64:a0:ae
sudo ip netns exec sw0 ip link set dev veth3 addr 96:c7:2b:42:25:3f
sudo ip link set dev veth6 addr 5a:3c:33:27:77:85
sudo ip netns exec sw1 ip link set dev veth7 addr f2:b1:c9:79:bc:c8
sudo ip link set dev veth10 addr 52:d9:dc:e2:46:03
sudo ip netns exec sw2 ip link set dev veth11 addr ea:4f:72:b5:59:5f

# Configure host interfaces in global namespace
sudo ip addr add dev veth0 10.1.0.1/24
sudo ip addr add dev veth2 10.1.1.1/24
sudo ip addr add dev veth6 10.1.2.1/24
sudo ip addr add dev veth10 10.1.3.1/24
sudo ip link set dev veth0 up
sudo ip link set dev veth2 up
sudo ip link set dev veth6 up
sudo ip link set dev veth10 up

# Load trivial XDP programs on host side (required for XDP_TX and XDP_REDIRECT on veths)
make -C xdp_pass
sudo make -C xdp_pass attach VETH=veth0
sudo make -C xdp_pass attach VETH=veth2
sudo make -C xdp_pass attach VETH=veth6
sudo make -C xdp_pass attach VETH=veth10

# Bring interface on switch side up
sudo ip netns exec sw0 ip addr add dev veth1 10.1.0.2/24
sudo ip netns exec sw0 ip addr add dev veth3 10.1.1.2/24
sudo ip netns exec sw0 ip link set dev veth1 up
sudo ip netns exec sw0 ip link set dev veth3 up
sudo ip netns exec sw1 ip addr add dev veth7 10.1.2.2/24
sudo ip netns exec sw1 ip link set dev veth7 up
sudo ip netns exec sw2 ip addr add dev veth11 10.1.3.2/24
sudo ip netns exec sw2 ip link set dev veth11 up

# Configure links between switches
sudo ip netns exec sw0 ip addr add dev veth5 10.2.0.1/24
sudo ip netns exec sw1 ip addr add dev veth4 10.2.0.2/24
sudo ip netns exec sw0 ip link set dev veth5 up
sudo ip netns exec sw1 ip link set dev veth4 up
sudo ip netns exec sw1 ip addr add dev veth8 10.3.0.1/24
sudo ip netns exec sw2 ip addr add dev veth9 10.3.0.2/24
sudo ip netns exec sw1 ip link set dev veth8 up
sudo ip netns exec sw2 ip link set dev veth9 up

# Configure AS internal routing
sudo ip netns exec sw1 sysctl -w net.ipv4.ip_forward=1
sudo ip netns exec sw0 ip route add 10.3.0.0/24 via 10.2.0.2 dev veth5
sudo ip netns exec sw2 ip route add 10.2.0.0/24 via 10.3.0.1 dev veth9

# Disable checksum offload
# sudo ethtool --offload veth0 rx off tx off
# sudo ethtool --offload veth2 rx off tx off
# sudo ip netns exec sw0 ethtool --offload veth1 rx off tx off
# sudo ip netns exec sw0 ethtool --offload veth3 rx off tx off

# Run border routers
# cd ..
# sudo ip netns exec sw0 build/int build/xdp_combined.o test/config0.json veth1 veth3 veth5
# sudo ip netns exec sw1 build/int build/xdp_combined.o test/config1.json veth7 veth4 veth8
# sudo ip netns exec sw2 build/int build/xdp_combined.o test/config2.json veth11 veth9
