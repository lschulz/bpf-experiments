#!/bin/bash

if [[ ! "$(ip link)" =~ veth0 ]]; then
    sudo ip link add veth0 type veth peer name veth1
    sudo ip link add veth2 type veth peer name veth3
    sudo ip link set dev veth0 up
    sudo ip link set dev veth1 up
    sudo ip link set dev veth2 up
    sudo ip link set dev veth3 up
fi
