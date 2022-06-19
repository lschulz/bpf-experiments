#!/bin/bash

if [[ "$(ip link)" =~ veth0 ]]; then
    sudo ip link delete veth0
    sudo ip link delete veth2
fi
