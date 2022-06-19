#!/bin/bash

if [[ "$(ip link)" =~ veth0 ]]; then
    sudo ip link delete veth0
fi
