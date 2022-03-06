#!/bin/bash

export PYTHONPATH=$(readlink -f ../../scapy-scion-int)
./test.py "$@"
