#!/bin/bash

SCRIPT_DIR=$(dirname "$(readlink -f "$0")")

# Remove network namespaces
sudo "$SCRIPT_DIR/../netns.bash" delete sw0
sudo "$SCRIPT_DIR/../netns.bash" delete sw1
sudo "$SCRIPT_DIR/../netns.bash" delete sw2
