#!/bin/bash

SCRIPT_DIR=$(dirname "$(readlink -f "$0")")

# Remove network namespace
sudo "$SCRIPT_DIR/../netns.bash" delete sw0
