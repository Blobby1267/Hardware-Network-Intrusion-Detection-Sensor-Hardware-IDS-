#!/bin/bash

# Raspberry Pi startup wrapper for the Hardware IDS
# Run this script on the Pi after installing dependencies.

set -e

if [[ "$EUID" -ne 0 ]]; then
  echo "Please run this script with sudo or as root."
  exit 1
fi

INTERFACE="${IDS_INTERFACE:-eth0}"
ALLOWED_MACS="${IDS_ALLOWED_MACS:-}"
PYTHON="${PYTHON:-python3}"

echo "Starting Hardware IDS on Raspberry Pi"
echo "Capture interface: $INTERFACE"
if [[ -n "$ALLOWED_MACS" ]]; then
  echo "Allowed MAC addresses: $ALLOWED_MACS"
fi

exec "$PYTHON" "$(dirname "$0")/main.py" --interface "$INTERFACE" --allowed-macs "$ALLOWED_MACS"
