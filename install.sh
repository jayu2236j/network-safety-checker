#!/usr/bin/env bash
# Simple installer for Network Safety Checker

set -e

TARGET="/usr/local/bin/netscan"

sudo cp network_safety_checker.sh "$TARGET"
sudo chmod +x "$TARGET"

echo "Installed Network Safety Checker as 'netscan'."
echo "Run it using: sudo netscan"
