#!/usr/bin/env bash
set -eu
if [ "$(id -u)" -ne 0 ]; then
  echo "[!] Run inside a NetHunter root shell."
  exit 1
fi
apt update
apt install -y python3 python3-scapy python3-colorama
echo "[+] NetHunter dependencies installed."
echo "[*] Test: python3 cyberscan.py -p diagnostics"
