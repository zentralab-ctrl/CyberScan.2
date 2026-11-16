#!/data/data/com.termux/files/usr/bin/bash
set -eu
pkg update -y
pkg install -y python clang libpcap
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
echo "[+] CyberScan GODMODE dependencies installed."
echo "[*] Test: python cyberscan.py -p diagnostics"
