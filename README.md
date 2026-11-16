# CyberScan GODMODE SAFE Edition 3.0

## Files
- `cyberscan.py`: main application; can be edited in Acode and run in Termux/NetHunter.
- `requirements.txt`: required optional-friendly packages (Scapy and Colorama).
- `requirements-geoip.txt`: optional GeoIP library.
- `install_termux.sh`: Termux installer.
- `install_nethunter.sh`: Kali NetHunter root-shell installer.
- `captures/`: place authorized PCAP captures here.
- `reports/`: output reports.

## Termux
```bash
bash install_termux.sh
python cyberscan.py --menu
```

## Kali NetHunter
```bash
bash install_nethunter.sh
python3 cyberscan.py --menu
```

## CLI examples
```bash
python cyberscan.py -p diagnostics
python cyberscan.py -s 192.168.1.1 -p tcp -d 80
python cyberscan.py -s 192.168.1.1 -p scan --report reports/scan.json
python cyberscan.py -f captures/capture.pcap --pcap tcp --report reports/pcap.csv
```

Active network checks accept private IPv4 targets only. Custom TCP port checks are
limited to 256 ports per run. Use only on networks/devices you own or are
explicitly authorized to assess. Scapy raw-packet features depend on OS, kernel,
permissions and network-interface support; root does not guarantee Android
monitor-mode support.

GeoIP is optional and approximate. Install `requirements-geoip.txt` and place a
licensed MaxMind `GeoLite2-City.mmdb` database beside the script.
