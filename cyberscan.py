#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
CyberScan GODMODE SAFE Edition
Python 3 | Termux | Kali NetHunter | Linux

A defensive network diagnostics and PCAP inspection utility.
Active network checks are restricted to private IPv4 targets.
Use only on systems and networks you own or are authorized to assess.
"""

from __future__ import annotations

import argparse
import concurrent.futures
import csv
import datetime as dt
import ipaddress
import json
import os
import platform
import socket
import sys
import time
from pathlib import Path
from typing import Any

VERSION = "3.0.0"
APP_NAME = "CYBERSCAN GODMODE"

COMMON_PORTS = {
    21: "FTP", 22: "SSH", 23: "TELNET", 25: "SMTP",
    53: "DNS", 80: "HTTP", 110: "POP3", 123: "NTP",
    135: "MS-RPC", 139: "NETBIOS", 143: "IMAP",
    443: "HTTPS", 445: "SMB", 587: "SMTP-SUBMISSION",
    993: "IMAPS", 995: "POP3S", 3306: "MYSQL",
    5432: "POSTGRESQL", 8000: "HTTP-ALT",
    8080: "HTTP-ALT", 8443: "HTTPS-ALT",
}

try:
    from colorama import Fore, Style, init
    init(autoreset=True)
    C = {
        "red": Fore.RED, "green": Fore.GREEN, "yellow": Fore.YELLOW,
        "cyan": Fore.CYAN, "white": Fore.WHITE, "reset": Style.RESET_ALL,
        "bold": Style.BRIGHT,
    }
except ImportError:
    C = {k: "" for k in ("red", "green", "yellow", "cyan", "white", "reset", "bold")}

def paint(text: str, color: str = "white") -> str:
    return f"{C.get(color, '')}{text}{C['reset']}"

def banner() -> None:
    print(paint(r"""
   ____          __              _____
  / ___|  _   _ / _| ___ _ __   / ____|__ _ _ __
  \___ \ | | | | |_ / _ \ '__| | |   / _` | '_ \
   ___) || |_| |  _|  __/ |    | |__| (_| | | | |
  |____/  \__, |_|  \___|_|     \_____\__,_|_| |_|
          |___/
""", "cyan"))
    print(paint(f"  {APP_NAME} v{VERSION}  |  DEFENSIVE EDITION", "bold"))
    print("-" * 62)

def require_private_ipv4(host: str) -> str:
    """Resolve a host and accept only private IPv4 addresses."""
    try:candidates = socket.getaddrinfo(host, None, socket.AF_INET, socket.SOCK_STREAM)
    except socket.gaierror as exc:
        raise ValueError(f"Hostname tidak dapat di-resolve: {host}") from exc

    addresses = sorted({item[4][0] for item in candidates})
    if not addresses:
        raise ValueError("Tidak ada alamat IPv4 yang ditemukan.")

        
    return candidates[0][4][0]

def local_info() -> dict[str, Any]:
    info: dict[str, Any] = {
        "platform": platform.platform(),
        "system": platform.system(),
        "machine": platform.machine(),
        "python": platform.python_version(),
        "hostname": socket.gethostname(),
        "effective_uid": os.geteuid() if hasattr(os, "geteuid") else None,
    }
    try:
        info["local_ip"] = socket.gethostbyname(socket.gethostname())
    except OSError:
        info["local_ip"] = "unavailable"
    try:
        import scapy.all  # noqa: F401
        info["scapy"] = "available"
    except ImportError:
        info["scapy"] = "not installed"
    try:
        import colorama  # noqa: F401
        info["colorama"] = "available"
    except ImportError:
        info["colorama"] = "not installed"
    try:
        import geoip2  # noqa: F401
        info["geoip2"] = "available"
    except ImportError:
        info["geoip2"] = "not installed"
    return info

def diagnostics() -> dict[str, Any]:
    data = local_info()
    print(paint("\n[ SYSTEM DIAGNOSTICS ]", "cyan"))
    for key, value in data.items():
        print(f"{key.replace('_', ' ').title():18}: {value}")
    if data["effective_uid"] is not None:
        print(f"{'Root privileges':18}: {'yes' if data['effective_uid'] == 0 else 'no'}")
    print(paint("\nNote: root access does not guarantee Android Wi-Fi monitor-mode support.", "yellow"))
    return data

def tcp_check(host: str, port: int, timeout: float = 2.0) -> dict[str, Any]:
    target = require_private_ipv4(host)
    if not 1 <= port <= 65535:
        raise ValueError("Port harus berada pada rentang 1-65535.")
    started = time.perf_counter()
    result: dict[str, Any] = {
        "target": target, "port": port,
        "service": COMMON_PORTS.get(port, "unknown"),
    }
    try:
        with socket.create_connection((target, port), timeout=timeout):
            result["status"] = "open"
    except ConnectionRefusedError:
        result["status"] = "closed"
    except (socket.timeout, TimeoutError):
        result["status"] = "filtered_or_timeout"
    except OSError as exc:
        result["status"] = "unreachable"
        result["error"] = str(exc)
    result["latency_ms"] = round((time.perf_counter() - started) * 1000, 2)
    return result

def port_check(host: str, start: int | None = None, end: int | None = None,
               timeout: float = 0.6, workers: int = 16) -> dict[str, Any]:
    target = require_private_ipv4(host)
    if start is None and end is None:
        ports = sorted(COMMON_PORTS)
        mode = "common"
    elif start is not None and end is not None:
        if not (1 <= start <= 65535 and 1 <= end <= 65535 and start <= end):
            raise ValueError(...)
        if end - start + 1 > 65535:
            raise ValueError(...)
        ports = list(range(start, end + 1))
        mode = "custom"
    else:
        raise ValueError("Isi start dan end port secara bersamaan.")

    workers  = 500 
    print(paint(f"\n[ TCP PORT CHECK ] {target} | {mode} | {len(ports)} ports", "cyan"))
    started = time.perf_counter()
    results: list[dict[str, Any]] = []

    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as pool:
        futures = {pool.submit(tcp_check, target, port, timeout): port for port in ports}
        for future in concurrent.futures.as_completed(futures):
            item = future.result()
            results.append(item)
            if item["status"] == "open":
                print(paint(
                    f"[OPEN] {item['port']:5}  {item['service']:<18} {item['latency_ms']} ms",
                    "green"
                ))

    results.sort(key=lambda item: item["port"])
    elapsed = round(time.perf_counter() - started, 2)
    opened = [item for item in results if item["status"] == "open"]
    print(f"\nCompleted in {elapsed}s | Open: {len(opened)} | Checked: {len(ports)}")
    if not opened:
        print(paint("No open TCP ports detected.", "yellow"))
    return {
        "tool": "tcp_port_check", "target": target, "mode": mode,
        "started_at": dt.datetime.now().astimezone().isoformat(),
        "duration_seconds": elapsed, "checked": len(ports),
        "open_count": len(opened), "results": results,
    }

def scapy_module():
    try:
        from scapy.all import ARP, Ether, ICMP, IP, UDP, sr1, srp, rdpcap
        return ARP, Ether, ICMP, IP, UDP, sr1, srp, rdpcap
    except ImportError as exc:
        raise RuntimeError("Scapy belum terpasang. Install: pip install scapy") from exc

def ping_check(host: str) -> dict[str, Any]:
    target = require_private_ipv4(host)
    _, _, ICMP, IP, _, sr1, _, _ = scapy_module()
    print(paint(f"\n[ ICMP CHECK ] {target}", "cyan"))
    try:
        reply = sr1(IP(dst=target) / ICMP(), timeout=3, verbose=False)
    except PermissionError as exc:
        raise RuntimeError("Izin raw socket ditolak. Periksa hak akses dan dukungan sistem.") from exc
    if reply:
        data = {"target": target, "status": "responded",
                "source": reply.src, "ttl": getattr(reply, "ttl", None)}
        print(paint(f"[+] Host responded from {reply.src}; TTL={data['ttl']}", "green"))
    else:
        data = {"target": target, "status": "no_response"}
        print(paint("[-] Tidak ada balasan ICMP; ini tidak selalu berarti host mati.", "yellow"))
    return data

def arp_check(host: str) -> dict[str, Any]:
    target = require_private_ipv4(host)
    ARP, Ether, _, _, _, _, srp, _ = scapy_module()
    print(paint(f"\n[ ARP CHECK ] {target}", "cyan"))
    try:
        answered, _ = srp(Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=target),
                          timeout=3, verbose=False)
    except PermissionError as exc:
        raise RuntimeError("Izin raw socket ditolak untuk ARP.") from exc
    devices = [{"ip": received.psrc, "mac": received.hwsrc}
               for _, received in answered]
    for device in devices:
        print(paint(f"[+] {device['ip']}  {device['mac']}", "green"))
    if not devices:
        print(paint("Tidak ada balasan ARP.", "yellow"))
    return {"target": target, "devices": devices}

def analyze_pcap(filename: str, layer: str = "all", limit: int = 5000) -> dict[str, Any]:
    *_, rdpcap = scapy_module()
    path = Path(filename).expanduser()
    if not path.is_file():
        raise FileNotFoundError(f"PCAP tidak ditemukan: {path}")
    if path.stat().st_size > 100 * 1024 * 1024:
        raise ValueError("Batas ukuran PCAP adalah 100 MB.")
    if not 1 <= limit <= 5000:
        raise ValueError("Batas analisis adalah 1-5000 paket.")
    packets = rdpcap(str(path), count=limit)
    try:
        from scapy.all import Ether, IP, TCP, UDP, ICMP
    except ImportError as exc:
        raise RuntimeError("Scapy tidak tersedia.") from exc

    counts = {"ethernet": 0, "ip": 0, "tcp": 0, "udp": 0, "icmp": 0}
    rows = []
    for index, packet in enumerate(packets, 1):
        if Ether in packet: counts["ethernet"] += 1
        if IP in packet: counts["ip"] += 1
        if TCP in packet: counts["tcp"] += 1
        if UDP in packet: counts["udp"] += 1
        if ICMP in packet: counts["icmp"] += 1

        matched = (
            layer == "all" or
            (layer == "eth" and Ether in packet) or
            (layer == "ip" and IP in packet) or
            (layer == "tcp" and TCP in packet) or
            (layer == "udp" and UDP in packet) or
            (layer == "icmp" and ICMP in packet)
        )
        if not matched:
            continue

        row: dict[str, Any] = {"packet": index, "summary": packet.summary()}
        if IP in packet:
            row.update({"src": packet[IP].src, "dst": packet[IP].dst})
        if TCP in packet:
            row.update({"protocol": "TCP", "sport": packet[TCP].sport,
                        "dport": packet[TCP].dport, "flags": str(packet[TCP].flags)})
        elif UDP in packet:
            row.update({"protocol": "UDP", "sport": packet[UDP].sport,
                        "dport": packet[UDP].dport})
        elif ICMP in packet:
            row.update({"protocol": "ICMP", "icmp_type": packet[ICMP].type})
        rows.append(row)

    print(paint(f"\n[ PCAP ANALYSIS ] {path.name}", "cyan"))
    print(f"Packets read: {len(packets)} (limit {limit})")
    for key, value in counts.items():
        print(f"{key.upper():10}: {value}")
    for row in rows[:30]:
        print(f"#{row['packet']:<5} {row['summary']}")
    if len(rows) > 30:
        print(f"... {len(rows) - 30} additional matching packets omitted from screen.")
    return {"file": str(path), "packets_read": len(packets),
            "layer_filter": layer, "counts": counts, "packets": rows}

def geoip_lookup(host: str, database: str) -> dict[str, Any]:
    try:
        import geoip2.database
    except ImportError as exc:
        raise RuntimeError("GeoIP opsional belum terpasang: pip install geoip2") from exc
    ip = socket.gethostbyname(host)
    path = Path(database).expanduser()
    if not path.is_file():
        raise FileNotFoundError(f"Database GeoIP tidak ditemukan: {path}")
    with geoip2.database.Reader(str(path)) as reader:
        record = reader.city(ip)
        data = {
            "ip": ip,
            "country": record.country.name,
            "city": record.city.name,
            "region": ", ".join(x.name for x in record.subdivisions),
            "latitude": record.location.latitude,
            "longitude": record.location.longitude,
            "timezone": record.location.time_zone,
            "notice": "GeoIP is approximate and is not an exact device location.",
        }
    print(paint("\n[ GEOIP ]", "cyan"))
    for key, value in data.items():
        print(f"{key.title():12}: {value}")
    return data

def save_report(data: dict[str, Any], filename: str) -> None:
    path = Path(filename).expanduser()
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.suffix.lower() == ".csv":
        rows = data.get("results") or data.get("packets")
        if not isinstance(rows, list) or not rows:
            raise ValueError("CSV hanya tersedia untuk hasil yang memiliki daftar baris.")
        keys = sorted({key for row in rows for key in row})
        with path.open("w", newline="", encoding="utf-8") as handle:
            writer = csv.DictWriter(handle, fieldnames=keys)
            writer.writeheader()
            writer.writerows(rows)
    else:
        path.write_text(json.dumps(data, indent=2, ensure_ascii=False, default=str),
                        encoding="utf-8")
    print(paint(f"[+] Report saved: {path}", "green"))

def interactive_menu() -> None:
    while True:
        banner()
        print("  1. System diagnostics")
        print("  2. TCP connectivity check")
        print("  3. Common TCP ports check")
        print("  4. ICMP check (Scapy)")
        print("  5. ARP check (Scapy)")
        print("  6. PCAP analysis")
        print("  7. GeoIP lookup (optional)")
        print("  0. Exit")
        choice = input("\nCyberScan > ").strip()
        try:
            if choice == "1":
                diagnostics()
            elif choice == "2":
                host = input("Private IPv4/hostname: ").strip()
                port = int(input("TCP port: ").strip())
                print(tcp_check(host, port))
            elif choice == "3":
                host = input("Private IPv4/hostname: ").strip()
                result = port_check(host)
                save_report(result, "reports/scan_report.json")
            elif choice == "4":
                ping_check(input("Private IPv4/hostname: ").strip())
            elif choice == "5":
                arp_check(input("Private IPv4/hostname: ").strip())
            elif choice == "6":
                filename = input("PCAP path: ").strip()
                result = analyze_pcap(filename)
                save_report(result, "reports/pcap_report.json")
            elif choice == "7":
                host = input("IP/hostname: ").strip()
                geoip_lookup(host, "GeoLite2-City.mmdb")
            elif choice == "0":
                print("Bye.")
                return
            else:
                print(paint("Pilihan tidak dikenal.", "yellow"))
        except (ValueError, OSError, RuntimeError) as exc:
            print(paint(f"[ERROR] {exc}", "red"))
        input("\nTekan Enter untuk kembali ke menu...")

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=f"{APP_NAME} v{VERSION} - defensive network diagnostics"
    )
    parser.add_argument("--version", action="version", version=VERSION)
    parser.add_argument("--menu", action="store_true", help="Buka menu interaktif")
    parser.add_argument("-p", "--level",
        choices=["diagnostics", "tcp", "scan", "icmp", "arp", "geoip"])
    parser.add_argument("-s", "--server", "--serveur", dest="server")
    parser.add_argument("-d", "--sport", type=int, help="TCP port / start port")
    parser.add_argument("-t", "--eport", type=int, help="End port")
    parser.add_argument("-f", "--file", help="PCAP file")
    parser.add_argument("--pcap", choices=["all", "eth", "ip", "tcp", "udp", "icmp"],
                        default="all")
    parser.add_argument("--geoip-db", default="GeoLite2-City.mmdb")
    parser.add_argument("--report", help="Simpan hasil ke .json atau .csv")
    return parser

def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    banner()
    try:
        result = None
        if args.menu or (not args.level and not args.file):
            interactive_menu()
            return 0
        if args.file:
            result = analyze_pcap(args.file, args.pcap)
        elif args.level == "diagnostics":
            result = diagnostics()
        elif args.level == "tcp" and args.server:
            result = tcp_check(args.server, args.sport or 80)
            print(result)
        elif args.level == "scan" and args.server:
            result = port_check(args.server, args.sport, args.eport)
        elif args.level == "icmp" and args.server:
            result = ping_check(args.server)
        elif args.level == "arp" and args.server:
            result = arp_check(args.server)
        elif args.level == "geoip" and args.server:
            result = geoip_lookup(args.server, args.geoip_db)
        else:
            parser.print_help()
            return 2
        if args.report and result is not None:
            save_report(result, args.report)
        return 0
    except KeyboardInterrupt:
        print(paint("\n[!] Dibatalkan pengguna.", "yellow"))
        return 130
    except (ValueError, OSError, RuntimeError) as exc:
        print(paint(f"\n[ERROR] {exc}", "red"))
        return 1

if __name__ == "__main__":
    raise SystemExit(main())
