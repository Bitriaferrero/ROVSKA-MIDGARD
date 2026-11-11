#!/usr/bin/env python3
"""Descubre la LAN en modo solo lectura y genera el mapa visual.

No usa credenciales: ARP (arp-scan) + fingerprint de puertos (nmap).
Uso:  python3 netmap.py [--iface wlan0]
"""
import argparse
import json
import re
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

ROOT = Path(__file__).resolve().parent
KALI = "rovska-kali"


def run(cmd, timeout=180):
    try:
        return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    except (subprocess.TimeoutExpired, FileNotFoundError) as exc:
        return subprocess.CompletedProcess(cmd, 1, "", str(exc))


def arp_scan(iface):
    res = run(["docker", "exec", KALI, "arp-scan", "--interface", iface, "--localnet"], 180)
    hosts = {}
    for line in res.stdout.splitlines():
        match = re.match(
            r"^(\d+\.\d+\.\d+\.\d+)\s+([0-9a-f:]{17})\s+(.*)$", line.strip(), re.I
        )
        if not match:
            continue
        ip, mac, vendor = match.group(1), match.group(2).lower(), match.group(3).strip()
        if ip not in hosts:
            hosts[ip] = {"ip": ip, "mac": mac, "vendor": vendor, "ports": [], "latency_ms": None}
    if not hosts:  # fallback sin contenedor
        res = run(["ip", "neigh", "show", "dev", iface], 10)
        for line in res.stdout.splitlines():
            match = re.match(r"^(\d+\.\d+\.\d+\.\d+)\s+.*lladdr\s+([0-9a-f:]{17})", line, re.I)
            if match and match.group(1) not in hosts:
                hosts[match.group(1)] = {
                    "ip": match.group(1), "mac": match.group(2).lower(),
                    "vendor": "", "ports": [], "latency_ms": None,
                }
    return hosts


def ping(ip):
    res = run(["ping", "-c1", "-W1", "-n", ip], 5)
    match = re.search(r"time=([\d.]+)", res.stdout)
    return round(float(match.group(1)), 2) if match else None


def nmap(ip):
    res = run(
        ["nmap", "-Pn", "-n", "-T4", "--top-ports", "200", "-sV", "--version-light", ip],
        150,
    )
    ports = []
    for line in res.stdout.splitlines():
        match = re.match(r"^(\d+)/(tcp|udp)\s+open\s+(\S+)", line)
        if match:
            ports.append(f"{match.group(1)}/{match.group(3)}")
    return ports


def ssid(iface):
    res = run(["iw", "dev", iface, "link"], 10)
    match = re.search(r"SSID:\s*(.+)", res.stdout)
    return match.group(1).strip() if match else None


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--iface", default="wlan0")
    args = parser.parse_args()

    hosts = arp_scan(args.iface)
    print(f"[+] {len(hosts)} dispositivos por ARP")

    def enrich(host):
        host["latency_ms"] = ping(host["ip"])
        host["ports"] = nmap(host["ip"])

    with ThreadPoolExecutor(max_workers=8) as pool:
        list(pool.map(enrich, hosts.values()))

    data = {
        "ssid": ssid(args.iface),
        "generated": __import__("datetime").datetime.now().isoformat(timespec="seconds"),
        "hosts": sorted(hosts.values(), key=lambda h: tuple(int(p) for p in h["ip"].split("."))),
        "notes": (
            "Descubrimiento solo lectura: ARP + sondeo de puertos. Sin SNMP ni credenciales. "
            "Los equipos que filtran ICMP pueden aparecer sin latencia; los que filtran ARP no aparecen. "
            "El mapa L2 real (switches, VLAN, LLDP) requiere SNMP de solo lectura en los equipos."
        ),
    }
    (ROOT / "map").mkdir(exist_ok=True)
    json_path = ROOT / "map" / "scan.json"
    json_path.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")
    subprocess.run(
        [sys.executable, str(ROOT / "mapgen.py"), str(json_path), str(ROOT / "map" / "index.html")],
        check=True,
    )
    for host in data["hosts"]:
        print(f"    {host['ip']:<15} {host['vendor'][:28]:<28} {','.join(host['ports']) or '-'}")


if __name__ == "__main__":
    raise SystemExit(main())
