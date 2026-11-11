#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Motor de análisis: convierte puertos y salidas de herramientas en hallazgos.

Combina reglas heurísticas (exposición, versiones EOL, configuraciones débiles)
con los hallazgos ya normalizados por cada adaptador, elimina duplicados y
enriquece cada resultado con ATT&CK, PTES, OSSTMM, OWASP y CWE.
"""

from __future__ import annotations

import html
import re
from datetime import datetime

from . import attack, frameworks
from .models import (
    Finding,
    Host,
    SEV_ORDER,
    SEV_WEIGHT,
    counts_by_severity,
    merge_findings,
    normalize_severity,
    risk_meta,
)


PORT_RULES: dict[int, tuple[str, str, str, str]] = {
    21: ("BAJO", "FTP expuesto", "Servicio FTP accesible desde la red.", "Restringir FTP a la LAN de gestión, usar SFTP y deshabilitar cuentas anónimas."),
    23: ("ALTO", "Telnet expuesto", "Telnet transmite credenciales en claro.", "Deshabilitar Telnet y usar SSH."),
    111: ("MEDIO", "rpcbind expuesto", "rpcbind permite enumerar servicios RPC.", "Filtrar TCP/UDP 111 y limitar NFS a la LAN de gestión."),
    135: ("MEDIO", "RPC de Windows expuesto", "El endpoint mapper de Windows es accesible.", "Filtrar 135 en el perímetro y segmentar la red."),
    139: ("ALTO", "SMB expuesto", "SMB (NetBIOS) accesible desde la red.", "Filtrar 139/445, exigir SMB3 y firmado, y revisar recursos compartidos."),
    445: ("ALTO", "SMB expuesto", "SMB accesible desde la red.", "Filtrar 139/445, exigir SMB3 y firmado, y revisar recursos compartidos."),
    512: ("CRÍTICO", "rexec expuesto", "Servicio rexec heredado y sin cifrado.", "Deshabilitar rexec y usar SSH."),
    513: ("CRÍTICO", "rlogin expuesto", "Servicio rlogin heredado y sin cifrado.", "Deshabilitar rlogin y usar SSH."),
    514: ("CRÍTICO", "rsh expuesto", "Servicio rsh heredado y sin cifrado.", "Deshabilitar rsh y usar SSH."),
    873: ("MEDIO", "rsync expuesto", "rsync puede permitir listar o copiar ficheros.", "Exigir autenticación, limitar módulos y filtrar el puerto."),
    1080: ("ALTO", "Proxy SOCKS expuesto", "Proxy SOCKS abierto que puede usarse para pivotar.", "Exigir autenticación y filtrar el puerto."),
    1433: ("ALTO", "SQL Server expuesto", "Base de datos Microsoft SQL Server accesible.", "Filtrar 1433, exigir autenticación fuerte y cifrado TLS."),
    1521: ("ALTO", "Oracle Database expuesto", "Listener Oracle accesible.", "Filtrar 1521 y restringir a la red de aplicación."),
    2049: ("ALTO", "NFS expuesto", "NFS puede exponer sistemas de ficheros.", "Limitar exports por IP, usar NFSv4 con Kerberos y filtrar 2049."),
    2375: ("CRÍTICO", "Docker API sin TLS expuesta", "La API de Docker permite control total del host.", "Deshabilitar 2375, usar TLS mutuo en 2376 y filtrar a localhost."),
    2376: ("ALTO", "Docker API expuesta", "La API de Docker es accesible por red.", "Exigir TLS mutuo, autenticación y filtrar el puerto."),
    3128: ("MEDIO", "Proxy HTTP expuesto", "Proxy Squid/HTTP accesible.", "Exigir autenticación, limitar ACL y filtrar el puerto."),
    3306: ("ALTO", "MySQL/MariaDB expuesto", "Base de datos MySQL/MariaDB accesible.", "Filtrar 3306, crear usuarios por host y exigir TLS."),
    3389: ("ALTO", "RDP expuesto", "Escritorio remoto accesible desde la red.", "Filtrar 3389, exigir NLA/MFA y limitar a VPN."),
    4008: ("ALTO", "CPE/TR-069 expuesto", "Gestión remota de CPE expuesta.", "Deshabilitar CWMP en WAN o exigir ACS autenticado."),
    5432: ("ALTO", "PostgreSQL expuesto", "Base de datos PostgreSQL accesible.", "Filtrar 5432, usar pg_hba.conf restrictivo y TLS."),
    5601: ("ALTO", "Kibana expuesto", "Kibana puede exponer datos y paneles.", "Exigir autenticación, TLS y filtrar el puerto."),
    5900: ("ALTO", "VNC expuesto", "VNC accesible, a menudo sin cifrado fuerte.", "Filtrar 5900, usar túnel SSH y contraseña robusta."),
    5985: ("ALTO", "WinRM expuesto", "WinRM permite ejecución remota en Windows.", "Filtrar 5985/5986, exigir HTTPS y autenticación fuerte."),
    5986: ("ALTO", "WinRM TLS expuesto", "WinRM sobre HTTPS accesible.", "Filtrar 5986 y limitar a hosts de administración."),
    6379: ("CRÍTICO", "Redis expuesto", "Redis suele no tener autenticación y permite RCE.", "Exigir requirepass/ACL, bind a localhost y filtrar 6379."),
    6443: ("ALTO", "API de Kubernetes expuesta", "La API del clúster es accesible.", "Restringir 6443, exigir RBAC y autenticación fuerte."),
    8006: ("MEDIO", "Interfaz Proxmox expuesta", "La UI/API de Proxmox VE es accesible.", "Restringir 8006 a la LAN de gestión, exigir MFA y revisar versiones."),
    8112: ("MEDIO", "Deluge Web expuesto", "La UI de Deluge es accesible por HTTP.", "Exigir login, usar HTTPS y filtrar el puerto."),
    9042: ("ALTO", "Cassandra expuesta", "Cassandra accesible desde la red.", "Filtrar 9042, exigir autenticación y TLS."),
    9080: ("ALTO", "Promtail expuesto", "La UI/config de Promtail puede no tener autenticación.", "Detener Promtail o migrar a Grafana Alloy; filtrar 9080."),
    9200: ("CRÍTICO", "Elasticsearch expuesto", "Elasticsearch puede permitir lectura/escritura sin autenticación.", "Exigir autenticación, TLS y filtrar 9200."),
    9221: ("ALTO", "pve-exporter expuesto", "pve-exporter expone métricas del clúster Proxmox.", "Escuchar en localhost, filtrar 9221 o usar reverse proxy autenticado."),
    9300: ("ALTO", "Elasticsearch transporte expuesto", "El puerto de transporte de Elasticsearch es accesible.", "Filtrar 9300 a los nodos del clúster."),
    10000: ("MEDIO", "Webmin expuesto", "Webmin es accesible por red.", "Restringir 10000, exigir MFA y actualizar."),
    10250: ("CRÍTICO", "Kubelet expuesto", "Kubelet permite ejecución en nodos si no está protegido.", "Deshabilitar acceso anónimo, exigir authn/authz y filtrar 10250."),
    11211: ("CRÍTICO", "Memcached expuesto", "Memcached no tiene autenticación y puede amplificar DDoS.", "Filtrar 11211, bind a localhost y deshabilitar UDP."),
    15672: ("ALTO", "RabbitMQ Management expuesto", "La consola de gestión de RabbitMQ es accesible.", "Exigir autenticación, TLS y filtrar 15672."),
    27017: ("CRÍTICO", "MongoDB expuesto", "MongoDB puede permitir acceso sin autenticación.", "Exigir autenticación, bind a localhost y filtrar 27017."),
}


PORT_TAGS = {
    21: ["ftp"], 23: ["telnet"], 111: ["rpc"], 135: ["rpc"], 139: ["smb"],
    445: ["smb"], 512: ["r-services"], 513: ["r-services"], 514: ["r-services"],
    1433: ["database"], 1521: ["database"], 2049: ["nfs"], 2375: ["docker"],
    2376: ["docker"], 3306: ["database"], 3389: ["rdp"], 4008: ["cpe"],
    5432: ["database"], 5900: ["vnc"], 5985: ["winrm"], 5986: ["winrm"],
    6379: ["database", "redis"], 6443: ["kubernetes"], 8006: ["proxmox"],
    8112: ["deluge"], 9042: ["database"], 9080: ["promtail"], 9200: ["database"],
    9221: ["proxmox"], 9300: ["database"], 10000: ["webmin"], 10250: ["kubernetes"],
    11211: ["memcached"], 15672: ["rabbitmq"], 27017: ["database", "mongodb"],
}


DB_PORTS = {1433, 1521, 3306, 5432, 6379, 9042, 9200, 9300, 11211, 27017}
REMOTE_PORTS = {22, 23, 139, 445, 3389, 5900, 5985, 5986}


def analyze(
    hosts: list[Host],
    tool_findings: list[Finding] | None = None,
    tool_good: list[str] | None = None,
    proxmox: dict | None = None,
) -> dict:
    findings: list[Finding] = list(tool_findings or [])
    good: list[str] = list(tool_good or [])
    proxmox = proxmox or {}

    for host in hosts:
        classify_host(host)
        _port_rules(host, findings)
        _version_rules(host, findings, good)
        _http_rules(host, findings)
        _script_rules(host, findings, good)

    _global_good_checks(hosts, good, proxmox)
    findings = merge_findings(findings)
    for item in findings:
        frameworks.enrich(item)
        if not item.attack:
            item.attack = attack.techniques_for_finding(item)

    counts = counts_by_severity(findings)
    per_host: dict[str, dict] = {}
    for host in hosts:
        host_findings = [f for f in findings if f.host == host.ip]
        host_counts = counts_by_severity(host_findings)
        score = min(100, sum(SEV_WEIGHT.get(f.severity, 0) for f in host_findings))
        host.extra["risk"] = score
        host.extra["risk_meta"] = risk_meta(score, host_counts, len(host_findings))
        host.extra["severity_counts"] = host_counts
        per_host[host.ip] = {
            "risk": score,
            "risk_meta": host.extra["risk_meta"],
            "counts": host_counts,
            "findings": len(host_findings),
        }

    return {
        "findings": findings,
        "good_checks": sorted(set(good)),
        "counts": counts,
        "per_host": per_host,
        "proxmox": proxmox,
    }


UBUNTU_OPENSSH = {
    "7.2p2": "16.04", "7.6p1": "18.04", "8.2p1": "20.04",
    "8.9p1": "22.04", "9.6p1": "24.04",
    "9.9p1": "25.04/25.10 (interim)",
}
DEBIAN_OPENSSH = {
    "6.7p1": "8", "7.4p1": "9", "7.9p1": "10",
    "8.4p1": "11", "9.2p1": "12", "9.7p1": "12",
}
APACHE_UBUNTU = {"2.4.18": "16.04", "2.4.29": "18.04", "2.4.41": "20.04", "2.4.52": "22.04", "2.4.58": "24.04"}
NGINX_UBUNTU = {"1.10.3": "16.04", "1.14.0": "18.04", "1.18.0": "20.04/22.04", "1.24.0": "24.04"}
APACHE_DEBIAN = {"2.4.10": "9", "2.4.25": "9", "2.4.38": "10", "2.4.56": "11", "2.4.62": "12"}
NGINX_DEBIAN = {"1.6.2": "8", "1.10.3": "9", "1.14.2": "10", "1.18.0": "11", "1.22.1": "12"}
WINDOWS_BUILDS = {
    "7601": "Windows 7 SP1",
    "9600": "Windows 8.1",
    "14393": "Windows Server 2016 / 10 1607",
    "17763": "Windows Server 2019 / 10 1809",
    "19041": "Windows 10 2004",
    "19042": "Windows 10 20H2",
    "19043": "Windows 10 21H1",
    "19044": "Windows 10 21H2",
    "19045": "Windows 10 22H2",
    "20348": "Windows Server 2022",
    "22000": "Windows 11 21H2",
    "22621": "Windows 11 22H2",
    "22631": "Windows 11 23H2",
    "26100": "Windows 11 24H2",
}
ANDROID_VENDORS = {
    "samsung": "Samsung", "xiaomi": "Xiaomi", "huawei": "Huawei",
    "oneplus": "OnePlus", "oppo": "OPPO", "vivo": "vivo",
    "motorola": "Motorola", "lg electronics": "LG", "sony": "Sony",
    "google": "Google", "realme": "realme", "nothing": "Nothing",
    "fairphone": "Fairphone", "tcl": "TCL",
}

DEVICE_VENDOR_HINTS = {
    "raspberry pi": "Raspberry Pi OS (Linux)",
    "espressif": "Dispositivo IoT (ESP32/ESP8266)",
    "tuya": "Dispositivo IoT",
    "shelly": "Dispositivo IoT",
    "synology": "Synology DSM (Linux)",
    "qnap": "QNAP QTS (Linux)",
    "vmware": "VMware ESXi",
    "qemu": "Máquina virtual (QEMU/KVM)",
    "virtualbox": "Máquina virtual (VirtualBox)",
    "sonos": "Sonos (Linux)",
    "roku": "Roku OS",
    "amazon": "Amazon Fire OS / Android",
    "brother": "Impresora en red",
    "canon": "Impresora en red",
    "epson": "Impresora en red",
    "xerox": "Impresora en red",
}

PC_VENDOR_HINTS = {
    "hewlett packard": "PC / servidor HP",
    "hp inc": "PC / servidor HP",
    "dell": "PC / servidor Dell",
    "lenovo": "PC / servidor Lenovo",
    "lcfc": "PC Lenovo (LCFC)",
    "asustek": "PC ASUS",
    "micro-star": "PC MSI",
    "gigabyte": "PC Gigabyte",
    "intel": "PC Intel",
    "acer": "PC Acer",
}

# Prefijos MAC que delatan una máquina virtual. No dependen de que nmap
# conozca el OUI: los rangos locales (QEMU, Xen, Hyper-V...) no siempre
# aparecen en su base de datos.
PROXMOX_GUEST_MACS = ("bc:24:11",)
VM_MAC_PREFIXES = {
    "52:54:00": "QEMU/KVM",
    "00:0c:29": "VMware",
    "00:50:56": "VMware",
    "00:05:69": "VMware",
    "08:00:27": "VirtualBox",
    "00:15:5d": "Hyper-V",
    "00:16:3e": "Xen",
}


def _vm_label(mac: str) -> str:
    value = (mac or "").lower().replace("-", ":")
    for prefix, label in VM_MAC_PREFIXES.items():
        if value.startswith(prefix):
            return label
    return ""


def _os_family(name: str) -> str:
    low = (name or "").lower()
    if "mikrotik" in low or "routeros" in low:
        return "mikrotik"
    for key in ("ubuntu", "debian", "windows", "macos", "mac os", "android", "linux"):
        if key in low:
            return "macos" if key == "mac os" else key
    return ""


def _host_text(host: Host) -> str:
    parts = [host.os, host.vendor, " ".join(host.hostnames)]
    for port in host.ports:
        parts += [port.service, port.product, port.version, port.extrainfo]
        parts += list((port.scripts or {}).values())
    parts += list((host.hostscripts or {}).values())
    return "\n".join(p for p in parts if p)


def refine_os(host: Host) -> None:
    """Ajusta el SO con banners cuando `-O` solo da la familia/kernel.

    No sustituye un dato más concreto por uno más genérico.
    """
    current = (host.os or "").strip()
    text = _host_text(host)
    low = text.lower()
    candidate = ""

    # Mismo criterio que MIDGARD: la versión exacta de un servicio RouterOS
    # ("MikroTik router ftpd 6.49.23") manda sobre la rama aproximada del
    # `osmatch` de nmap ("RouterOS 6.19").
    routeros = ""
    for port in host.ports:
        blob = f"{port.product} {port.version} {port.extrainfo} {port.service}"
        if not re.search(r"mikrotik|routerboard|routeros|\brossh\b", blob, re.I):
            continue
        exact = re.search(
            r"\b([0-9]+\.[0-9]+(?:\.[0-9]+)+)\b", port.version or ""
        ) or re.search(r"\b([0-9]+\.[0-9]+(?:\.[0-9]+)+)\b", blob)
        if exact:
            routeros = exact.group(1)
            break
    if routeros:
        candidate = f"MikroTik RouterOS {routeros}"
    else:
        match = re.search(r"RouterOS(?:\s+\S+)?\s+([0-9]+(?:\.[0-9]+)+)", text, re.I)
        if match:
            candidate = f"MikroTik RouterOS {match.group(1)}"
        else:
            # El banner SSH de RouterOS es "ROSSH <versión>".
            match = re.search(r"\bROSSH[\s_-]+([0-9]+(?:\.[0-9]+)+)", text, re.I)
            if match:
                candidate = f"MikroTik RouterOS {match.group(1)}"
            elif re.search(r"mikrotik|routerboard|routeros|\brossh\b", low):
                candidate = "MikroTik RouterOS"

    if not candidate:
        match = re.search(r"OpenSSH[_\s-]([0-9][0-9A-Za-z.]*p\d+)", text, re.I)
        if match and "ubuntu" in low:
            version = UBUNTU_OPENSSH.get(match.group(1), "")
            candidate = f"Ubuntu {version}".strip()
        if not candidate:
            match = re.search(r"Ubuntu[- ](\d{2}\.\d{2})", text, re.I)
            if match:
                candidate = f"Ubuntu {match.group(1)}"
        if not candidate:
            match = re.search(r"(Apache|nginx)/([0-9.]+)[^\n]*\(Ubuntu\)", text, re.I)
            if match:
                table = APACHE_UBUNTU if match.group(1).lower() == "apache" else NGINX_UBUNTU
                version = table.get(match.group(2), "")
                candidate = f"Ubuntu {version}".strip()

        if not candidate:
            match = re.search(r"OpenSSH[_\s-]([0-9][0-9A-Za-z.]*p\d+)", text, re.I)
            if match and "debian" in low:
                direct = re.search(r"deb(\d+)u", text, re.I)
                version = direct.group(1) if direct else DEBIAN_OPENSSH.get(match.group(1), "")
                candidate = f"Debian {version}".strip()
        if not candidate:
            match = re.search(r"(Apache|nginx)/([0-9.]+)[^\n]*\(Debian\)", text, re.I)
            if match:
                table = APACHE_DEBIAN if match.group(1).lower() == "apache" else NGINX_DEBIAN
                version = table.get(match.group(2), "")
                candidate = f"Debian {version}".strip()

        if not candidate:
            match = re.search(r"Windows[^\n]*?\b(\d{5})\b", text, re.I)
            if match and match.group(1) in WINDOWS_BUILDS:
                candidate = WINDOWS_BUILDS[match.group(1)]
        if not candidate:
            match = re.search(r"Windows\s+(11|10|8\.1|8|7|Server\s+20\d{2})", text, re.I)
            if match:
                candidate = f"Windows {match.group(1)}"

        if not candidate:
            match = re.search(r"(?:Apple\s+)?(?:macOS|Mac OS X)\s*([0-9][0-9.]*)?", text, re.I)
            if match:
                candidate = f"macOS {match.group(1) or ''}".strip()

        if not candidate:
            for key, label in ANDROID_VENDORS.items():
                if key in (host.vendor or "").lower():
                    candidate = f"Android ({label})"
                    break

        weak = not current or current.lower().startswith("so desconocido")
        if not candidate and weak:
            vendor = (host.vendor or "").lower()
            for key, label in DEVICE_VENDOR_HINTS.items():
                if key in vendor:
                    candidate = label
                    break

        if not candidate and weak:
            ttl = int((host.extra or {}).get("ttl") or 0)
            if ttl > 0:
                initial = 64 if ttl <= 64 else 128 if ttl <= 128 else 255
                candidate = {
                    64: "Linux / Unix (TTL 64)",
                    128: "Windows (TTL 128)",
                    255: "Dispositivo de red (TTL 255)",
                }[initial]

        if not candidate and weak:
            vendor = (host.vendor or "").lower()
            for key, label in PC_VENDOR_HINTS.items():
                if key in vendor:
                    candidate = label
                    break

    if not candidate:
        return
    current_family = _os_family(current)
    candidate_family = _os_family(candidate)
    replace = (
        not current
        or current.lower().startswith("so desconocido")
        or current_family == candidate_family and len(candidate) > len(current)
        or current_family in {"", "linux", "unix", "windows", "macos"}
    )
    if replace and candidate.lower() != current.lower():
        host.os = candidate


def os_from_sysdescr(value: str) -> str:
    """Convierte el sysDescr de SNMP en un nombre de SO legible."""
    text = (value or "").strip()
    if not text:
        return ""
    match = re.search(r"RouterOS(?:\s+\S+)?\s+([0-9]+(?:\.[0-9]+)+)", text, re.I)
    if match:
        return f"MikroTik RouterOS {match.group(1)}"
    if re.search(r"mikrotik|routeros", text, re.I):
        return "MikroTik RouterOS"
    match = re.search(r"Windows[^,;]*", text, re.I)
    if match:
        return match.group(0).strip()[:60]
    match = re.search(r"Linux\s+\S+\s+([0-9][\w.\-]*)", text, re.I)
    if match:
        return f"Linux {match.group(1)}"
    match = re.search(r"(FreeBSD|OpenBSD|Cisco IOS|Junos)[^,;]*", text, re.I)
    if match:
        return match.group(0).strip()[:60]
    return ""


def classify_host(host: Host) -> None:
    refine_os(host)
    ports = {p.port for p in host.ports}
    text = " ".join(
        [host.os, host.vendor, " ".join(host.hostnames)]
        + [f"{p.product} {p.version} {p.service}" for p in host.ports]
    ).lower()
    mac = (host.mac or "").lower().replace("-", ":")
    vm = _vm_label(mac)

    if 8006 in ports or "proxmox" in text or "pve" in text:
        host.type = "Nodo Proxmox"
        if not host.os or host.os.lower().startswith(("so desconocido", "linux", "unix")):
            host.os = "Debian + Proxmox VE"
        elif "proxmox" not in host.os.lower():
            host.os = f"{host.os} + Proxmox VE"
    elif mac.startswith(PROXMOX_GUEST_MACS):
        host.type = "Guest Proxmox (LXC/VM)"
        if not host.os or host.os.lower().startswith(("so desconocido", "linux", "unix")):
            host.os = "Linux (invitado Proxmox)"
    elif "lxc" in text or "lxd" in text:
        host.type = "LXC"
        if not host.os or host.os.lower().startswith("so desconocido"):
            host.os = "Linux (LXC)"
    elif any(k in text for k in ("mikrotik", "routeros", "zte", "cisco", "huawei", "tp-link", "routerboard")):
        host.type = "Router"
        if "mikrotik" in text or "routeros" in text:
            if not host.os or host.os.lower().startswith(("linux", "so desconocido")):
                host.os = "MikroTik RouterOS"
        elif "zte" in text:
            host.os = host.os or "ZTE (router/CPE)"
        elif "cisco" in text:
            host.os = host.os or "Cisco IOS"
    elif any(k in text for k in ("windows", "microsoft", "smb")):
        host.type = "Servidor / servicio"
        host.os = host.os or "Windows"
    elif any(k in text for k in ("linux", "ubuntu", "debian", "centos", "red hat", "alpine")):
        host.type = "Servidor / servicio"
        host.os = host.os or "Linux"
    elif ports:
        host.type = "Servidor / servicio"
        host.os = host.os or "SO desconocido"
    else:
        host.type = "Dispositivo"
        host.os = host.os or "SO desconocido"

    if vm and host.type in {"Servidor / servicio", "Dispositivo", "Cliente / IoT"}:
        host.type = f"Máquina virtual ({vm})"
        low_os = (host.os or "").lower()
        if not host.os or low_os.startswith("so desconocido"):
            host.os = f"Linux (VM {vm})"
        elif low_os.startswith(("linux", "unix")):
            host.os = f"{host.os} (VM {vm})"

    if host.hostnames and not host.os:
        host.os = "SO desconocido"


def _add(
    findings: list[Finding],
    severity: str,
    title: str,
    host: str,
    evidence: str,
    recommendation: str,
    *,
    cves: list[str] | None = None,
    cwe: list[str] | None = None,
    tags: list[str] | None = None,
    source: str = "heuristic",
    confidence: str = "media",
) -> None:
    findings.append(
        Finding(
            severity=normalize_severity(severity),
            title=title,
            host=host,
            evidence=evidence,
            recommendation=recommendation,
            cves=cves or [],
            cwe=cwe or [],
            tags=tags or [],
            source=source,
            confidence=confidence,
        )
    )


def _port_rules(host: Host, findings: list[Finding]) -> None:
    for port in host.ports:
        rule = PORT_RULES.get(port.port)
        if rule:
            severity, title, evidence, recommendation = rule
            _add(
                findings,
                severity,
                title,
                host.ip,
                f"{host.ip}:{port.port}/{port.proto} abierto"
                + (f" ({port.service_str})" if port.service_str else "")
                + f". {evidence}",
                recommendation,
                tags=["exposure"] + PORT_TAGS.get(port.port, []),
                source="heuristic",
                confidence="alta",
            )
        if port.port not in {80, 443, 8080, 8443, 8000, 8006, 8081, 8888} and port.service in {"http", "https"}:
            _add(
                findings,
                "INFO",
                "Servicio web en puerto no estándar",
                host.ip,
                f"{host.ip}:{port.port} sirve {port.service}.",
                "Revisar si el servicio debe ser accesible y documentarlo.",
                tags=["web", "info-disclosure"],
                source="heuristic",
                confidence="media",
            )


def _version_rules(host: Host, findings: list[Finding], good: list[str]) -> None:
    for port in host.ports:
        text = f"{port.product} {port.version} {port.extrainfo}".strip()
        low = text.lower()
        if not low:
            continue

        if "openssh" in low:
            version = _version_tuple(text, r"OpenSSH[_\s]?([\d.]+)")
            ubuntu_build = re.search(r"(3ubuntu[\d.]+)", text)
            patched = False
            if ubuntu_build:
                patched = _build_at_least(ubuntu_build.group(1), "3ubuntu0.10")
            if version and version < (9, 8) and not patched:
                _add(
                    findings,
                    "ALTO",
                    "OpenSSH vulnerable a regreSSHion",
                    host.ip,
                    f"{host.ip}:{port.port} → {text}. Build anterior al parche de regreSSHion.",
                    "Actualizar openssh-server (>= 9.8 o build 3ubuntu0.10) y reiniciar sshd.",
                    cves=["CVE-2024-6387"],
                    cwe=["CWE-362"],
                    tags=["ssh", "vuln-scan"],
                    source="heuristic",
                    confidence="alta",
                )
            elif version and version < (8, 0):
                _add(
                    findings,
                    "MEDIO",
                    "OpenSSH desactualizado",
                    host.ip,
                    f"{host.ip}:{port.port} → {text}.",
                    "Actualizar OpenSSH a una versión soportada.",
                    tags=["ssh", "outdated"],
                    source="heuristic",
                    confidence="media",
                )
            else:
                good.append(f"{host.ip}: OpenSSH {port.version or version} incluye el parche de regreSSHion.")

        if "bind" in low and re.search(r"9\.(11|16|18)", low):
            branch = re.search(r"9\.(11|16|18)", low)
            eol = branch.group(0) if branch else "9.x"
            _add(
                findings,
                "ALTO",
                f"BIND {eol} EOL y potencialmente vulnerable",
                host.ip,
                f"{host.ip}:{port.port} → {text}. Rama {eol} fuera de soporte.",
                "Actualizar BIND a una rama soportada, desactivar recursión en WAN y revisar CVEs.",
                cves=["CVE-2025-13878", "CVE-2026-1519", "CVE-2026-3039"],
                cwe=["CWE-1104"],
                tags=["dns", "outdated", "vuln-scan"],
                source="heuristic",
                confidence="media",
            )

        if "proxmox" in low or port.port == 8006:
            version = _version_tuple(text, r"(\d+\.\d+(?:\.\d+)?)")
            if version and version[0] == 8:
                _add(
                    findings,
                    "MEDIO",
                    "Proxmox VE 8.x cerca de fin de soporte",
                    host.ip,
                    f"{host.ip}:{port.port} → Proxmox {'.'.join(map(str, version))}.",
                    "Planificar la actualización a Proxmox VE 9.x y revisar el ciclo de vida oficial.",
                    cwe=["CWE-1104"],
                    tags=["proxmox", "outdated"],
                    source="heuristic",
                    confidence="media",
                )

        if "promtail" in low or port.port == 9080:
            _add(
                findings,
                "ALTO",
                "Promtail EOL y sin autenticación",
                host.ip,
                f"{host.ip}:{port.port} → {text or 'Promtail'}. Promtail 2.x está EOL.",
                "Detener Promtail, migrar a Grafana Alloy y filtrar el puerto 9080.",
                cwe=["CWE-1104", "CWE-306"],
                tags=["promtail", "outdated", "exposure"],
                source="heuristic",
                confidence="alta",
            )

        if "zte" in low and ("http" in low or port.port == 80):
            _add(
                findings,
                "ALTO",
                "Router ZTE con firmware/servidor web antiguo",
                host.ip,
                f"{host.ip}:{port.port} → {text}.",
                "Actualizar el firmware del router, cambiar credenciales por defecto y desactivar gestión WAN.",
                cwe=["CWE-1104"],
                tags=["router", "outdated"],
                source="heuristic",
                confidence="media",
            )

        if "vsftpd 2.3.4" in low:
            _add(
                findings,
                "CRÍTICO",
                "vsftpd 2.3.4 con backdoor",
                host.ip,
                f"{host.ip}:{port.port} → {text}.",
                "Sustituir vsftpd 2.3.4 inmediatamente; contiene una puerta trasera conocida.",
                cves=["CVE-2011-2523"],
                tags=["ftp", "exploit"],
                source="heuristic",
                confidence="alta",
            )
        if "proftpd 1.3.5" in low:
            _add(
                findings,
                "CRÍTICO",
                "ProFTPD 1.3.5 con ejecución remota",
                host.ip,
                f"{host.ip}:{port.port} → {text}.",
                "Actualizar ProFTPD; la versión 1.3.5 es vulnerable a CVE-2015-3306.",
                cves=["CVE-2015-3306"],
                tags=["ftp", "exploit"],
                source="heuristic",
                confidence="alta",
            )
        if "samba" in low and re.search(r"\b3\.", low):
            _add(
                findings,
                "CRÍTICO",
                "Samba 3.x vulnerable",
                host.ip,
                f"{host.ip}:{port.port} → {text}.",
                "Actualizar Samba y deshabilitar SMBv1.",
                cves=["CVE-2017-7494"],
                tags=["smb", "exploit"],
                source="heuristic",
                confidence="media",
            )
        if "openssl 1.0" in low or "openssl 1.1" in low:
            _add(
                findings,
                "ALTO",
                "OpenSSL EOL",
                host.ip,
                f"{host.ip}:{port.port} → {text}.",
                "Actualizar OpenSSL a 3.x y revisar los cifrados habilitados.",
                cwe=["CWE-1104"],
                tags=["tls", "outdated"],
                source="heuristic",
                confidence="media",
            )
        if "php/" in low or "php " in low:
            version = _version_tuple(text, r"PHP/(\d+\.\d+)")
            if version and version < (8, 1):
                _add(
                    findings,
                    "MEDIO",
                    "PHP sin soporte",
                    host.ip,
                    f"{host.ip}:{port.port} → {text}.",
                    "Actualizar PHP a una versión soportada.",
                    cwe=["CWE-1104"],
                    tags=["web", "outdated"],
                    source="heuristic",
                    confidence="media",
                )
        if "apache" in low:
            version = _version_tuple(text, r"Apache/(\d+\.\d+\.\d+)")
            if version and version < (2, 4, 60):
                _add(
                    findings,
                    "MEDIO",
                    "Apache HTTP Server desactualizado",
                    host.ip,
                    f"{host.ip}:{port.port} → {text}.",
                    "Actualizar Apache a la última versión estable de la rama soportada.",
                    cwe=["CWE-1104"],
                    tags=["web", "outdated"],
                    source="heuristic",
                    confidence="media",
                )
        if "nginx" in low:
            version = _version_tuple(text, r"nginx/(\d+\.\d+\.\d+)")
            if version and version < (1, 24, 0):
                _add(
                    findings,
                    "MEDIO",
                    "nginx desactualizado",
                    host.ip,
                    f"{host.ip}:{port.port} → {text}.",
                    "Actualizar nginx a una versión soportada.",
                    cwe=["CWE-1104"],
                    tags=["web", "outdated"],
                    source="heuristic",
                    confidence="media",
                )
        if "microsoft sql server" in low and "2012" in low:
            _add(
                findings,
                "ALTO",
                "SQL Server 2012 sin soporte",
                host.ip,
                f"{host.ip}:{port.port} → {text}.",
                "Migrar a una versión soportada de SQL Server.",
                cwe=["CWE-1104"],
                tags=["database", "outdated"],
                source="heuristic",
                confidence="media",
            )
        if "mysql" in low and re.search(r"5\.[0-7]", low):
            _add(
                findings,
                "MEDIO",
                "MySQL 5.x sin soporte",
                host.ip,
                f"{host.ip}:{port.port} → {text}.",
                "Migrar a MySQL 8.x o MariaDB soportada.",
                cwe=["CWE-1104"],
                tags=["database", "outdated"],
                source="heuristic",
                confidence="media",
            )


WEB_PORTS = {80, 443, 8000, 8006, 8080, 8081, 8443, 8888, 9000, 9090}


def _is_web_port(port) -> bool:
    service = (port.service or "").lower()
    if service in ("http", "https", "http-proxy", "http-alt", "ssl/http", "http-mgmt"):
        return True
    return port.port in WEB_PORTS


def _http_rules(host: Host, findings: list[Finding]) -> None:
    for port in host.ports:
        headers = port.scripts.get("http-headers", "")
        title = html.unescape(port.scripts.get("http-title", "") or "")
        server = port.scripts.get("http-server-header", "")
        if not headers and not title:
            continue
        low_headers = headers.lower()
        if title and re.search(
            r"(apache2 ubuntu default page|welcome to nginx|iis windows server|test page|routeros|zte|default)",
            title,
            re.IGNORECASE,
        ):
            _add(
                findings,
                "BAJO",
                "Página por defecto o panel expuesto",
                host.ip,
                f"{host.ip}:{port.port} → «{title}».",
                "Retirar páginas por defecto, restringir paneles de administración y cambiar credenciales.",
                tags=["web", "misconfig"],
                source="heuristic",
                confidence="alta",
            )
        if "server:" in low_headers:
            server_value = re.search(r"server:\s*([^\n]+)", low_headers)
            if server_value and re.search(r"\d+\.\d+", server_value.group(1)):
                _add(
                    findings,
                    "INFO",
                    "Divulgación de versión del servidor web",
                    host.ip,
                    f"{host.ip}:{port.port} → Server: {server_value.group(1).strip()}",
                    "Minimizar la cabecera Server.",
                    tags=["web", "info-disclosure"],
                    source="heuristic",
                    confidence="media",
                )
        if headers and _is_web_port(port):
            missing = [
                name
                for name in (
                    "strict-transport-security",
                    "x-content-type-options",
                    "x-frame-options",
                    "content-security-policy",
                )
                if name not in low_headers
            ]
            if len(missing) >= 3:
                _add(
                    findings,
                    "BAJO",
                    "Cabeceras de seguridad HTTP ausentes",
                    host.ip,
                    f"{host.ip}:{port.port} → faltan: {', '.join(missing)}.",
                    "Añadir HSTS, X-Content-Type-Options, X-Frame-Options o CSP según el tipo de aplicación.",
                    cwe=["CWE-693"],
                    tags=["web", "misconfig"],
                    source="heuristic",
                    confidence="media",
                )
        if "set-cookie:" in low_headers:
            for cookie in re.findall(r"set-cookie:\s*([^\n]+)", low_headers):
                if "httponly" not in cookie or "secure" not in cookie:
                    _add(
                        findings,
                        "BAJO",
                        "Cookie sin HttpOnly/Secure",
                        host.ip,
                        f"{host.ip}:{port.port} → Set-Cookie: {cookie.strip()[:160]}",
                        "Añadir HttpOnly y Secure a las cookies de sesión y usar SameSite.",
                        cwe=["CWE-1004"],
                        tags=["web", "misconfig"],
                        source="heuristic",
                        confidence="media",
                    )
                    break
        if server and "zte" in server.lower():
            _add(
                findings,
                "ALTO",
                "Servidor web ZTE antiguo",
                host.ip,
                f"{host.ip}:{port.port} → {server.strip()}",
                "Actualizar firmware y restringir la gestión al segmento de administración.",
                cwe=["CWE-1104"],
                tags=["router", "outdated"],
                source="heuristic",
                confidence="media",
            )


def _script_rules(host: Host, findings: list[Finding], good: list[str]) -> None:
    for port in host.ports:
        scripts = {k.lower(): v for k, v in (port.scripts or {}).items()}
        for name, output in scripts.items():
            low = str(output).lower()
            if "ftp-anon" in name and ("anonymous" in low and "allowed" in low):
                _add(
                    findings,
                    "ALTO",
                    "FTP anónimo habilitado",
                    host.ip,
                    f"{host.ip}:{port.port} permite login anónimo.",
                    "Deshabilitar el acceso anónimo y exigir autenticación.",
                    cwe=["CWE-306"],
                    tags=["ftp", "valid-accounts"],
                    source="heuristic",
                    confidence="alta",
                )
            if "smb-security-mode" in name and "signing: disabled" in low:
                _add(
                    findings,
                    "MEDIO",
                    "SMB sin firma obligatoria",
                    host.ip,
                    f"{host.ip}:{port.port} → {output.strip()[:220]}",
                    "Exigir firma SMB y deshabilitar SMBv1.",
                    cwe=["CWE-345"],
                    tags=["smb", "misconfig"],
                    source="heuristic",
                    confidence="alta",
                )
            if "smb2-security-mode" in name and "not required" in low:
                _add(
                    findings,
                    "MEDIO",
                    "SMB2 sin firma obligatoria",
                    host.ip,
                    f"{host.ip}:{port.port} → {output.strip()[:220]}",
                    "Configurar la firma SMB como obligatoria.",
                    cwe=["CWE-345"],
                    tags=["smb", "misconfig"],
                    source="heuristic",
                    confidence="alta",
                )
            if "smb-os-discovery" in name and output.strip():
                if not host.os or host.os == "SO desconocido":
                    host.os = output.strip().splitlines()[0][:120]
            if "ssl-cert" in name:
                expiry = _cert_expiry(output)
                if expiry:
                    days = (expiry - datetime.now()).days
                    if days < 0:
                        _add(
                            findings,
                            "ALTO",
                            "Certificado TLS caducado",
                            host.ip,
                            f"{host.ip}:{port.port} → caducado el {expiry:%Y-%m-%d}.",
                            "Renovar el certificado y automatizar la renovación.",
                            cwe=["CWE-298"],
                            tags=["tls", "misconfig"],
                            source="heuristic",
                            confidence="alta",
                        )
                    elif days < 30:
                        _add(
                            findings,
                            "MEDIO",
                            "Certificado TLS próximo a caducar",
                            host.ip,
                            f"{host.ip}:{port.port} → caduca en {days} días ({expiry:%Y-%m-%d}).",
                            "Renovar el certificado antes de la fecha de expiración.",
                            tags=["tls", "misconfig"],
                            source="heuristic",
                            confidence="alta",
                        )
                    else:
                        good.append(f"{host.ip}: certificado TLS válido hasta {expiry:%Y-%m-%d}.")
            if "ssh-hostkey" in name and "dsa" in low:
                _add(
                    findings,
                    "BAJO",
                    "Clave SSH DSA obsoleta",
                    host.ip,
                    f"{host.ip}:{port.port} ofrece una clave DSA.",
                    "Eliminar las claves DSA y usar Ed25519 o RSA >= 3072.",
                    cwe=["CWE-327"],
                    tags=["ssh", "weak-crypto"],
                    source="heuristic",
                    confidence="alta",
                )


def _global_good_checks(hosts: list[Host], good: list[str], proxmox: dict) -> None:
    all_ports = {p.port for h in hosts for p in h.ports}
    if not (all_ports & DB_PORTS):
        good.append("No se detectaron puertos de bases de datos ni Redis/Memcached expuestos.")
    if not (all_ports & {139, 445}):
        good.append("No se detectó SMB expuesto en los hosts analizados.")
    if not (all_ports & {23, 512, 513, 514}):
        good.append("No se detectaron servicios remotos en claro (Telnet/r-services).")
    if proxmox.get("quorate") == "1":
        good.append(f"El clúster Proxmox {proxmox.get('cluster', '')} reporta quórum correcto.")
    if not any(22 in {p.port for p in h.ports} for h in hosts):
        good.append("No se detectaron servidores SSH expuestos.")


def _version_tuple(text: str, pattern: str) -> tuple[int, ...]:
    match = re.search(pattern, text, re.IGNORECASE)
    if not match:
        return ()
    return tuple(int(part) for part in re.findall(r"\d+", match.group(1)))


def _build_at_least(value: str, minimum: str) -> bool:
    def parse(raw: str) -> tuple[int, ...]:
        return tuple(int(part) for part in re.findall(r"\d+", raw))

    return parse(value) >= parse(minimum)


def _cert_expiry(output: str) -> datetime | None:
    match = re.search(r"Not valid after:\s*([A-Za-z]{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}\s+\d{4})", output)
    if not match:
        return None
    for fmt in ("%b %d %H:%M:%S %Y", "%b %d %H:%M:%S %Z %Y"):
        try:
            return datetime.strptime(match.group(1), fmt)
        except ValueError:
            continue
    return None
