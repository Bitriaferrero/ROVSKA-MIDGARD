"""Enriquecimiento de sistema operativo.

Nmap `-O` da una familia (Linux 5.x, Windows 10, macOS...). Para acercarse
a "Ubuntu 16.04", "Debian 11" o "Windows 11 23H2" se combinan banners de
SSH, HTTP, SMB, SNMP y el fabricante de la MAC. Todo es best-effort y cada
resultado indica su fuente y su confianza.
"""

from __future__ import annotations

import re

from .nmap import Host


# OpenSSH -> versión de Ubuntu (según el banner de la distribución).
UBUNTU_OPENSSH = {
    "7.2p2": "16.04",
    "7.6p1": "18.04",
    "8.2p1": "20.04",
    "8.9p1": "22.04",
    "9.6p1": "24.04",
    "9.9p1": "25.04/25.10 (interim)",
}

APACHE_UBUNTU = {
    "2.4.18": "16.04",
    "2.4.29": "18.04",
    "2.4.41": "20.04",
    "2.4.52": "22.04",
    "2.4.58": "24.04",
}

NGINX_UBUNTU = {
    "1.10.3": "16.04",
    "1.14.0": "18.04",
    "1.18.0": "20.04/22.04",
    "1.24.0": "24.04",
}

DEBIAN_OPENSSH = {
    "6.7p1": "8",
    "7.4p1": "9",
    "7.9p1": "10",
    "8.4p1": "11",
    "9.2p1": "12",
    "9.7p1": "12",
}

APACHE_DEBIAN = {
    "2.4.10": "9",
    "2.4.25": "9",
    "2.4.38": "10",
    "2.4.56": "11",
    "2.4.62": "12",
}

NGINX_DEBIAN = {
    "1.6.2": "8",
    "1.10.3": "9",
    "1.14.2": "10",
    "1.18.0": "11",
    "1.22.1": "12",
}

# Build de Windows -> (nombre, edición).
WINDOWS_BUILDS = {
    "7601": ("Windows 7", "SP1"),
    "9600": ("Windows 8.1", ""),
    "14393": ("Windows Server 2016 / Windows 10", "1607"),
    "17763": ("Windows Server 2019 / Windows 10", "1809"),
    "19041": ("Windows 10", "2004"),
    "19042": ("Windows 10", "20H2"),
    "19043": ("Windows 10", "21H1"),
    "19044": ("Windows 10", "21H2"),
    "19045": ("Windows 10", "22H2"),
    "20348": ("Windows Server 2022", "21H2"),
    "22000": ("Windows 11", "21H2"),
    "22621": ("Windows 11", "22H2"),
    "22631": ("Windows 11", "23H2"),
    "26100": ("Windows 11 / Server 2025", "24H2"),
}

ANDROID_VENDORS = {
    "samsung": "Samsung",
    "xiaomi": "Xiaomi",
    "huawei": "Huawei",
    "oneplus": "OnePlus",
    "oppo": "OPPO",
    "vivo": "vivo",
    "motorola": "Motorola",
    "lg electronics": "LG",
    "sony": "Sony",
    "google": "Google",
    "realme": "realme",
    "nothing": "Nothing",
    "fairphone": "Fairphone",
    "tcl": "TCL",
}

NETWORK_VENDORS = {
    "cisco": "Cisco IOS",
    "juniper": "Juniper Junos",
    "ubiquiti": "Ubiquiti (UniFi/EdgeOS)",
    "aruba": "Aruba (ArubaOS)",
    "tp-link": "TP-Link (router/CPE)",
    "zte": "ZTE (router/CPE)",
    "huawei": "Huawei (router/CPE)",
}

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

# Pistas por fabricante de la MAC. Son deliberadamente de baja confianza:
# sirven para no dejar el SO en "desconocido" cuando `nmap -O` no responde.
VENDOR_HINTS = {
    "raspberry pi": ("Raspberry Pi OS (Linux)", 55),
    "espressif": ("Dispositivo IoT (ESP32/ESP8266)", 45),
    "tuya": ("Dispositivo IoT", 40),
    "shelly": ("Dispositivo IoT", 40),
    "synology": ("Synology DSM (Linux)", 55),
    "qnap": ("QNAP QTS (Linux)", 55),
    "vmware": ("VMware ESXi", 55),
    "qemu": ("Máquina virtual (QEMU/KVM)", 35),
    "virtualbox": ("Máquina virtual (VirtualBox)", 35),
    "sonos": ("Sonos (Linux)", 50),
    "roku": ("Roku OS", 50),
    "amazon": ("Amazon Fire OS / Android", 45),
    "brother": ("Impresora en red", 50),
    "canon": ("Impresora en red", 50),
    "epson": ("Impresora en red", 50),
    "xerox": ("Impresora en red", 50),
    "hewlett packard": ("PC / servidor HP", 32),
    "hp inc": ("PC / servidor HP", 32),
    "dell": ("PC / servidor Dell", 32),
    "lenovo": ("PC / servidor Lenovo", 32),
    "lcfc": ("PC Lenovo (LCFC)", 32),
    "asustek": ("PC ASUS", 30),
    "micro-star": ("PC MSI", 30),
    "gigabyte": ("PC Gigabyte", 30),
    "intel": ("PC Intel", 28),
    "acer": ("PC Acer", 30),
}

SERVICE_OS = {
    "routeros": ("MikroTik RouterOS", 70),
    "mikrotik": ("MikroTik RouterOS", 70),
    "windows": ("Windows", 52),
    "linux": ("Linux", 44),
    "unix": ("Linux / Unix", 40),
    "macos": ("macOS", 52),
    "mac os": ("macOS", 52),
    "freebsd": ("FreeBSD", 52),
    "openbsd": ("OpenBSD", 50),
    "cisco": ("Cisco IOS", 55),
    "junos": ("Juniper Junos", 55),
}


def _text(host: Host) -> str:
    parts: list[str] = [host.vendor, " ".join(host.hostnames)]
    for match in host.os_matches:
        parts.append(match.name)
        for cls in match.classes:
            parts.append(" ".join(str(v) for v in cls.values()))
    for port in host.ports:
        parts += [port.service, port.product, port.version, port.extrainfo, port.ostype, port.devicetype]
        parts += list(port.scripts.values())
    parts += list(host.scripts.values())
    return "\n".join(p for p in parts if p)


def _add(
    candidates: list[dict],
    name: str,
    version: str,
    score: int,
    source: str,
    detail: str = "",
) -> None:
    name = (name or "").strip()
    version = (version or "").strip()
    if not name:
        return
    key = (name.lower(), version.lower())
    for candidate in candidates:
        if (candidate["name"].lower(), candidate["version"].lower()) == key:
            if source not in candidate["sources"]:
                candidate["sources"].append(source)
            if score > candidate["score"]:
                candidate["score"] = score
            if detail and detail not in candidate["details"]:
                candidate["details"].append(detail)
            return
    candidates.append(
        {
            "name": name,
            "version": version,
            "score": score,
            "sources": [source],
            "details": [detail] if detail else [],
        }
    )


def _ubuntu(text: str, candidates: list[dict]) -> None:
    match = re.search(r"OpenSSH[_\s-]([0-9][0-9A-Za-z.]*p\d+)", text, re.I)
    if match and re.search(r"Ubuntu", text, re.I):
        version = UBUNTU_OPENSSH.get(match.group(1), "")
        _add(
            candidates,
            "Ubuntu",
            version,
            97 if version else 80,
            "banner SSH",
            f"OpenSSH {match.group(1)} con marca Ubuntu",
        )
        if version:
            return

    match = re.search(r"Ubuntu[- ](\d{2}\.\d{2})", text, re.I)
    if match:
        _add(candidates, "Ubuntu", match.group(1), 96, "banner", "versión en el banner")
        return

    match = re.search(r"(Apache|nginx)/([0-9.]+)[^\n]*\(Ubuntu\)", text, re.I)
    if match:
        product, version = match.group(1).lower(), match.group(2)
        table = APACHE_UBUNTU if product == "apache" else NGINX_UBUNTU
        distro = table.get(version, "")
        _add(
            candidates,
            "Ubuntu",
            distro,
            97 if distro else 78,
            "cabecera HTTP",
            f"{product} {version} (Ubuntu)",
        )
        return

    if re.search(r"\bUbuntu\b", text, re.I):
        _add(candidates, "Ubuntu", "", 80, "texto", "marca Ubuntu sin versión")


def _debian(text: str, candidates: list[dict]) -> None:
    match = re.search(r"OpenSSH[_\s-]([0-9][0-9A-Za-z.]*p\d+)", text, re.I)
    if match and re.search(r"Debian", text, re.I):
        direct = re.search(r"deb(\d+)u", text, re.I)
        if direct:
            version = direct.group(1)
        else:
            legacy = re.search(r"Debian[- ](\d+)", text, re.I)
            version = legacy.group(1) if legacy else DEBIAN_OPENSSH.get(match.group(1), "")
        _add(
            candidates,
            "Debian",
            version,
            97 if version else 80,
            "banner SSH",
            f"OpenSSH {match.group(1)} con marca Debian",
        )
        if version:
            return

    match = re.search(r"(Apache|nginx)/([0-9.]+)[^\n]*\(Debian\)", text, re.I)
    if match:
        product, version = match.group(1).lower(), match.group(2)
        table = APACHE_DEBIAN if product == "apache" else NGINX_DEBIAN
        distro = table.get(version, "")
        _add(
            candidates,
            "Debian",
            distro,
            97 if distro else 78,
            "cabecera HTTP",
            f"{product} {version} (Debian)",
        )
        return

    match = re.search(r"\bDebian(?: GNU/Linux)?\s*(\d+)?", text, re.I)
    if match:
        _add(candidates, "Debian", match.group(1) or "", 80, "texto", "marca Debian")


def _windows(text: str, candidates: list[dict]) -> None:
    build_match = re.search(r"Windows[^\n]*?\b(\d{5})\b", text, re.I)
    build = build_match.group(1) if build_match else ""
    if build in WINDOWS_BUILDS:
        name, edition = WINDOWS_BUILDS[build]
        _add(
            candidates,
            name,
            edition,
            99,
            "SMB / build",
            f"build {build}",
        )
        return
    match = re.search(
        r"Windows\s+(11|10|8\.1|8|7|Server\s+20\d{2}(?:\s+R2)?)",
        text,
        re.I,
    )
    if match:
        name = "Windows " + match.group(1)
        _add(candidates, name, "", 82, "banner", match.group(0))
        return
    if re.search(r"\bWindows\b", text, re.I):
        _add(candidates, "Windows", "", 60, "texto", "marca Windows")


def _mikrotik(text: str, host: Host, candidates: list[dict]) -> None:
    version = ""
    source = "RouterOS"
    detail = "banner/sysDescr de RouterOS"

    # Un servicio de RouterOS publica la versión exacta ("MikroTik router
    # ftpd 6.49.23"); el `osmatch` de nmap solo aproxima la rama
    # ("RouterOS 6.19"). Por eso manda el banner del servicio.
    for port in host.open_ports:
        blob = " ".join(
            [port.product, port.version, port.extrainfo, port.service, port.ostype]
        )
        if not re.search(r"mikrotik|routerboard|routeros|\brossh\b", blob, re.I):
            continue
        exact = re.search(
            r"\b([0-9]+\.[0-9]+(?:\.[0-9]+)+)\b", port.version or ""
        ) or re.search(r"\b([0-9]+\.[0-9]+(?:\.[0-9]+)+)\b", blob)
        if exact:
            version = exact.group(1).rstrip(".")
            source = "producto/servicio"
            detail = f"versión en {port.service or 'servicio'}"
            break

    if not version:
        match = re.search(r"RouterOS(?:\s+\S+)?\s+([0-9]+(?:\.[0-9]+)+)", text, re.I)
        if not match:
            # El banner SSH de RouterOS es "ROSSH <versión>".
            match = re.search(r"\bROSSH[\s_-]+([0-9]+(?:\.[0-9]+)+)", text, re.I)
        version = match.group(1).rstrip(".") if match else ""

    if version:
        _add(
            candidates,
            "MikroTik RouterOS",
            version,
            99,
            source,
            detail,
        )
        return
    strong = bool(re.search(r"mikrotik|routerboard|routeros|\brossh\b", text, re.I))
    strong = strong or any(p.port in {8291, 8728, 8729} for p in host.open_ports)
    if strong:
        _add(candidates, "MikroTik RouterOS", "", 97, "producto/servicio", "marca MikroTik")


def _apple(text: str, host: Host, candidates: list[dict]) -> None:
    match = re.search(r"(?:Apple\s+)?(?:macOS|Mac OS X)\s*([0-9][0-9.]*)?", text, re.I)
    if match:
        _add(
            candidates,
            "macOS",
            (match.group(1) or "").rstrip("."),
            88 if match.group(1) else 70,
            "nmap / banner",
            "fingerprint de Apple",
        )
        return
    if "apple" in host.vendor.lower():
        ios = any(p.port == 62078 for p in host.open_ports)
        _add(
            candidates,
            "iOS" if ios else "Apple (macOS/iOS)",
            "",
            45 if ios else 35,
            "fabricante MAC",
            host.vendor,
        )


def _android(host: Host, candidates: list[dict]) -> None:
    vendor = host.vendor.lower()
    for key, label in ANDROID_VENDORS.items():
        if key in vendor:
            _add(candidates, f"Android ({label})", "", 40, "fabricante MAC", host.vendor)
            return
    if re.search(r"\bandroid\b", _text(host), re.I):
        _add(candidates, "Android", "", 62, "banner", "marca Android")


def _network_vendor(text: str, host: Host, candidates: list[dict]) -> None:
    haystack = (text + " " + host.vendor).lower()
    for key, label in NETWORK_VENDORS.items():
        if key in haystack:
            _add(candidates, label, "", 55, "fabricante/texto", key)
            return


def _vendor_hint(host: Host, candidates: list[dict]) -> None:
    vendor = (host.vendor or "").lower()
    if not vendor:
        return
    for key, (name, score) in VENDOR_HINTS.items():
        if key in vendor:
            _add(candidates, name, "", score, "fabricante MAC", host.vendor)
            return


def _service_os(host: Host, candidates: list[dict]) -> None:
    for port in host.open_ports:
        ostype = (port.ostype or "").strip()
        devicetype = (port.devicetype or "").strip()
        blob = f"{ostype} {devicetype}".lower()
        for key, (name, score) in SERVICE_OS.items():
            if key in blob:
                version = ""
                if name == "MikroTik RouterOS":
                    version = port.version if re.fullmatch(r"\d+(?:\.\d+)+", port.version or "") else ""
                _add(candidates, name, version, score, "servicio -sV", f"{port.label} {ostype} {devicetype}".strip())
                break
        else:
            if "printer" in blob or "impresora" in blob:
                _add(candidates, "Impresora en red", "", 42, "servicio -sV", f"{port.label} {devicetype}".strip())
            elif "router" in blob or "switch" in blob:
                _add(candidates, "Dispositivo de red", "", 40, "servicio -sV", f"{port.label} {devicetype}".strip())


def _ttl_hint(host: Host, candidates: list[dict]) -> None:
    ttl = int(host.ttl or 0)
    if ttl <= 0:
        return
    initial = 64 if ttl <= 64 else 128 if ttl <= 128 else 255
    if initial == 64:
        _add(candidates, "Linux / Unix (TTL 64)", "", 30, "TTL ICMP", f"ttl {ttl}")
    elif initial == 128:
        _add(candidates, "Windows (TTL 128)", "", 38, "TTL ICMP", f"ttl {ttl}")
    else:
        _add(candidates, "Dispositivo de red (TTL 255)", "", 42, "TTL ICMP", f"ttl {ttl}")


def _proxmox(text: str, host: Host, candidates: list[dict]) -> None:
    if "proxmox" in text.lower() or any(p.port == 8006 for p in host.open_ports):
        _add(candidates, "Proxmox VE", "", 70, "puerto/texto", "8006 o marca Proxmox")


def _virtualization(host: Host, candidates: list[dict]) -> None:
    """Marca guests de Proxmox y máquinas virtuales por el prefijo MAC."""
    mac = (host.mac or "").lower().replace("-", ":")
    if not mac:
        return
    if mac.startswith(PROXMOX_GUEST_MACS):
        _add(candidates, "Linux (invitado Proxmox)", "", 58, "MAC", "prefijo BC:24:11 (Proxmox)")
        return
    for prefix, label in VM_MAC_PREFIXES.items():
        if mac.startswith(prefix):
            _add(candidates, f"Linux (VM {label})", "", 50, "MAC", f"prefijo {prefix}")
            return


def _from_nmap(text: str, host: Host, candidates: list[dict]) -> None:
    for match in host.os_matches:
        name = match.name
        lower = name.lower()
        family = " ".join(str(c.get("osfamily", "")) for c in match.classes).lower()
        accuracy = int(match.accuracy)
        # Un `osmatch` genérico vale menos que un banner de distribución.
        score = max(20, accuracy - 5)
        if "mikrotik" in lower:
            _add(candidates, "MikroTik RouterOS", _version_after(name, "RouterOS"), score, "nmap -O", name)
        elif "macos" in lower or "mac os x" in lower:
            _add(candidates, "macOS", _version_after(name, "macOS"), score, "nmap -O", name)
        elif "windows" in lower or "windows" in family:
            version = _version_after(name, "Windows")
            _add(candidates, "Windows", version, score, "nmap -O", name)
        elif "linux" in lower or "linux" in family:
            version = _version_after(name, "Linux")
            _add(candidates, "Linux", version, score, "nmap -O", name)
        elif "freebsd" in lower:
            _add(candidates, "FreeBSD", _version_after(name, "FreeBSD"), score, "nmap -O", name)
        elif "openbsd" in lower:
            _add(candidates, "OpenBSD", "", score, "nmap -O", name)
        elif "cisco" in lower:
            _add(candidates, "Cisco IOS", "", score, "nmap -O", name)
        elif name:
            _add(candidates, name, "", max(20, accuracy - 15), "nmap -O", name)


def _version_after(name: str, label: str) -> str:
    match = re.search(re.escape(label) + r"\s*([0-9][0-9.\- ]*)", name, re.I)
    if not match:
        return ""
    return re.sub(r"\s+", " ", match.group(1)).strip(" .-")


def _from_ports(host: Host, candidates: list[dict]) -> None:
    ports = {p.port for p in host.open_ports}
    if 8006 in ports:
        _add(candidates, "Proxmox VE", "", 65, "puerto 8006", "panel Proxmox")
    if {135, 139, 445} & ports and 3389 in ports:
        _add(candidates, "Windows", "", 45, "puertos", "135/139/445/3389")
    if 9100 in ports or 631 in ports:
        _add(candidates, "Impresora en red", "", 40, "puertos", "9100/631")


def confidence_label(score: int) -> str:
    if score >= 85:
        return "alta"
    if score >= 60:
        return "media"
    if score >= 30:
        return "baja"
    return "muy baja"


def device_type(os_name: str, host: Host) -> str:
    name = os_name.lower()
    ports = {p.port for p in host.open_ports}
    mac = (host.mac or "").lower().replace("-", ":")
    if "mikrotik" in name or "routeros" in name or "cisco" in name or "junos" in name:
        return "Router"
    if "android" in name or "ios" in name:
        return "Móvil / tablet"
    if "invitado proxmox" in name:
        return "Guest Proxmox (LXC/VM)"
    if mac.startswith(PROXMOX_GUEST_MACS):
        return "Guest Proxmox (LXC/VM)"
    if "lxc" in name or "lxd" in name:
        return "LXC"
    if "proxmox" in name or 8006 in ports:
        return "Nodo Proxmox"
    for prefix, label in VM_MAC_PREFIXES.items():
        if mac.startswith(prefix):
            return f"Máquina virtual ({label})"
    if "vm " in name or "máquina virtual" in name or "virtualbox" in name or "vmware" in name or "qemu" in name:
        return "Máquina virtual"
    if "impresora" in name:
        return "Impresora"
    if 8291 in ports or 8728 in ports:
        return "Router / CPE"
    if 3389 in ports or 445 in ports:
        return "Servidor / PC"
    if "windows" in name:
        return "PC / servidor Windows"
    if "linux" in name or "unix" in name or "raspberry" in name:
        return "Host Linux"
    if "vmware" in name or "máquina virtual" in name or "virtual" in name:
        return "Máquina virtual"
    if os_name.startswith("SO desconocido"):
        return "Dispositivo"
    return "Host"


def detect(host: Host) -> dict:
    """Devuelve el SO probable con fuentes y confianza."""
    text = _text(host)
    candidates: list[dict] = []

    _mikrotik(text, host, candidates)
    _ubuntu(text, candidates)
    _debian(text, candidates)
    _windows(text, candidates)
    _apple(text, host, candidates)
    _android(host, candidates)
    _proxmox(text, host, candidates)
    _virtualization(host, candidates)
    _network_vendor(text, host, candidates)
    _vendor_hint(host, candidates)
    _service_os(host, candidates)
    _from_nmap(text, host, candidates)
    _from_ports(host, candidates)
    _ttl_hint(host, candidates)

    candidates.sort(key=lambda c: (c["score"], bool(c["version"])), reverse=True)
    best = candidates[0] if candidates else None

    if best is None:
        result = {
            "name": "SO desconocido",
            "version": "",
            "confidence": "muy baja",
            "score": 0,
            "sources": [],
            "candidates": [],
            "nmap_matches": [m.name for m in host.os_matches],
            "device": device_type("SO desconocido", host),
        }
    else:
        name = best["name"]
        device = device_type(name, host)
        low = name.lower()
        if device == "Nodo Proxmox" and "proxmox" not in low:
            name = f"{name} + Proxmox VE"
        elif device.startswith("Máquina virtual") and "vm" not in low:
            label = device.split("(", 1)[1].rstrip(")") if "(" in device else ""
            name = f"{name} (VM {label})" if label else f"{name} (VM)"
        result = {
            "name": name,
            "version": best["version"],
            "confidence": confidence_label(best["score"]),
            "score": best["score"],
            "sources": best["sources"],
            "details": best["details"],
            "candidates": candidates[:6],
            "nmap_matches": [m.name for m in host.os_matches],
            "device": device,
        }

    host.os = result
    return result


def detect_all(hosts: list[Host]) -> list[Host]:
    for host in hosts:
        detect(host)
    return hosts
