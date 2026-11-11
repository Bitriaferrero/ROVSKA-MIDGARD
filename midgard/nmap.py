"""Nmap: construcción de argumentos y parseo del XML.

No se invoca ningún shell. Todos los valores que vienen del usuario se
validan antes de convertirse en argumentos.
"""

from __future__ import annotations

import re
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field

from .profiles import Profile


class NmapError(ValueError):
    """Argumentos de Nmap inválidos."""


PORT_RE = re.compile(r"^[0-9U:T,S\-]+$")
SCRIPT_RE = re.compile(r"^[A-Za-z0-9_.\-]+(?:,[A-Za-z0-9_.\-]+)*$")

SAFE_SCRIPTS = {
    "banner",
    "http-title",
    "http-headers",
    "http-methods",
    "http-enum",
    "ssl-cert",
    "ssl-enum-ciphers",
    "ssh-hostkey",
    "ssh2-enum-algos",
    "smb-os-discovery",
    "smb2-security-mode",
    "snmp-info",
    "snmp-sysdescr",
}


@dataclass
class Port:
    port: int
    proto: str
    state: str
    service: str = ""
    product: str = ""
    version: str = ""
    extrainfo: str = ""
    tunnel: str = ""
    ostype: str = ""
    devicetype: str = ""
    scripts: dict[str, str] = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "port": self.port,
            "proto": self.proto,
            "state": self.state,
            "service": self.service,
            "product": self.product,
            "version": self.version,
            "extrainfo": self.extrainfo,
            "tunnel": self.tunnel,
            "ostype": self.ostype,
            "devicetype": self.devicetype,
            "scripts": dict(self.scripts),
        }

    @property
    def label(self) -> str:
        bits = [self.service or "?"]
        if self.product:
            bits.append(self.product)
        if self.version:
            bits.append(self.version)
        return " ".join(bits)


@dataclass
class OSMatch:
    name: str
    accuracy: int
    classes: list[dict] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {"name": self.name, "accuracy": self.accuracy, "classes": list(self.classes)}


@dataclass
class Host:
    ip: str
    mac: str = ""
    vendor: str = ""
    hostnames: list[str] = field(default_factory=list)
    ports: list[Port] = field(default_factory=list)
    os_matches: list[OSMatch] = field(default_factory=list)
    scripts: dict[str, str] = field(default_factory=dict)
    os: dict = field(default_factory=dict)
    ttl: int = 0

    def to_dict(self) -> dict:
        return {
            "ip": self.ip,
            "mac": self.mac,
            "vendor": self.vendor,
            "hostnames": list(self.hostnames),
            "ports": [p.to_dict() for p in self.ports],
            "os_matches": [m.to_dict() for m in self.os_matches],
            "scripts": dict(self.scripts),
            "os": dict(self.os),
            "ttl": self.ttl,
        }

    @property
    def open_ports(self) -> list[Port]:
        return [p for p in self.ports if p.state == "open"]

    @classmethod
    def from_dict(cls, data: dict) -> "Host":
        ports = [
            Port(
                port=int(p.get("port", 0)),
                proto=p.get("proto", "tcp"),
                state=p.get("state", "unknown"),
                service=p.get("service", ""),
                product=p.get("product", ""),
                version=p.get("version", ""),
                extrainfo=p.get("extrainfo", ""),
                tunnel=p.get("tunnel", ""),
                ostype=p.get("ostype", ""),
                devicetype=p.get("devicetype", ""),
                scripts=dict(p.get("scripts") or {}),
            )
            for p in data.get("ports", [])
        ]
        matches = [
            OSMatch(
                name=m.get("name", ""),
                accuracy=int(m.get("accuracy", 0) or 0),
                classes=list(m.get("classes") or []),
            )
            for m in data.get("os_matches", [])
        ]
        return cls(
            ip=data.get("ip", ""),
            mac=data.get("mac", ""),
            vendor=data.get("vendor", ""),
            hostnames=list(data.get("hostnames") or []),
            ports=ports,
            os_matches=matches,
            scripts=dict(data.get("scripts") or {}),
            os=dict(data.get("os") or {}),
            ttl=int(data.get("ttl", 0) or 0),
        )


def validate_ports(value: str) -> str:
    value = (value or "").strip()
    if not value:
        raise NmapError("lista de puertos vacía")
    if not PORT_RE.match(value):
        raise NmapError(
            "puertos no válidos. Ejemplo: 22,80,443 o 1-1024 o T:22,U:161"
        )
    return value


def validate_scripts(value: str) -> list[str]:
    value = (value or "").strip()
    if not value:
        return []
    if not SCRIPT_RE.match(value):
        raise NmapError("nombres de script no válidos (usa comas, sin espacios)")
    scripts = [s for s in value.split(",") if s]
    for script in scripts:
        if script not in SAFE_SCRIPTS:
            raise NmapError(
                f"script no permitido: {script!r}. "
                f"Permitidos: {', '.join(sorted(SAFE_SCRIPTS))}"
            )
    return scripts


def build_nmap_args(
    target: str,
    profile: Profile,
    *,
    ports: str | None = None,
    scripts: list[str] | None = None,
    os_detection: bool | None = None,
    no_ping: bool = False,
    udp: bool | None = None,
) -> list[str]:
    """Devuelve los argumentos de nmap (sin el binario)."""
    args: list[str] = ["-oX", "-"]

    if profile.mode == "discovery":
        args += ["-sn"]
        args += [profile.timing]
        if no_ping:
            # En descubrimiento, -Pn no tiene sentido; se ignora.
            pass
        args += [target]
        return args

    args += list(profile.scan or ("-sS",))
    if profile.version:
        args += ["-sV", "--version-light"]
    if os_detection is None:
        os_detection = profile.os
    if os_detection:
        args += ["-O", "--osscan-guess"]
    if no_ping:
        args.append("-Pn")

    args.append(profile.timing or "-T4")
    args += ["--max-retries", "1", "--host-timeout", "30m"]
    args += list(profile.extra_args)

    tcp = (ports if ports is not None else profile.ports_tcp).strip()
    udp_enabled = profile.udp if udp is None else udp
    udp_ports = profile.ports_udp.strip() if udp_enabled else ""
    if udp and not udp_ports:
        raise NmapError(
            f"el perfil {profile.id!r} no define puertos UDP; "
            "usa --profile infra o --profile router"
        )

    if ports is not None:
        validate_ports(ports)
    if tcp:
        validate_ports(tcp)
    if udp_ports:
        validate_ports(udp_ports)

    if tcp and udp_ports:
        args += ["-p", f"T:{tcp},U:{udp_ports}"]
        args.append("-sU")
    elif tcp:
        args += ["-p", tcp]
    elif udp_ports:
        args += ["-p", f"U:{udp_ports}", "-sU"]
    elif profile.id == "quick":
        args += ["--top-ports", "1000"]
    elif profile.id == "custom":
        raise NmapError("el perfil custom exige --ports")

    selected = scripts if scripts is not None else list(profile.scripts)
    if selected:
        for script in selected:
            if script not in SAFE_SCRIPTS:
                raise NmapError(f"script no permitido: {script!r}")
        args += ["--script", ",".join(selected)]

    args.append(target)
    return args


def _parse_script(element: ET.Element) -> tuple[str, str]:
    return element.get("id", ""), element.get("output", "")


def parse_xml(xml_text: str) -> list[Host]:
    """Parsea la salida XML de Nmap y devuelve hosts con puertos y SO."""
    if not xml_text or not xml_text.strip():
        raise NmapError("XML vacío")
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError as exc:
        raise NmapError(f"XML de Nmap no válido: {exc}") from exc

    hosts: list[Host] = []
    for node in root.findall("host"):
        status = node.find("status")
        if status is not None and status.get("state") not in (None, "up"):
            continue

        ip = ""
        mac = ""
        vendor = ""
        for addr in node.findall("address"):
            kind = addr.get("addrtype")
            if kind in {"ipv4", "ipv6"} and not ip:
                ip = addr.get("addr", "")
            elif kind == "mac":
                mac = addr.get("addr", "")
                vendor = addr.get("vendor", "")
        if not ip:
            continue

        hostnames = [
            h.get("name", "")
            for h in node.findall("hostnames/hostname")
            if h.get("name")
        ]

        ports: list[Port] = []
        for p in node.findall("ports/port"):
            state_node = p.find("state")
            service = p.find("service")
            script_map: dict[str, str] = {}
            for script in p.findall("script"):
                sid, output = _parse_script(script)
                if sid:
                    script_map[sid] = output
            ports.append(
                Port(
                    port=int(p.get("portid", "0")),
                    proto=p.get("protocol", "tcp"),
                    state=state_node.get("state", "unknown") if state_node is not None else "unknown",
                    service=service.get("name", "") if service is not None else "",
                    product=service.get("product", "") if service is not None else "",
                    version=service.get("version", "") if service is not None else "",
                    extrainfo=service.get("extrainfo", "") if service is not None else "",
                    tunnel=service.get("tunnel", "") if service is not None else "",
                    ostype=service.get("ostype", "") if service is not None else "",
                    devicetype=service.get("devicetype", "") if service is not None else "",
                    scripts=script_map,
                )
            )

        os_matches: list[OSMatch] = []
        for om in node.findall("os/osmatch"):
            classes = []
            for oc in om.findall("osclass"):
                classes.append(
                    {
                        "type": oc.get("type", ""),
                        "vendor": oc.get("vendor", ""),
                        "osfamily": oc.get("osfamily", ""),
                        "osgen": oc.get("osgen", ""),
                        "accuracy": int(oc.get("accuracy", "0") or 0),
                    }
                )
            os_matches.append(
                OSMatch(
                    name=om.get("name", ""),
                    accuracy=int(om.get("accuracy", "0") or 0),
                    classes=classes,
                )
            )

        scripts: dict[str, str] = {}
        for script in node.findall("hostscript/script"):
            sid, output = _parse_script(script)
            if sid:
                scripts[sid] = output

        hosts.append(
            Host(
                ip=ip,
                mac=mac,
                vendor=vendor,
                hostnames=hostnames,
                ports=ports,
                os_matches=os_matches,
                scripts=scripts,
                ttl=int(status.get("reason_ttl", "0") or 0) if status is not None else 0,
            )
        )

    hosts.sort(key=lambda h: tuple(int(x) if x.isdigit() else 0 for x in h.ip.split(".")))
    return hosts


def nmap_version_from_text(text: str) -> str:
    match = re.search(r"Nmap version\s+([^\s]+)", text or "")
    return match.group(1) if match else ""
