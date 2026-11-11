"""Sonda SNMPv2c para obtener el sysDescr exacto del objetivo.

Es una lectura puntual: `snmpget` del OID 1.3.6.1.2.1.1.1.0. No escribe
nada en el objetivo ni usa MIBs externas. Sirve para confirmar versiones
que `nmap -O` solo aproxima (por ejemplo RouterOS 6.49.23).
"""

from __future__ import annotations

import re
from typing import Callable

from . import docker
from .nmap import Host


SYS_DESCR_OID = "1.3.6.1.2.1.1.1.0"
COMMUNITY_RE = re.compile(r"^[A-Za-z0-9_.\-]{1,64}$")
VALUE_RE = re.compile(r"=\s*(?:STRING|Hex-STRING|OID):\s*(.+)$", re.I)


class SnmpError(ValueError):
    """Comunidad u objetivo SNMP no válido."""


def validate_community(value: str) -> str:
    value = (value or "").strip()
    if not COMMUNITY_RE.match(value):
        raise SnmpError(
            "comunidad SNMP no válida: usa 1-64 caracteres alfanuméricos, '_', '-' o '.'"
        )
    return value


def build_get_argv(ip: str, community: str, *, timeout: int = 3, retries: int = 1) -> list[str]:
    community = validate_community(community)
    return [
        "/usr/bin/snmpget",
        "-v2c",
        "-c",
        community,
        "-t",
        str(max(1, int(timeout))),
        "-r",
        str(max(0, int(retries))),
        "-Oqv",
        ip,
        SYS_DESCR_OID,
    ]


def parse_sysdescr(output: str) -> str:
    """Extrae el valor de sysDescr de la salida de snmpget."""
    for line in reversed((output or "").splitlines()):
        text = line.strip()
        if not text:
            continue
        if "No Such Object" in text or "Timeout:" in text or "No Response" in text:
            return ""
        match = VALUE_RE.search(text)
        value = match.group(1) if match else text
        value = value.strip().strip('"').strip()
        if value and not value.lower().startswith(("snmpv2-mib::", "iso.")):
            return value
    return ""


def probe_host(
    host: Host,
    community: str,
    *,
    timeout: int = 8,
    runner: Callable[..., docker.CommandResult] | None = None,
) -> dict:
    run = runner or docker.run_quick
    argv = build_get_argv(host.ip, community)
    safe_argv = list(argv)
    if community != "public":
        try:
            safe_argv[safe_argv.index("-c") + 1] = "<redactada>"
        except (ValueError, IndexError):
            pass
    result = run(argv, timeout=timeout)
    sysdescr = parse_sysdescr((result.stdout or "") + "\n" + (result.stderr or ""))
    return {
        "ip": host.ip,
        "ok": bool(result.ok and sysdescr),
        "argv": safe_argv,
        "returncode": result.returncode,
        "timed_out": result.timed_out,
        "sysdescr": sysdescr,
        "error": "" if sysdescr else (result.stderr or result.stdout or "").strip()[-500:],
    }


def _mikrotik_like(host: Host) -> bool:
    haystack = " ".join(
        [host.vendor]
        + [match.name for match in host.os_matches]
        + [f"{port.product} {port.version}" for port in host.ports]
    ).lower()
    return (
        "mikrotik" in haystack
        or "routeros" in haystack
        or "routerboard" in haystack
        or any(port.port in {8291, 8728, 8729} for port in host.open_ports)
    )


def probe_hosts(
    hosts: list[Host],
    community: str,
    *,
    timeout: int = 8,
    runner: Callable[..., docker.CommandResult] | None = None,
) -> dict:
    """Sondea hosts con UDP/161 o, si no se escaneó, routers MikroTik conocidos."""
    community = validate_community(community)
    targets = [
        host
        for host in hosts
        if any(
            (port.port == 161 and port.proto == "udp" and port.state in {"open", "open|filtered"})
            or port.service.lower() == "snmp"
            for port in host.ports
        )
    ]
    if not targets:
        targets = [host for host in hosts if _mikrotik_like(host)][:64]
    results = []
    for host in targets:
        item = probe_host(host, community, timeout=timeout, runner=runner)
        results.append(item)
        if item["sysdescr"]:
            host.scripts["snmp-sysdescr"] = item["sysdescr"]
    return {
        "community": community if community == "public" else "<redactada>",
        "targets": len(targets),
        "responded": sum(1 for item in results if item["ok"]),
        "hosts": results,
    }
