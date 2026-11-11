"""Sondas ligeras de host que complementan el fingerprint de Nmap.

`nmap -O` necesita al menos un puerto abierto y otro cerrado, y aun así suele
quedarse en la familia del kernel. Para hosts sin puertos (móviles, equipos
apagados por software, IoT) el TTL del ICMP distingue razonablemente entre
Linux/Unix (64), Windows (128) y equipos de red (255).
"""

from __future__ import annotations

import concurrent.futures
import re
import shutil
import subprocess

from .nmap import Host

TTL_RE = re.compile(r"\bttl[= ](\d+)\b", re.I)


def _ping_ttl(ping: str, ip: str, timeout: int = 2) -> int:
    try:
        result = subprocess.run(  # noqa: S603 - argv sin shell
            [ping, "-c", "1", "-W", "1", "-n", ip],
            capture_output=True,
            text=True,
            timeout=timeout,
        )
    except (OSError, subprocess.SubprocessError):
        return 0
    match = TTL_RE.search((result.stdout or "") + "\n" + (result.stderr or ""))
    if not match:
        return 0
    try:
        return int(match.group(1))
    except ValueError:
        return 0


def probe_ttl(hosts: list[Host], workers: int = 32) -> int:
    """Rellena ``host.ttl`` sin abortar el escaneo si ping no está disponible."""
    ping = shutil.which("ping")
    candidates = [host for host in hosts if host.ip and ":" not in host.ip]
    if not ping or not candidates:
        return 0
    updated = 0
    with concurrent.futures.ThreadPoolExecutor(max_workers=min(workers, len(candidates))) as pool:
        futures = {pool.submit(_ping_ttl, ping, host.ip): host for host in candidates}
        for future in concurrent.futures.as_completed(futures):
            host = futures[future]
            try:
                ttl = future.result()
            except Exception:  # noqa: BLE001 - sonda best-effort
                ttl = 0
            if ttl:
                host.ttl = ttl
                updated += 1
    return updated
