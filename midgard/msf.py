"""Plan de Metasploit generado a partir de un escaneo.

Solo se generan resource scripts `.rc` con módulos *auxiliary*
(reconocimiento). La ejecución es opcional, requiere ``MIDGARD_ALLOW_MSF=1``
y el flag ``--yes``, y el RC se valida antes de enviarlo a msfconsole.
No se incluye ningún módulo de explotación.
"""

from __future__ import annotations

import re
from pathlib import Path

from . import config, docker
from .nmap import Host


class RCSafetyError(ValueError):
    """El resource script contiene algo distinto de módulos auxiliary."""


MODULE_RE = re.compile(r"^auxiliary/[a-z0-9_/-]+$")
USE_RE = re.compile(r"^\s*use\s+(.+?)\s*$", re.I)
FORBIDDEN_RE = re.compile(
    r"^\s*(?:"
    r"exploit|sessions?|shell|execute|load|resource|spool|"
    r"setg?\s+(?:PAYLOAD|AutoRunScript|InitialAutoRunScript|ExitOnSession)"
    r")\b",
    re.I,
)


# Puerto -> (módulo auxiliary, descripción)
MODULES: dict[int, tuple[str, str]] = {
    21: ("auxiliary/scanner/ftp/ftp_version", "versión FTP"),
    22: ("auxiliary/scanner/ssh/ssh_version", "versión SSH"),
    23: ("auxiliary/scanner/telnet/telnet_version", "versión Telnet"),
    25: ("auxiliary/scanner/smtp/smtp_version", "versión SMTP"),
    53: ("auxiliary/scanner/dns/dns_version", "versión DNS"),
    80: ("auxiliary/scanner/http/http_version", "versión HTTP"),
    111: ("auxiliary/scanner/portscan/tcp", "RPC (sondeo TCP)"),
    139: ("auxiliary/scanner/smb/smb_version", "versión SMB"),
    443: ("auxiliary/scanner/http/http_version", "versión HTTPS"),
    445: ("auxiliary/scanner/smb/smb_version", "versión SMB"),
    3306: ("auxiliary/scanner/mysql/mysql_version", "versión MySQL"),
    3389: ("auxiliary/scanner/rdp/rdp_scanner", "RDP"),
    5432: ("auxiliary/scanner/postgres/postgres_version", "versión PostgreSQL"),
    5900: ("auxiliary/scanner/vnc/vnc_none_auth", "VNC sin autenticación"),
    6379: ("auxiliary/scanner/redis/redis_server", "Redis"),
    8080: ("auxiliary/scanner/http/http_version", "versión HTTP alternativo"),
    8291: ("auxiliary/scanner/http/http_version", "panel MikroTik (HTTP)"),
    8443: ("auxiliary/scanner/http/http_version", "versión HTTPS alternativo"),
    8728: ("auxiliary/scanner/http/http_version", "API MikroTik"),
    8729: ("auxiliary/scanner/http/http_version", "API MikroTik TLS"),
}


def collect(hosts: list[Host]) -> dict[str, list[str]]:
    """Agrupa IPs por módulo auxiliary."""
    grouped: dict[str, list[str]] = {}
    for host in hosts:
        for port in host.open_ports:
            entry = MODULES.get(port.port)
            if not entry:
                continue
            module = entry[0]
            grouped.setdefault(module, [])
            if host.ip not in grouped[module]:
                grouped[module].append(host.ip)
    return dict(sorted(grouped.items()))


def build_rc(hosts: list[Host], run_id: str) -> str:
    grouped = collect(hosts)
    lines = [
        "# MIDGARD - plan de Metasploit (reconocimiento)",
        f"# run: {run_id}",
        "# Solo módulos auxiliary. Sin exploits ni cargas.",
        "# Revisa el alcance antes de ejecutar.",
        "",
        "setg THREADS 4",
        "setg VERBOSE false",
        "",
    ]
    for module, ips in grouped.items():
        lines.append(f"use {module}")
        lines.append("set RHOSTS " + " ".join(ips))
        lines.append("run")
        lines.append("")
    if not grouped:
        lines.append("# No hay puertos que mapear a módulos auxiliary.")
        lines.append("")
    lines += ["exit -y", ""]
    return "\n".join(lines)


def validate_rc(text: str) -> bool:
    """Rechaza exploits, payloads, sesiones y módulos que no sean auxiliary."""
    if not text or not text.strip():
        raise RCSafetyError("resource script vacío")
    for number, line in enumerate(text.splitlines(), start=1):
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if FORBIDDEN_RE.match(stripped):
            raise RCSafetyError(f"línea {number}: instrucción no permitida: {stripped!r}")
        match = USE_RE.match(stripped)
        if match:
            module = match.group(1).strip()
            if not MODULE_RE.match(module):
                raise RCSafetyError(
                    f"línea {number}: solo se permiten módulos auxiliary/: {module!r}"
                )
    return True


def write_plan(run_dir: Path, hosts: list[Host]) -> Path:
    text = build_rc(hosts, run_dir.name)
    validate_rc(text)
    path = run_dir / "msf_plan.rc"
    path.write_text(text, encoding="utf-8")
    return path


def run_plan(run_dir: Path, *, timeout: int = 900) -> docker.CommandResult:
    """Ejecuta el RC por stdin en msfconsole sin base de datos ni shell."""
    path = run_dir / "msf_plan.rc"
    if not path.is_file():
        raise FileNotFoundError(f"no existe el plan: {path}")
    text = path.read_text(encoding="utf-8")
    validate_rc(text)
    name = "midgard-msf-" + re.sub(r"[^A-Za-z0-9_.-]+", "-", run_dir.name)[:90]
    return docker.run_container(
        config.docker_image(),
        ["/usr/bin/msfconsole", "-q", "-n", "--no-readline", "-r", "/out/msf_plan.rc"],
        name=name.strip("-") or "midgard-msf",
        timeout=timeout,
        extra=["-v", f"{run_dir.resolve()}:/out:ro"],
    )


def docker_command(run_dir: Path) -> str:
    image = config.docker_image()
    return (
        "docker run --rm -it --network host "
        f'-v "{run_dir}:/out" '
        f"--entrypoint msfconsole {image} -q -n --no-readline -r /out/msf_plan.rc"
    )
