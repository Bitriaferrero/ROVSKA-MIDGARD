"""Configuración de MIDGARD basada en variables de entorno.

Todo tiene valores por defecto seguros: sin salida a Internet, sin
Metasploit activo y con las evidencias dentro del propio proyecto.
"""

from __future__ import annotations

import os
from pathlib import Path


PACKAGE_DIR = Path(__file__).resolve().parent
HOME = PACKAGE_DIR.parent
DEFAULT_EVIDENCE_DIR = HOME / "evidence"
PROFILE_DIR = HOME / "profiles"

DEFAULT_IMAGE = "rovvska/kali-tools:latest"
DEFAULT_CONTAINER = "rovska-kali"

# Capacidades necesarias para `nmap -O`, `-sS` y capturas ARP.
DOCKER_CAPS = ("NET_RAW", "NET_ADMIN")


def env_bool(name: str, default: bool = False) -> bool:
    """Lee un booleano de entorno con valores 1/true/yes/on."""
    raw = os.environ.get(name)
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on", "si", "sí"}


def evidence_dir() -> Path:
    raw = os.environ.get("MIDGARD_EVIDENCE", "").strip()
    return Path(raw).expanduser() if raw else DEFAULT_EVIDENCE_DIR


def docker_image() -> str:
    return os.environ.get("MIDGARD_IMAGE", DEFAULT_IMAGE).strip() or DEFAULT_IMAGE


def docker_container() -> str:
    return os.environ.get("MIDGARD_CONTAINER", DEFAULT_CONTAINER).strip() or DEFAULT_CONTAINER


def allow_public() -> bool:
    """Permitir objetivos fuera de RFC1918.

    Requiere MIDGARD_ALLOW_PUBLIC=1 **y** el flag --authorized en el comando.
    """
    return env_bool("MIDGARD_ALLOW_PUBLIC", False)


def allow_msf() -> bool:
    """Permitir ejecutar Metasploit (por defecto solo se generan planes .rc)."""
    return env_bool("MIDGARD_ALLOW_MSF", False)


def operator() -> str:
    return os.environ.get("MIDGARD_OPERATOR", "").strip() or os.environ.get("USER", "operador")
