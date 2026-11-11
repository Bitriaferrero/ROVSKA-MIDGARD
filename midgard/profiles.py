"""Perfiles de escaneo declarativos.

Los perfiles viven en `profiles/*.json` y no contienen código. Así se
pueden revisar y versionar sin tocar el motor.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from pathlib import Path

from . import config


class ProfileError(ValueError):
    """Perfil inexistente o mal formado."""


@dataclass(frozen=True)
class Profile:
    id: str
    label: str
    description: str
    scan: tuple[str, ...] = ()
    mode: str = "scan"  # "scan" | "discovery"
    version: bool = True
    os: bool = True
    timing: str = "-T4"
    ports_tcp: str = ""
    ports_udp: str = ""
    udp: bool = False
    scripts: tuple[str, ...] = ()
    extra_args: tuple[str, ...] = ()
    timeout: int = 900

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "label": self.label,
            "description": self.description,
            "mode": self.mode,
            "scan": list(self.scan),
            "version": self.version,
            "os": self.os,
            "timing": self.timing,
            "ports_tcp": self.ports_tcp,
            "ports_udp": self.ports_udp,
            "udp": self.udp,
            "scripts": list(self.scripts),
            "extra_args": list(self.extra_args),
            "timeout": self.timeout,
        }


def _profile_dir() -> Path:
    raw = os.environ.get("MIDGARD_PROFILES", "").strip()
    return Path(raw).expanduser() if raw else config.PROFILE_DIR


def _load_one(path: Path) -> Profile:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ProfileError(f"no se pudo leer {path.name}: {exc}") from exc
    if not isinstance(data, dict):
        raise ProfileError(f"{path.name}: el perfil debe ser un objeto JSON")

    pid = str(data.get("id") or path.stem).strip()
    if not pid:
        raise ProfileError(f"{path.name}: falta 'id'")

    def _list(key: str) -> tuple[str, ...]:
        raw = data.get(key, [])
        if not isinstance(raw, list):
            raise ProfileError(f"{path.name}: '{key}' debe ser una lista")
        return tuple(str(x) for x in raw)

    mode = str(data.get("mode", "scan"))
    if mode not in {"scan", "discovery"}:
        raise ProfileError(f"{path.name}: 'mode' debe ser scan o discovery")

    return Profile(
        id=pid,
        label=str(data.get("label") or pid),
        description=str(data.get("description") or ""),
        scan=_list("scan"),
        mode=mode,
        version=bool(data.get("version", True)),
        os=bool(data.get("os", True)),
        timing=str(data.get("timing", "-T4")),
        ports_tcp=str(data.get("ports_tcp", "")),
        ports_udp=str(data.get("ports_udp", "")),
        udp=bool(data.get("udp", False)),
        scripts=_list("scripts"),
        extra_args=_list("extra_args"),
        timeout=int(data.get("timeout", 900)),
    )


def load_all() -> dict[str, Profile]:
    directory = _profile_dir()
    if not directory.is_dir():
        raise ProfileError(f"no existe el directorio de perfiles: {directory}")
    profiles: dict[str, Profile] = {}
    for path in sorted(directory.glob("*.json")):
        profile = _load_one(path)
        profiles[profile.id] = profile
    if not profiles:
        raise ProfileError(f"no hay perfiles en {directory}")
    return profiles


def get(profile_id: str) -> Profile:
    profiles = load_all()
    try:
        return profiles[profile_id]
    except KeyError as exc:
        raise ProfileError(
            f"perfil desconocido: {profile_id!r}. Disponibles: {', '.join(sorted(profiles))}"
        ) from exc
