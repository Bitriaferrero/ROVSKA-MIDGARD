#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Configuración central de ROVSKA.

Todo se controla con variables de entorno (ver ``.env.example``). No se
instalan dependencias: el backend usa solo la biblioteca estándar de Python.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path


BASE_DIR = Path(__file__).resolve().parent.parent


def _env_bool(name: str, default: bool = False) -> bool:
    raw = os.environ.get(name)
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on", "si", "sí"}


def _env_int(name: str, default: int) -> int:
    try:
        return int(os.environ.get(name, "").strip())
    except (TypeError, ValueError):
        return default


def _env_path(name: str, default: Path) -> Path:
    raw = os.environ.get(name, "").strip()
    return Path(raw).expanduser().resolve() if raw else default


def _env_list(name: str) -> tuple[str, ...]:
    raw = os.environ.get(name, "")
    return tuple(part.strip() for part in raw.split(",") if part.strip())


@dataclass(frozen=True)
class Settings:
    """Configuración inmutable de una ejecución."""

    base_dir: Path = BASE_DIR
    data_dir: Path = BASE_DIR / "data"
    db_path: Path = BASE_DIR / "data" / "rovska.db"
    reports_dir: Path = BASE_DIR / "data" / "reports"
    evidence_dir: Path = BASE_DIR / "data" / "evidence"
    work_dir: Path = BASE_DIR / "data" / "work"
    web_dir: Path = BASE_DIR / "web"

    host: str = "127.0.0.1"
    port: int = 8780
    api_token: str = ""

    runner: str = "docker"
    container: str = "rovska-kali"

    allowed_cidrs: tuple[str, ...] = ()
    allow_public: bool = False
    allow_attack: bool = False
    max_hosts: int = 256
    tool_timeout: int = 900

    opencode_enabled: bool = True
    opencode_bin: str = "opencode"
    opencode_model: str = "opencode/deepseek-v4.1-flash-free"
    opencode_timeout: int = 300

    extra: dict = field(default_factory=dict)

    def ensure_dirs(self) -> None:
        for path in (self.data_dir, self.reports_dir, self.evidence_dir, self.work_dir):
            try:
                path.mkdir(parents=True, exist_ok=True)
            except OSError as exc:
                raise PermissionError(
                    f"no se puede crear {path}: {exc}. Revisa ROVSKA_DATA_DIR y sus permisos."
                ) from exc
            if not os.access(path, os.W_OK):
                raise PermissionError(
                    f"{path} no es escribible por el UID {os.getuid()}. "
                    "Si el contenedor lo creó como root, ejecuta 'rovvska init' "
                    "antes de 'docker compose up' o ajusta el propietario del directorio."
                )


def load_settings() -> Settings:
    """Construye la configuración a partir del entorno."""

    data_dir = _env_path("ROVSKA_DATA_DIR", BASE_DIR / "data")
    settings = Settings(
        base_dir=BASE_DIR,
        data_dir=data_dir,
        db_path=_env_path("ROVSKA_DB_PATH", data_dir / "rovska.db"),
        reports_dir=_env_path("ROVSKA_REPORTS_DIR", data_dir / "reports"),
        evidence_dir=_env_path("ROVSKA_EVIDENCE_DIR", data_dir / "evidence"),
        work_dir=_env_path("ROVSKA_WORK_DIR", data_dir / "work"),
        web_dir=_env_path("ROVSKA_WEB_DIR", BASE_DIR / "web"),
        host=os.environ.get("ROVSKA_HOST", "127.0.0.1").strip() or "127.0.0.1",
        port=_env_int("ROVSKA_PORT", 8780),
        api_token=os.environ.get("ROVSKA_API_TOKEN", "").strip(),
        runner=os.environ.get("ROVSKA_RUNNER", "docker").strip().lower() or "docker",
        container=os.environ.get("ROVSKA_CONTAINER", "rovska-kali").strip() or "rovska-kali",
        allowed_cidrs=_env_list("ROVSKA_ALLOWED_CIDRS"),
        allow_public=_env_bool("ROVSKA_ALLOW_PUBLIC", False),
        allow_attack=_env_bool("ROVSKA_ALLOW_ATTACK", False),
        max_hosts=_env_int("ROVSKA_MAX_HOSTS", 256),
        tool_timeout=_env_int("ROVSKA_TOOL_TIMEOUT", 900),
        opencode_enabled=_env_bool("ROVSKA_OPENCODE_ENABLED", True),
        opencode_bin=os.environ.get("ROVSKA_OPENCODE_BIN", "opencode").strip() or "opencode",
        opencode_model=os.environ.get(
            "ROVSKA_OPENCODE_MODEL", "opencode/deepseek-v4.1-flash-free"
        ).strip()
        or "opencode/deepseek-v4.1-flash-free",
        opencode_timeout=_env_int("ROVSKA_OPENCODE_TIMEOUT", 300),
    )
    settings.ensure_dirs()
    return settings


_SETTINGS: Settings | None = None


def get_settings() -> Settings:
    """Configuración vigente, cargada una sola vez por proceso."""
    global _SETTINGS
    if _SETTINGS is None:
        _SETTINGS = load_settings()
    return _SETTINGS


def reset_settings() -> Settings:
    """Recarga la configuración desde el entorno.

    Pensado para tests y para herramientas que cambian ``ROVSKA_*`` antes de
    tocar la base de datos. Los módulos importan ``SETTINGS`` (un proxy), así
    que ven el cambio sin reiniciar el proceso.
    """
    global _SETTINGS
    _SETTINGS = load_settings()
    return _SETTINGS


class _SettingsProxy:
    """Delegación perezosa para que ``SETTINGS`` siga siendo un singleton vivo."""

    def __getattr__(self, name: str):
        return getattr(get_settings(), name)

    def __repr__(self) -> str:  # pragma: no cover - ayuda de depuración
        return repr(get_settings())


SETTINGS = _SettingsProxy()
