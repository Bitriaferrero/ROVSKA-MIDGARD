"""Evidencias: directorios por ejecución, hashes y manifiesto.

Cada escaneo deja una carpeta autocontenida y verificable. El manifiesto
incluye los hashes SHA-256 de todos los artefactos y declara explícitamente
que no hubo IA ni telemetría en runtime.
"""

from __future__ import annotations

import hashlib
import json
import re
import shutil
from datetime import datetime, timezone
from pathlib import Path

from . import __version__, config


def now_iso() -> str:
    return datetime.now(timezone.utc).astimezone().isoformat(timespec="seconds")


def _slug(value: str, limit: int = 40) -> str:
    cleaned = re.sub(r"[^A-Za-z0-9]+", "_", value).strip("_")
    return (cleaned or "target")[:limit]


def runs_dir() -> Path:
    directory = config.evidence_dir()
    directory.mkdir(parents=True, exist_ok=True)
    return directory


def new_run(target: str, profile: str) -> Path:
    stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    base = f"{stamp}-{_slug(profile, 20)}-{_slug(target, 40)}"
    directory = runs_dir()
    candidate = directory / base
    counter = 2
    while candidate.exists():
        candidate = directory / f"{base}-{counter}"
        counter += 1
    candidate.mkdir(parents=True)
    return candidate


def run_path(run_id: str) -> Path:
    candidate = runs_dir() / run_id
    if not candidate.is_dir():
        raise FileNotFoundError(f"no existe la ejecución: {run_id}")
    if candidate.parent.resolve() != runs_dir().resolve():
        raise ValueError("run_id no válido")
    return candidate


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def write_json(path: Path, data) -> None:
    path.write_text(
        json.dumps(data, indent=2, ensure_ascii=False, sort_keys=False) + "\n",
        encoding="utf-8",
    )


def write_manifest(run_dir: Path, meta: dict) -> dict:
    artifacts = {}
    for path in sorted(run_dir.iterdir()):
        if not path.is_file() or path.name == "manifest.json":
            continue
        artifacts[path.name] = {
            "sha256": sha256_file(path),
            "bytes": path.stat().st_size,
        }

    manifest = {
        "tool": "MIDGARD",
        "version": __version__,
        "run_id": run_dir.name,
        "manifest_at": now_iso(),
        "ai_runtime": False,
        "telemetry": False,
        "external_network": "solo el objetivo autorizado",
        "artifacts": artifacts,
    }
    manifest.update(meta)
    write_json(run_dir / "manifest.json", manifest)
    return manifest


def read_manifest(run_dir: Path) -> dict:
    path = run_dir / "manifest.json"
    if not path.is_file():
        return {}
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}


def refresh_manifest(run_dir: Path) -> dict:
    """Recalcula los hashes tras añadir artefactos (p. ej. msf_plan.rc)."""
    manifest = read_manifest(run_dir)
    if not manifest:
        return {}
    meta = {
        key: value
        for key, value in manifest.items()
        if key not in {"artifacts", "manifest_at", "tool", "version", "run_id"}
    }
    return write_manifest(run_dir, meta)


def list_runs() -> list[dict]:
    directory = runs_dir()
    runs: list[dict] = []
    for path in sorted(directory.iterdir(), reverse=True):
        if not path.is_dir():
            continue
        manifest = read_manifest(path)
        runs.append(
            {
                "run_id": path.name,
                "path": str(path),
                "target": manifest.get("target", "?"),
                "profile": manifest.get("profile", "?"),
                "status": manifest.get("status", "?"),
                "created_at": manifest.get("created_at", ""),
                "hosts": (manifest.get("counts") or {}).get("hosts", 0),
            }
        )
    return runs


def prune(max_runs: int) -> int:
    """Borra las ejecuciones más antiguas conservando `max_runs`."""
    if max_runs <= 0:
        return 0
    directories = [p for p in runs_dir().iterdir() if p.is_dir()]
    directories.sort(key=lambda p: p.stat().st_mtime, reverse=True)
    removed = 0
    for path in directories[max_runs:]:
        shutil.rmtree(path, ignore_errors=True)
        removed += 1
    return removed
