#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Integración de MIDGARD y NETMAP dentro del panel ROVSKA.

Expone trabajos en segundo plano (sin IA en runtime) y lectura de resultados:

  - MIDGARD: lanza ``python3 -m midgard scan`` y guarda log/estado.
  - NETMAP:  lanza ``python3 netmap/netmap.py`` y lee ``netmap/map/scan.json``.

Todo se ejecuta en local, con las mismas reglas de alcance de MIDGARD.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import signal
import subprocess
import sys
import threading
import time
import uuid
from collections import deque
from datetime import datetime
from pathlib import Path

from .config import SETTINGS

ROOT = Path(SETTINGS.base_dir)
PROFILES_DIR = ROOT / "profiles"
EVIDENCE_DIR = ROOT / "evidence"
NETMAP_DIR = ROOT / "netmap"
NETMAP_MAP = NETMAP_DIR / "map"
WORK_DIR = Path(SETTINGS.work_dir) / "integrations"

_LOCK = threading.Lock()
_JOBS: dict[str, dict] = {}
_MAX_LOG = 2000

_SAFE_TARGET = re.compile(r"^[A-Za-z0-9_.:/\-]{1,100}$")
_SAFE_PROFILE = re.compile(r"^[A-Za-z0-9_\-]{1,32}$")
_SAFE_IFACE = re.compile(r"^[A-Za-z0-9_.:\-]{1,32}$")


def _now() -> str:
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def _ensure_work() -> None:
    WORK_DIR.mkdir(parents=True, exist_ok=True)


def _last_line(job: dict) -> str:
    log = job.get("log") or job.get("log_tail") or []
    if not log:
        return ""
    return str(log[-1]).strip()


def _public_job(job: dict, with_log: bool = False, live: bool = False) -> dict:
    data = {
        "id": job["id"],
        "kind": job["kind"],
        "label": job.get("label", ""),
        "target": job.get("target", ""),
        "status": job["status"],
        "started_at": job.get("started_at", ""),
        "finished_at": job.get("finished_at", ""),
        "exit_code": job.get("exit_code"),
        "command": job.get("command", []),
        "error": job.get("error", ""),
        "pid": int(job.get("pid") or 0),
        "live": live,
        "cancelled": bool(job.get("cancel_requested")),
        "last_line": _last_line(job),
    }
    if with_log:
        data["log"] = list(job.get("log", []))[-500:]
    return data


def _persist(job: dict) -> None:
    _ensure_work()
    path = WORK_DIR / f"{job['id']}.json"
    payload = _public_job(job)
    payload["log_tail"] = list(job.get("log", []))[-200:]
    try:
        path.write_text(json.dumps(payload, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    except OSError:
        pass


def _drain_log(job: dict, log_path: Path, position: int) -> int:
    """Copia al búfer en memoria las líneas nuevas del log en disco."""
    try:
        with log_path.open("r", encoding="utf-8", errors="replace") as handle:
            handle.seek(position)
            lines = handle.readlines()
            for line in lines:
                job["log"].append(line.rstrip("\n"))
            return handle.tell()
    except OSError:
        return position


def _reader(
    job: dict, proc: subprocess.Popen, log_path: Path, log_handle
) -> None:
    """Sigue el log en disco y espera al proceso.

    El hijo escribe directamente en el fichero, no en una tubería: así la
    salida sobrevive a un reinicio del panel y un trabajo adoptado puede
    seguir mostrando su progreso.
    """
    position = 0
    try:
        while proc.poll() is None:
            position = _drain_log(job, log_path, position)
            time.sleep(0.5)
        position = _drain_log(job, log_path, position)
        code = proc.wait()
    except Exception as exc:  # noqa: BLE001
        job["log"].append(f"[error] {exc}")
        code = -1
    finally:
        try:
            log_handle.close()
        except OSError:
            pass
    with _LOCK:
        job["exit_code"] = code
        if job.get("cancel_requested"):
            job["status"] = "cancelled"
            job["exit_code"] = 130
            job["error"] = ""
        else:
            job["status"] = "ok" if code == 0 else "error"
            if code != 0 and not job.get("error"):
                job["error"] = f"código de salida {code}"
        job["finished_at"] = _now()
    _persist(job)


def _spawn(kind: str, label: str, argv: list[str], cwd: Path, target: str = "") -> dict:
    _ensure_work()
    with _LOCK:
        for running in _JOBS.values():
            if running["kind"] == kind and running["status"] == "running":
                raise RuntimeError(f"ya hay un trabajo {kind} en curso")
        job_id = f"{kind}-{datetime.now():%Y%m%d-%H%M%S}-{uuid.uuid4().hex[:6]}"
        job = {
            "id": job_id,
            "kind": kind,
            "label": label,
            "target": target,
            "status": "running",
            "started_at": _now(),
            "finished_at": "",
            "exit_code": None,
            "command": argv,
            "log": deque(maxlen=_MAX_LOG),
        }
        _JOBS[job_id] = job

    env = os.environ.copy()
    env.setdefault("PYTHONUNBUFFERED", "1")
    log_path = WORK_DIR / f"{job_id}.log"
    log_handle = log_path.open("a", encoding="utf-8")
    try:
        proc = subprocess.Popen(  # noqa: S603 - argv sin shell
            argv,
            cwd=str(cwd),
            stdout=log_handle,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1,
            env=env,
            start_new_session=True,
        )
    except Exception:
        log_handle.close()
        raise
    with _LOCK:
        job["pid"] = proc.pid
        job["proc"] = proc
    _persist(job)
    threading.Thread(
        target=_reader, args=(job, proc, log_path, log_handle), daemon=True
    ).start()
    return _public_job(job)


def _pid_alive(pid: int, kind: str) -> bool:
    if pid <= 0:
        return False
    try:
        os.kill(pid, 0)
    except OSError:
        return False
    try:
        cmdline = Path(f"/proc/{pid}/cmdline").read_bytes().replace(b"\0", b" ").decode(
            "utf-8", "replace"
        )
    except OSError:
        return False
    needle = "netmap" if kind == "netmap" else "midgard"
    return needle in cmdline


def _log_file_tail(job_id: str, limit: int = 500) -> list[str]:
    path = WORK_DIR / f"{Path(job_id).name}.log"
    if not path.is_file():
        return []
    try:
        with path.open("r", encoding="utf-8", errors="replace") as handle:
            return [line.rstrip("\n") for line in deque(handle, maxlen=limit)]
    except OSError:
        return []


def _log_finished_at(job_id: str) -> str:
    path = WORK_DIR / f"{Path(job_id).name}.log"
    try:
        return datetime.fromtimestamp(path.stat().st_mtime).strftime("%Y-%m-%d %H:%M:%S")
    except OSError:
        return ""


def _iso_to_local(value: str) -> str:
    text = str(value or "").strip()
    if not text:
        return ""
    try:
        stamp = datetime.fromisoformat(text.replace("Z", "+00:00"))
        return stamp.astimezone().strftime("%Y-%m-%d %H:%M:%S")
    except ValueError:
        return text


def _reconcile_from_log(data: dict) -> None:
    """Deduce el estado final de un trabajo huérfano a partir de su log.

    Si el panel se reinició mientras el proceso seguía vivo, el lector de la
    tubería desapareció y el JSON puede quedarse en ``running`` para siempre.
    La última línea del log sí dice cómo terminó la ejecución.
    """
    lines = [
        line.strip()
        for line in _log_file_tail(str(data.get("id") or ""), limit=60)
        if line.strip()
    ]
    if not lines:
        return
    tail = lines[-8:]
    joined = "\n".join(tail)
    status = ""
    exit_code = 0
    if "manifiesto:" in joined and "[ok]" in joined:
        status = "ok"  # MIDGARD terminó y guardó su evidencia
    elif "terminó con estado timeout" in joined:
        status = "timeout"
        exit_code = 1
    elif any(line.startswith("OK:") for line in tail) and not any(
        line.startswith("[error]") for line in tail
    ):
        status = "ok"  # NETMAP terminó y escribió el mapa
    elif any(line.startswith("[error]") for line in tail):
        status = "error"
        exit_code = 1
    if not status:
        return
    data["status"] = status
    data["exit_code"] = exit_code
    data["finished_at"] = _log_finished_at(str(data.get("id") or ""))
    if status != "ok" and not data.get("error"):
        data["error"] = f"estado final {status} según el log"


def _reconcile_from_evidence(data: dict) -> None:
    """Cruza un trabajo MIDGARD huérfano con la evidencia ya escrita."""
    if str(data.get("kind") or "") != "midgard":
        return
    started = str(data.get("started_at") or "")
    try:
        prefix = datetime.strptime(started, "%Y-%m-%d %H:%M:%S").strftime("%Y%m%d-%H%M%S")
    except ValueError:
        return
    target = str(data.get("target") or "")
    if not EVIDENCE_DIR.is_dir():
        return
    for path in sorted(EVIDENCE_DIR.iterdir(), reverse=True):
        if not path.is_dir() or not path.name.startswith(prefix):
            continue
        manifest_path = path / "manifest.json"
        if not manifest_path.is_file():
            continue
        try:
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        if target and str(manifest.get("target") or "") not in {"", target}:
            continue
        status = str(manifest.get("status") or "").lower() or "ok"
        data["status"] = status
        data["exit_code"] = 0 if status == "ok" else 1
        data["finished_at"] = _iso_to_local(str(manifest.get("created_at") or ""))
        if status != "ok" and not data.get("error"):
            data["error"] = f"estado final {status} según la evidencia"
        return


def _adopt_persisted(data: dict) -> dict:
    """Marca como vivo un trabajo que sigue ejecutándose tras reiniciar el panel."""
    kind = str(data.get("kind") or "")
    pid = int(data.get("pid") or 0)
    status = str(data.get("status") or "").lower()
    live = status in {"running", "queued"} and _pid_alive(pid, kind)
    data["live"] = live
    if live:
        data["status"] = "running"
    elif status in {"running", "queued"}:
        # El proceso ya no existe: recupera el final real del log o de la
        # evidencia en vez de dejar el trabajo como activo de por vida.
        _reconcile_from_log(data)
        if str(data.get("status") or "").lower() in {"running", "queued"}:
            _reconcile_from_evidence(data)
        if str(data.get("status") or "").lower() in {"running", "queued"}:
            data["status"] = "interrupted"
            if not data.get("error"):
                data["error"] = "el panel se reinició y el proceso desapareció"
            if not data.get("finished_at"):
                data["finished_at"] = _log_finished_at(str(data.get("id") or ""))
    data.setdefault("last_line", _last_line(data))
    return data


def _kill_midgard_container(started_at: str) -> None:
    """Mata el contenedor efímero de una auditoría MIDGARD en curso."""
    text = str(started_at or "").strip()
    try:
        prefix = datetime.strptime(text, "%Y-%m-%d %H:%M:%S").strftime("%Y%m%d-%H%M%S")
    except ValueError:
        return
    if not shutil.which("docker"):
        return
    try:
        listed = subprocess.run(  # noqa: S603 - argv sin shell
            ["docker", "ps", "--filter", f"name=midgard-{prefix}", "--format", "{{.Names}}"],
            capture_output=True,
            text=True,
            timeout=20,
        )
    except (OSError, subprocess.SubprocessError):
        return
    for name in (listed.stdout or "").split():
        if not name.startswith("midgard-"):
            continue
        try:
            subprocess.run(  # noqa: S603 - nombre validado
                ["docker", "kill", name],
                capture_output=True,
                text=True,
                timeout=30,
            )
        except (OSError, subprocess.SubprocessError):
            continue


def _mark_midgard_evidence_cancelled(job: dict) -> None:
    """Deja la evidencia parcial de un MIDGARD cancelado como ``cancelled``.

    Si el proceso murió antes de escribir ``manifest.json``, la ejecución
    quedaría invisible o como estado desconocido. Se escribe un manifiesto
    mínimo para que la vista MIDGARD muestre la cancelación y nunca la dé por
    buena. Un manifiesto ya escrito por una ejecución terminada no se toca.
    """
    if str(job.get("kind") or "") != "midgard":
        return
    started = str(job.get("started_at") or "").strip()
    try:
        prefix = datetime.strptime(started, "%Y-%m-%d %H:%M:%S").strftime("%Y%m%d-%H%M%S")
    except ValueError:
        return
    if not EVIDENCE_DIR.is_dir():
        return
    target = str(job.get("target") or "")
    label = str(job.get("label") or "")
    profile = label.split("·", 1)[0].strip() if "·" in label else ""
    target_slug = re.sub(r"[^0-9A-Za-z]+", "_", target).strip("_")
    for path in sorted(EVIDENCE_DIR.iterdir(), reverse=True):
        if not path.is_dir() or not path.name.startswith(prefix):
            continue
        if target_slug and target_slug not in path.name:
            continue
        if (path / "manifest.json").is_file():
            continue
        manifest = {
            "tool": "MIDGARD",
            "run_id": path.name,
            "target": target or "?",
            "profile": profile or "?",
            "created_at": datetime.now().astimezone().isoformat(timespec="seconds"),
            "finished_at": datetime.now().astimezone().isoformat(timespec="seconds"),
            "status": "cancelled",
            "returncode": 130,
            "timed_out": False,
            "error": "cancelado por el usuario",
            "ai_runtime": False,
            "telemetry": False,
        }
        try:
            (path / "manifest.json").write_text(
                json.dumps(manifest, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
            )
        except OSError:
            pass
        return


def _terminate(pid: int, kind: str, started_at: str = "") -> None:
    """Detiene el grupo de proceso del trabajo y, en MIDGARD, su contenedor."""
    if kind == "midgard":
        _kill_midgard_container(started_at)
    if pid <= 0:
        return
    try:
        pgid = os.getpgid(pid)
    except OSError:
        return
    try:
        if pgid == pid:
            os.killpg(pgid, signal.SIGTERM)
        else:
            os.kill(pid, signal.SIGTERM)
    except OSError:
        return
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline:
        if not _pid_alive(pid, kind):
            return
        time.sleep(0.2)
    try:
        if pgid == pid:
            os.killpg(pgid, signal.SIGKILL)
        else:
            os.kill(pid, signal.SIGKILL)
    except OSError:
        pass


def cancel_job(job_id: str) -> dict | None:
    """Cancela un trabajo MIDGARD/NETMAP en curso (memoria o persistido)."""
    job = _JOBS.get(job_id)
    if job is not None:
        with _LOCK:
            if job["status"] not in {"running", "queued", "cancelling"}:
                return _public_job(job, live=False)
            job["cancel_requested"] = True
            job["status"] = "cancelling"
        _terminate(int(job.get("pid") or 0), str(job.get("kind") or ""), str(job.get("started_at") or ""))
        _mark_midgard_evidence_cancelled(job)
        with _LOCK:
            job["status"] = "cancelled"
            job["finished_at"] = _now()
            job["exit_code"] = 130
            job["error"] = ""
        _persist(job)
        return _public_job(job, live=False)

    _ensure_work()
    path = WORK_DIR / f"{Path(job_id).name}.json"
    if not path.is_file():
        return None
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    data = _adopt_persisted(data)
    if str(data.get("status") or "").lower() not in {
        "running",
        "queued",
        "cancelling",
        "interrupted",
    }:
        return data
    if data.get("live"):
        _terminate(
            int(data.get("pid") or 0),
            str(data.get("kind") or ""),
            str(data.get("started_at") or ""),
        )
    _mark_midgard_evidence_cancelled(data)
    data["status"] = "cancelled"
    data["finished_at"] = _now()
    data["exit_code"] = 130
    data["live"] = False
    data["cancelled"] = True
    data["error"] = ""
    try:
        path.write_text(
            json.dumps(data, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
        )
    except OSError:
        pass
    return data


def get_job(job_id: str) -> dict | None:
    job = _JOBS.get(job_id)
    if job:
        return _public_job(job, with_log=True, live=True)
    # trabajos de una ejecución anterior del panel
    _ensure_work()
    path = WORK_DIR / f"{Path(job_id).name}.json"
    if path.is_file():
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return None
        data = _adopt_persisted(data)
        lines = _log_file_tail(job_id)
        if lines:
            data["log"] = lines[-500:]
            data["last_line"] = lines[-1]
        return data
    return None


def list_jobs(kind: str | None = None) -> list[dict]:
    rows: dict[str, dict] = {}
    for job in _JOBS.values():
        rows[job["id"]] = _public_job(job, live=True)
    _ensure_work()
    for path in WORK_DIR.glob("*.json"):
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        data = _adopt_persisted(data)
        if data.get("status") == "running" and data.get("live"):
            tail = _log_file_tail(str(data.get("id", path.stem)), limit=1)
            if tail:
                data["last_line"] = tail[-1]
        rows.setdefault(data.get("id", path.stem), data)
    result = [row for row in rows.values() if not kind or row.get("kind") == kind]
    result.sort(key=lambda row: row.get("started_at", ""), reverse=True)
    return result[:50]


def profiles() -> list[dict]:
    rows = []
    if PROFILES_DIR.is_dir():
        for path in sorted(PROFILES_DIR.glob("*.json")):
            try:
                data = json.loads(path.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                continue
            rows.append(
                {
                    "id": data.get("id", path.stem),
                    "label": data.get("label", path.stem),
                    "description": data.get("description", ""),
                }
            )
    rows.sort(key=lambda row: (row["id"] != "discovery", row["id"] != "quick", row["id"]))
    return rows


def start_midgard(target: str, profile: str, authorized: bool) -> dict:
    target = (target or "").strip()
    profile = (profile or "quick").strip()
    if not _SAFE_TARGET.match(target):
        raise ValueError("objetivo no válido")
    if not _SAFE_PROFILE.match(profile):
        raise ValueError("perfil no válido")
    if profile not in {row["id"] for row in profiles()}:
        raise ValueError("perfil desconocido")
    argv = [
        sys.executable,
        "-m",
        "midgard",
        "scan",
        target,
        "--profile",
        profile,
        "-y",
    ]
    if authorized:
        argv.append("--authorized")
    return _spawn("midgard", f"{profile} · {target}", argv, ROOT, target=target)


def start_netmap(iface: str) -> dict:
    iface = (iface or "wlan0").strip()
    if not _SAFE_IFACE.match(iface):
        raise ValueError("interfaz no válida")
    argv = [sys.executable, str(NETMAP_DIR / "netmap.py"), "--iface", iface]
    return _spawn("netmap", f"barrido · {iface}", argv, ROOT, target=iface)


def midgard_runs(limit: int = 30) -> list[dict]:
    rows = []
    if not EVIDENCE_DIR.is_dir():
        return rows
    for path in sorted(EVIDENCE_DIR.iterdir(), key=lambda p: p.name, reverse=True):
        if not path.is_dir():
            continue
        manifest_path = path / "manifest.json"
        if not manifest_path.is_file():
            continue
        try:
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            manifest = {}
        rows.append(
            {
                "run_id": path.name,
                "target": manifest.get("target", "?"),
                "profile": manifest.get("profile", "?"),
                "status": manifest.get("status", "?"),
                "created_at": manifest.get("created_at", ""),
                "hosts": (manifest.get("counts") or {}).get("hosts", 0),
            }
        )
        if len(rows) >= limit:
            break
    return rows


def midgard_run(run_id: str) -> dict:
    safe = Path(run_id).name
    if safe != run_id or not safe:
        raise ValueError("run_id no válido")
    path = EVIDENCE_DIR / safe
    if not path.is_dir():
        raise FileNotFoundError("ejecución no encontrada")
    manifest = {}
    if (path / "manifest.json").is_file():
        manifest = json.loads((path / "manifest.json").read_text(encoding="utf-8"))
    artifacts = sorted(
        [
            {"name": item.name, "bytes": item.stat().st_size}
            for item in path.iterdir()
            if item.is_file()
        ],
        key=lambda item: item["name"],
    )
    report_text = ""
    for name in ("report.md", "report.txt", "summary.md"):
        candidate = path / name
        if candidate.is_file():
            report_text = candidate.read_text(encoding="utf-8", errors="replace")[:200_000]
            break
    hosts: list[dict] = []
    hosts_path = path / "hosts.json"
    if hosts_path.is_file():
        try:
            payload = json.loads(hosts_path.read_text(encoding="utf-8"))
            hosts = payload.get("hosts") or []
        except (OSError, json.JSONDecodeError):
            hosts = []
    return {
        "run_id": safe,
        "manifest": manifest,
        "artifacts": artifacts,
        "report": report_text,
        "hosts": hosts,
    }


def netmap_data() -> dict:
    path = NETMAP_MAP / "scan.json"
    if not path.is_file():
        return {"hosts": [], "ssid": None, "generated": None, "notes": "sin datos"}
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {"hosts": [], "ssid": None, "generated": None, "notes": "datos ilegibles"}


def overview() -> dict:
    data = netmap_data()
    return {
        "midgard": {
            "profiles": profiles(),
            "runs": midgard_runs(10),
            "jobs": list_jobs("midgard")[:10],
        },
        "netmap": {
            "generated": data.get("generated"),
            "ssid": data.get("ssid"),
            "hosts": len(data.get("hosts") or []),
            "jobs": list_jobs("netmap")[:10],
        },
    }
