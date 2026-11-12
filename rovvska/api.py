#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""API HTTP y servidor del panel web de ROVSKA (solo biblioteca estándar).

Rutas principales:
  GET  /api/data              datos agregados para el panel
  POST /api/scans             lanzar un escaneo
  POST /api/operations        lanzar una herramienta
  GET  /api/tasks             tareas activas e historial
  GET  /api/operations/<id>/stream   log en vivo (SSE)
  GET  /api/attack            matriz ATT&CK
  GET  /api/frameworks        PTES/OSSTMM/OWASP/CWE
  GET  /api/compare           diferencias entre dos escaneos
  POST /api/import-report     importa un informe JSON/XML
  POST /api/orchestrate       plan/ejecución con OpenCode
"""

from __future__ import annotations

import hashlib
import ipaddress
import json
import mimetypes
import os
import re
import threading
import time
import traceback
import webbrowser
from collections import Counter, defaultdict
from datetime import datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, unquote, urlparse

from . import analyzer, compare, db, importer, integrations, orchestrator, proxmox, report, scanner
from .config import SETTINGS
from .jobs import JOBS
from .models import Host, Port, SEV_ORDER, SEV_WEIGHT, counts_by_severity, risk_meta
from .runner import get_runner
from .scope import ScopeError, check_target
from .tools import catalog, get_tool


TYPE_OPTIONS = [
    "",
    "Nodo Proxmox",
    "LXC",
    "VM",
    "Router",
    "Servidor",
    "Cliente / IoT",
    "Dispositivo",
    "Este equipo",
]

API_VERSION = "1.0.0"
_TOOLS_CACHE: dict = {"at": 0.0, "rows": []}
_HEALTH_CACHE: dict = {"at": 0.0, "data": {}}

# Ficheros que el formulario de Operaciones puede adjuntar. Solo se guardan en
# el directorio de trabajo de la operación; en la base de datos queda el nombre,
# el número de líneas y el SHA-256, nunca el contenido.
UPLOAD_FIELDS = {
    "users": ("users_file", "hydra_users_upload.txt", "usuarios"),
    "passwords": ("passwords_file", "hydra_passwords_upload.txt", "contraseñas"),
    "combo": ("combo_file", "hydra_combo_upload.txt", "pares usuario:contraseña"),
}
UPLOAD_MAX_BYTES = 1_000_000
UPLOAD_MAX_LINE = 4_096


def _store_operation_files(operation_id: str, files: dict) -> tuple[dict, str]:
    """Guarda las listas subidas y devuelve solo sus metadatos.

    El contenido se escribe con permisos ``600`` dentro del directorio de la
    operación. El JSON de parámetros que se persiste no incluye contraseñas.
    """

    workdir = SETTINGS.work_dir / operation_id
    try:
        workdir.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        return {}, f"no se pudo preparar el directorio de la operación: {exc}"
    meta: dict = {}
    for key, entry in files.items():
        config = UPLOAD_FIELDS.get(key)
        if config is None:
            return {}, f"campo de fichero desconocido: {key}"
        param, filename, label = config
        if not isinstance(entry, dict):
            return {}, f"formato de fichero no válido para {label}"
        content = entry.get("content")
        if not isinstance(content, str) or not content.strip():
            return {}, f"el fichero de {label} está vacío"
        if "\x00" in content:
            return {}, f"el fichero de {label} no es texto válido"
        if len(content.encode("utf-8")) > UPLOAD_MAX_BYTES:
            return {}, f"el fichero de {label} supera 1 MB"
        lines: list[str] = []
        seen: set[str] = set()
        for line in content.splitlines():
            line = line.strip()
            if not line or line in seen:
                continue
            if key == "combo" and ":" not in line:
                continue
            seen.add(line)
            lines.append(line)
        if not lines:
            return {}, f"el fichero de {label} está vacío"
        if any(len(line) > UPLOAD_MAX_LINE for line in lines):
            return {}, f"el fichero de {label} tiene líneas demasiado largas"
        path = workdir / filename
        try:
            path.write_text("\n".join(lines) + "\n", encoding="utf-8")
            os.chmod(path, 0o600)
        except OSError as exc:
            return {}, f"no se pudo guardar el fichero de {label}: {exc}"
        meta[param] = filename
        meta[f"{key}_lines"] = len(lines)
        meta[f"{key}_sha256"] = hashlib.sha256(
            "\n".join(lines).encode("utf-8")
        ).hexdigest()
    return meta, ""


def _ip_key(value: str):
    try:
        ip = ipaddress.ip_address(value)
        return (ip.version, int(ip))
    except ValueError:
        return (99, value)


def _safe_report_name(name: str) -> str | None:
    name = Path(name).name
    if not re.match(r"^informe_[A-Za-z0-9_.-]+\.(json|xml|html|pdf|sarif|csv)$", name):
        return None
    return name


def _host_risk(findings: list[dict]) -> tuple[int, dict, dict]:
    counts = {sev: 0 for sev in SEV_ORDER}
    for finding in findings:
        counts[finding.get("severity", "INFO")] = counts.get(finding.get("severity", "INFO"), 0) + 1
    score = min(100, sum(SEV_WEIGHT.get(f.get("severity", ""), 0) for f in findings))
    return score, counts, risk_meta(score, counts, len(findings))


def _refresh_host_os(host: dict) -> None:
    """Recalcula SO y tipo con la heurística actual sin tocar la base de datos.

    Así los escaneos antiguos también muestran Ubuntu/Debian/Proxmox/LXC/VM en
    la lista de IPs tras actualizar el motor, sin necesidad de repetir el escaneo.
    """
    try:
        model = Host(
            ip=str(host.get("ip") or ""),
            mac=str(host.get("mac") or ""),
            vendor=str(host.get("vendor") or ""),
            hostnames=list(host.get("hostnames") or []),
            os=str(host.get("os") or ""),
            type=str(host.get("type") or ""),
            extra=dict(host.get("extra") or {}),
        )
        for raw in host.get("ports") or []:
            model.add_port(
                Port(
                    port=int(raw.get("port") or 0),
                    proto=str(raw.get("proto") or "tcp"),
                    service=str(raw.get("service") or raw.get("name") or ""),
                    product=str(raw.get("product") or ""),
                    version=str(raw.get("version") or ""),
                    extrainfo=str(raw.get("extrainfo") or ""),
                    scripts=dict(raw.get("scripts") or {}),
                )
            )
        analyzer.classify_host(model)
        host["os"] = model.os
        host["type"] = model.type
    except Exception:  # noqa: BLE001 - el panel nunca debe romperse por un host raro
        return


def _sweep_target(target: str) -> bool:
    """Un objetivo con más de una dirección es un barrido, no una IP suelta."""
    try:
        network = ipaddress.ip_network(str(target or "").strip(), strict=False)
    except ValueError:
        return False
    return network.num_addresses > 1


def _timestamp(value: str) -> float:
    text = str(value or "").strip()
    if not text:
        return 0.0
    try:
        return datetime.fromisoformat(text.replace("Z", "+00:00")).timestamp()
    except ValueError:
        return 0.0


def _midgard_started_at(name: str, manifest: dict) -> str:
    """El nombre del directorio guarda la hora de inicio; el manifiesto, la de fin."""
    match = re.match(r"^(\d{4})(\d{2})(\d{2})-(\d{2})(\d{2})(\d{2})", name)
    if match:
        return "{}-{}-{} {}:{}:{}".format(*match.groups())
    return str(manifest.get("created_at") or "")


def _midgard_os_name(value) -> str:
    if isinstance(value, str):
        return value.strip()
    if not isinstance(value, dict):
        return ""
    name = str(value.get("name") or "").strip()
    version = str(value.get("version") or "").strip()
    if name and version and version not in name:
        return f"{name} {version}"
    return name


def _midgard_host(raw: dict) -> dict:
    """Adapta un host de ``evidence/*/hosts.json`` al modelo del panel."""
    os_info = raw.get("os") if isinstance(raw.get("os"), dict) else {}
    model = Host(
        ip=str(raw.get("ip") or ""),
        mac=str(raw.get("mac") or ""),
        vendor=str(raw.get("vendor") or ""),
        hostnames=[str(item) for item in (raw.get("hostnames") or []) if item],
        os=_midgard_os_name(os_info),
        type=str(os_info.get("device") or ""),
        hostscripts={str(k): str(v) for k, v in (raw.get("scripts") or {}).items()},
        extra={
            "os_confidence": os_info.get("confidence", ""),
            "os_score": os_info.get("score", 0),
            "os_sources": list(os_info.get("sources") or []),
        },
    )
    for item in raw.get("ports") or []:
        if not isinstance(item, dict):
            continue
        state = str(item.get("state") or "open")
        if state not in {"open", "open|filtered"}:
            continue
        number = int(item.get("port") or 0)
        if not number:
            continue
        model.add_port(
            Port(
                port=number,
                proto=str(item.get("proto") or "tcp"),
                service=str(item.get("service") or item.get("name") or ""),
                product=str(item.get("product") or ""),
                version=str(item.get("version") or ""),
                extrainfo=str(item.get("extrainfo") or ""),
                scripts={str(k): str(v) for k, v in (item.get("scripts") or {}).items()},
            )
        )
    analyzer.classify_host(model)
    return model.to_dict()


def _midgard_events() -> list[dict]:
    """Ejecuciones MIDGARD ya terminadas, como eventos del mismo contexto."""
    events: list[dict] = []
    root = integrations.EVIDENCE_DIR
    if not root.is_dir():
        return events
    for path in root.iterdir():
        if not path.is_dir():
            continue
        manifest_path = path / "manifest.json"
        if not manifest_path.is_file():
            continue
        try:
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        hosts: list[dict] = []
        hosts_path = path / "hosts.json"
        if hosts_path.is_file():
            try:
                payload = json.loads(hosts_path.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                payload = {}
            for raw in payload.get("hosts") or []:
                if isinstance(raw, dict) and raw.get("ip"):
                    hosts.append(_midgard_host(raw))
        started = _midgard_started_at(path.name, manifest)
        status = str(manifest.get("status") or "ok").lower()
        target = str(manifest.get("target") or "")
        events.append(
            {
                "source": "midgard",
                "id": path.name,
                "target": target,
                "profile": str(manifest.get("profile") or ""),
                "mode": str(manifest.get("profile") or ""),
                "status": status,
                "scanned_at": started,
                "finished_at": str(manifest.get("created_at") or ""),
                "ts": _timestamp(started),
                "sweep": _sweep_target(target),
                "active": False,
                "ok": status == "ok",
                "hosts": hosts,
                "findings": [],
                "by_host": {},
                "good_checks": [],
                "proxmox": {},
                "attack": {},
                "frameworks": {},
                "limitations": [],
            }
        )
    return events


def _running_event(
    source: str, event_id: str, target: str, started_at: str, profile: str = ""
) -> dict:
    return {
        "source": source,
        "id": event_id,
        "target": target,
        "profile": profile,
        "mode": profile,
        "status": "running",
        "scanned_at": started_at,
        "finished_at": "",
        "ts": _timestamp(started_at),
        "sweep": _sweep_target(target),
        "active": True,
        "ok": False,
        "hosts": [],
        "findings": [],
        "by_host": {},
        "good_checks": [],
        "proxmox": {},
        "attack": {},
        "frameworks": {},
        "limitations": [],
    }


def _running_events() -> list[dict]:
    """Barridos en curso: limpian la lista desde el primer segundo."""
    events: list[dict] = []
    for job in JOBS.list():
        if job.get("kind") != "scan" or job.get("status") not in {"queued", "running"}:
            continue
        events.append(
            _running_event(
                "rovska",
                str(job.get("id") or ""),
                str(job.get("target") or ""),
                str(job.get("started_at") or ""),
            )
        )
    try:
        jobs = integrations.list_jobs("midgard")
    except Exception:  # noqa: BLE001 - una integración rota no debe tumbar el panel
        jobs = []
    for job in jobs:
        if str(job.get("status") or "").lower() != "running" or not job.get("live"):
            continue
        label = str(job.get("label") or "")
        profile = label.split(" · ", 1)[0] if " · " in label else label
        events.append(
            _running_event(
                "midgard",
                str(job.get("id") or ""),
                str(job.get("target") or ""),
                str(job.get("started_at") or ""),
                profile,
            )
        )
    return events


def build_payload() -> dict:
    scans = db.query("SELECT * FROM scans ORDER BY started_at ASC")
    reports: list[dict] = []
    for scan in scans:
        try:
            reports.append(report.build(scan["id"]))
        except Exception:  # noqa: BLE001
            continue

    events: list[dict] = []
    for rep in reports:
        by_host: dict[str, list[dict]] = defaultdict(list)
        for finding in rep.get("findings", []):
            by_host[finding.get("host", "")].append(finding)
        target = str(rep.get("target") or "")
        events.append(
            {
                "source": "rovska",
                "id": rep.get("scan_id", ""),
                "target": target,
                "profile": rep.get("profile", ""),
                "mode": rep.get("mode", "") or rep.get("profile", ""),
                "status": rep.get("status", ""),
                "scanned_at": rep.get("scanned_at", ""),
                "finished_at": rep.get("finished_at", ""),
                "ts": _timestamp(rep.get("scanned_at", "")),
                "sweep": _sweep_target(target),
                "active": False,
                "ok": rep.get("status") == "done",
                "hosts": rep.get("hosts", []),
                "findings": rep.get("findings", []),
                "by_host": by_host,
                "good_checks": rep.get("good_checks", []),
                "proxmox": rep.get("proxmox", {}),
                "attack": rep.get("attack", {}),
                "frameworks": rep.get("frameworks", {}),
                "limitations": rep.get("limitations", []),
            }
        )
    events += _midgard_events()
    events += _running_events()
    events.sort(key=lambda item: (item["ts"], 0 if item["source"] == "rovska" else 1))

    # Un barrido (subred) abre un contexto nuevo: lo anterior deja de mostrarse.
    # Los escaneos de una IP suelta se suman al contexto vigente. Nada se borra
    # de la base de datos: solo cambia lo que enseña la lista.
    host_map: dict[str, dict] = {}
    visible: list[dict] = []
    for event in events:
        if event["sweep"] and (event["ok"] or event["active"]):
            host_map = {}
            visible = []
        visible.append(event)
        scanned = event["scanned_at"]
        for host in event["hosts"]:
            ip = host.get("ip")
            if not ip:
                continue
            if event["source"] == "rovska":
                _refresh_host_os(host)
            entry = host_map.setdefault(
                ip, {"ip": ip, "history": [], "first_seen": scanned}
            )
            entry["history"].append(
                {
                    "scanned_at": scanned,
                    "scan_id": event["id"],
                    "source": event["source"],
                    "target": event["target"],
                    "profile": event["profile"],
                    "type": host.get("type", ""),
                    "os": host.get("os", ""),
                    "ports": len(host.get("ports", [])),
                    "risk": host.get("risk", 0),
                }
            )
            entry["last_seen"] = scanned
            entry["host"] = host
            entry["findings"] = event["by_host"].get(ip, [])
            entry["source"] = event["source"]

    # La cabecera debe describir el contexto que sostiene la lista, no un
    # barrido fallido o cancelado que no aportó nada.
    latest = None
    for event in visible:
        if event["ok"] or event["active"] or event["hosts"]:
            latest = event
    annotations = db.load_annotations()
    hosts: list[dict] = []
    for ip, entry in host_map.items():
        host = dict(entry.get("host") or {})
        host["ip"] = ip
        ann = annotations.get(ip) or {}
        if ann.get("type"):
            host["type_override"] = ann["type"]
        if ann.get("name"):
            host["name"] = ann["name"]
        findings = entry.get("findings", [])
        score, counts, meta = _host_risk(findings)
        host["findings"] = findings
        host["severity_counts"] = counts
        host["max_severity"] = next((sev for sev in SEV_ORDER if counts.get(sev)), None)
        host["risk"] = score
        host["risk_meta"] = meta
        host["history"] = sorted(entry.get("history", []), key=lambda x: x.get("scanned_at", ""))
        host["first_seen"] = entry.get("first_seen", "")
        host["last_seen"] = entry.get("last_seen", "")
        host["seen_count"] = len(host["history"])
        host["source"] = entry.get("source", "")
        hosts.append(host)
    hosts.sort(key=lambda h: _ip_key(h["ip"]))

    # Inventario Proxmox opcional: enriquece solo hosts del contexto actual y
    # marca los invitados escaneados con parent_ip para la vista en árbol.
    try:
        hosts, proxmox_state = proxmox.enrich_hosts(hosts)
    except Exception as exc:  # noqa: BLE001 - el panel sigue sin Proxmox
        proxmox_state = {
            "ok": False,
            "enabled": False,
            "configured": False,
            "error": str(exc),
            "stale": False,
            "fetched_at": "",
            "endpoint": "",
            "nodes": [],
            "node_count": 0,
            "guest_count": 0,
            "hidden_guests": 0,
        }

    visible_findings: list[dict] = []
    seen_findings: set[tuple[str, str, str]] = set()
    for host in hosts:
        for finding in host.get("findings") or []:
            key = (
                str(finding.get("host", "")),
                str(finding.get("title", "")),
                str(finding.get("evidence", "")),
            )
            if key in seen_findings:
                continue
            seen_findings.add(key)
            visible_findings.append(finding)
    score, counts, risk = _host_risk(visible_findings)
    port_counter: Counter[int] = Counter()
    port_names: dict[int, str] = {}
    service_counter: Counter[str] = Counter()
    for host in hosts:
        for port in host.get("ports", []):
            number = port.get("port")
            if number is None:
                continue
            port_counter[number] += 1
            port_names.setdefault(number, port.get("name", ""))
            service_counter[port.get("name") or "desconocido"] += 1

    type_counter = Counter(
        (h.get("type_override") or h.get("type") or "Desconocido") for h in hosts
    )
    last_rovska = next(
        (event for event in reversed(visible) if event["source"] == "rovska"), None
    )

    global_data = {
        "target": (latest or {}).get("target", ""),
        "scanned_at": (latest or {}).get("scanned_at", ""),
        "profile": (latest or {}).get("profile", ""),
        "mode": (latest or {}).get("mode", ""),
        "scan_id": (latest or {}).get("id", ""),
        "status": (latest or {}).get("status", ""),
        "source": (latest or {}).get("source", ""),
        "active_sweep": bool(latest and latest.get("active") and latest.get("sweep")),
        "counts": counts,
        "total_findings": len(visible_findings),
        "risk": risk,
        "total_hosts": len(hosts),
        "hosts_with_ports": sum(1 for h in hosts if h.get("ports")),
        "total_ports": sum(len(h.get("ports", [])) for h in hosts),
        "unique_services": len(
            {p.get("name") for h in hosts for p in h.get("ports", []) if p.get("name")}
        ),
        "type_counts": dict(type_counter.most_common()),
        "top_ports": [
            {"port": num, "count": count, "name": port_names.get(num, "?")}
            for num, count in port_counter.most_common(10)
        ],
        "top_services": [
            {"name": name, "count": count} for name, count in service_counter.most_common(10)
        ],
        "top_hosts": [
            {
                "ip": h["ip"],
                "risk": h["risk"],
                "risk_meta": h["risk_meta"],
                "type": h.get("type_override") or h.get("type", ""),
                "os": h.get("os", ""),
                "severity_counts": h["severity_counts"],
                "findings": len(h["findings"]),
            }
            for h in sorted(hosts, key=lambda x: (-x["risk"], _ip_key(x["ip"])))[:10]
            if h["risk"] > 0
        ],
        "findings": visible_findings,
        "good_checks": (last_rovska or {}).get("good_checks", []),
        "proxmox": (last_rovska or {}).get("proxmox", {}),
        "attack": (last_rovska or {}).get("attack", {}),
        "frameworks": (last_rovska or {}).get("frameworks", {}),
        "limitations": (last_rovska or {}).get("limitations", []),
    }

    scan_rows = []
    for rep in reports:
        scan_rows.append(
            {
                "id": rep.get("scan_id", ""),
                "target": rep.get("target", ""),
                "profile": rep.get("profile", ""),
                "mode": rep.get("mode", ""),
                "status": rep.get("status", ""),
                "started_at": rep.get("scanned_at", ""),
                "finished_at": rep.get("finished_at", ""),
                "hosts": len(rep.get("hosts", [])),
                "findings": len(rep.get("findings", [])),
                "risk": rep.get("risk", {}),
                "counts": rep.get("counts", {}),
            }
        )

    operations = db.query(
        "SELECT * FROM operations ORDER BY started_at DESC LIMIT 100"
    )
    for op in operations:
        op["params"] = db.json_loads(op.pop("params_json", "{}"), {})
        op["result"] = db.json_loads(op.pop("result_json", "{}"), {})

    trend = [
        {
            "scanned_at": rep.get("scanned_at", ""),
            "scan_id": rep.get("scan_id", ""),
            "counts": rep.get("counts", {}),
            "risk": rep.get("risk", {}).get("score", 0),
            "hosts": len(rep.get("hosts", [])),
            "findings": len(rep.get("findings", [])),
        }
        for rep in reports
    ]

    return {
        "generated_at": db.utc_now(),
        "api_version": API_VERSION,
        "reports_count": len(reports),
        "reports_dir": str(SETTINGS.reports_dir),
        "latest": {
            "scan_id": (latest or {}).get("id", ""),
            "scanned_at": (latest or {}).get("scanned_at", ""),
            "target": (latest or {}).get("target", ""),
            "profile": (latest or {}).get("profile", ""),
            "status": (latest or {}).get("status", ""),
            "source": (latest or {}).get("source", ""),
        },
        "global": global_data,
        "hosts": hosts,
        "scans": scan_rows,
        "operations": operations,
        "jobs": JOBS.list(),
        "trend": trend,
        "annotations": annotations,
        "type_options": TYPE_OPTIONS,
        "proxmox": proxmox_state,
        "settings": _public_settings(),
    }


def _public_settings() -> dict:
    return {
        "host": SETTINGS.host,
        "port": SETTINGS.port,
        "runner": SETTINGS.runner,
        "container": SETTINGS.container,
        "allow_public": SETTINGS.allow_public,
        "allow_attack": SETTINGS.allow_attack,
        "max_hosts": SETTINGS.max_hosts,
        "tool_timeout": SETTINGS.tool_timeout,
        "opencode_enabled": SETTINGS.opencode_enabled,
        "opencode_model": SETTINGS.opencode_model,
        "reports_dir": str(SETTINGS.reports_dir),
        "data_dir": str(SETTINGS.data_dir),
        "api_token_required": bool(SETTINGS.api_token),
    }


TASK_STATUS_LABELS = {
    "queued": "En cola",
    "running": "Activo",
    "cancelling": "Cancelando",
    "done": "Completado",
    "error": "Fallido",
    "cancelled": "Cancelado",
    "interrupted": "Interrumpido",
    "unknown": "Desconocido",
}
TASK_ACTIVE_STATUSES = {"queued", "running", "cancelling"}


def _task_status(db_status: str, job: dict | None) -> str:
    status = str(db_status or "").lower()
    if status in {"done", "error", "cancelled"}:
        return status
    if job:
        job_status = str(job.get("status") or "").lower()
        if job_status in {"done", "error", "cancelled", "cancelling", "running", "queued"}:
            return job_status
    # Una tarea marcada como activa en SQLite pero sin trabajo en memoria quedó
    # interrumpida por un reinicio del panel.
    if status in {"queued", "running"}:
        return "interrupted"
    return status or "unknown"


def _integration_task_status(job: dict) -> str:
    status = str(job.get("status") or "").lower()
    if status == "ok":
        return "done"
    if status in {"running", "queued"} and not job.get("live"):
        # El panel se reinició y el proceso hijo ya no está bajo su control.
        return "interrupted"
    if status in {"done", "error", "cancelled", "cancelling", "running", "queued"}:
        return status
    return status or "unknown"


def _task_duration(started_at: str, finished_at: str = "") -> int:
    if not started_at:
        return 0
    try:
        fmt = "%Y-%m-%d %H:%M:%S"
        start = datetime.strptime(str(started_at)[:19], fmt)
        end = datetime.strptime(str(finished_at)[:19], fmt) if finished_at else datetime.now()
        return max(0, int((end - start).total_seconds()))
    except ValueError:
        return 0


def _last_task_events(operation_ids: list[str], scan_ids: list[str]) -> dict[str, dict]:
    events: dict[str, dict] = {}
    if operation_ids:
        marks = ",".join("?" for _ in operation_ids)
        for row in db.query(
            "SELECT e.operation_id, e.ts, e.level, e.message FROM events e "
            f"JOIN (SELECT operation_id, MAX(id) AS id FROM events WHERE operation_id IN ({marks}) "
            "GROUP BY operation_id) m ON e.id = m.id",
            tuple(operation_ids),
        ):
            events[f"op:{row['operation_id']}"] = row
    if scan_ids:
        marks = ",".join("?" for _ in scan_ids)
        for row in db.query(
            "SELECT e.scan_id, e.ts, e.level, e.message FROM events e "
            f"JOIN (SELECT scan_id, MAX(id) AS id FROM events WHERE scan_id IN ({marks}) "
            "GROUP BY scan_id) m ON e.id = m.id",
            tuple(scan_ids),
        ):
            events[f"scan:{row['scan_id']}"] = row
    return events


def tasks_payload() -> dict:
    """Tareas visibles para el operador: escaneos, herramientas e importaciones.

    Une el estado persistido en SQLite con los trabajos en memoria para saber si
    una tarea sigue viva o quedó interrumpida por un reinicio.
    """
    jobs = {job.get("id", ""): job for job in JOBS.list() if job.get("id")}
    scans = db.query("SELECT * FROM scans ORDER BY started_at DESC LIMIT 100")
    scan_ops = db.query("SELECT * FROM operations WHERE kind='scan' ORDER BY started_at DESC")
    scan_op_map: dict[str, dict] = {}
    for operation in scan_ops:
        if operation.get("scan_id"):
            scan_op_map.setdefault(operation["scan_id"], operation)

    tasks: list[dict] = []
    seen: set[str] = set()
    event_operation_ids: list[str] = []
    event_scan_ids: list[str] = []

    for scan in scans:
        scan_id = scan["id"]
        operation = scan_op_map.get(scan_id)
        job = jobs.get(scan_id)
        status = _task_status(scan.get("status", ""), job)
        active = status in TASK_ACTIVE_STATUSES or status == "interrupted"
        stats = db.json_loads(scan.get("stats_json", "{}"), {}) or {}
        imported = scan.get("profile") == "import" or bool(stats.get("imported"))
        operation_id = operation.get("id", "") if operation else ""
        task = {
            "id": scan_id,
            "entity_id": scan_id,
            "operation_id": operation_id,
            "scan_id": scan_id,
            "type": "import" if imported else "scan",
            "target": scan.get("target", ""),
            "label": scan.get("profile", "") or "scan",
            "profile": scan.get("profile", ""),
            "tool": "",
            "status": status,
            "status_label": TASK_STATUS_LABELS.get(status, status),
            "started_at": scan.get("started_at", ""),
            "finished_at": scan.get("finished_at", "") or "",
            "duration_seconds": _task_duration(scan.get("started_at", ""), scan.get("finished_at", "") or ""),
            "active": status in TASK_ACTIVE_STATUSES,
            "can_cancel": status in TASK_ACTIVE_STATUSES or status == "interrupted",
            "cancel_kind": "scan",
            "dry_run": bool(operation.get("dry_run")) if operation else scan.get("profile") != "attack",
            "log_available": bool(operation_id),
            "error": scan.get("error", "") or "",
            "current": "",
            "current_at": "",
        }
        tasks.append(task)
        seen.add(scan_id)
        if operation_id:
            seen.add(operation_id)
            event_operation_ids.append(operation_id)
        else:
            event_scan_ids.append(scan_id)

    operations = db.query(
        "SELECT * FROM operations WHERE kind != 'scan' ORDER BY started_at DESC LIMIT 100"
    )
    for operation in operations:
        operation_id = operation["id"]
        job = jobs.get(operation_id)
        status = _task_status(operation.get("status", ""), job)
        task = {
            "id": operation_id,
            "entity_id": operation_id,
            "operation_id": operation_id,
            "scan_id": operation.get("scan_id", "") or "",
            "type": "operation",
            "target": operation.get("target", ""),
            "label": operation.get("tool", "") or "tool",
            "profile": "",
            "tool": operation.get("tool", ""),
            "status": status,
            "status_label": TASK_STATUS_LABELS.get(status, status),
            "started_at": operation.get("started_at", ""),
            "finished_at": operation.get("finished_at", "") or "",
            "duration_seconds": _task_duration(
                operation.get("started_at", ""), operation.get("finished_at", "") or ""
            ),
            "active": status in TASK_ACTIVE_STATUSES,
            "can_cancel": status in TASK_ACTIVE_STATUSES or status == "interrupted",
            "cancel_kind": "operation",
            "dry_run": bool(operation.get("dry_run")),
            "log_available": True,
            "error": operation.get("error", "") or "",
            "current": "",
            "current_at": "",
        }
        tasks.append(task)
        seen.add(operation_id)
        event_operation_ids.append(operation_id)

    for job in jobs.values():
        if job.get("id") in seen:
            continue
        status = _task_status("", job)
        started_at = job.get("started_at", "")
        tasks.append(
            {
                "id": job.get("id", ""),
                "entity_id": job.get("id", ""),
                "operation_id": "",
                "scan_id": "",
                "type": job.get("kind", "job") or "job",
                "target": job.get("target", "") or "—",
                "label": job.get("kind", "job") or "job",
                "profile": "",
                "tool": "",
                "status": status,
                "status_label": TASK_STATUS_LABELS.get(status, status),
                "started_at": started_at,
                "finished_at": "",
                "duration_seconds": _task_duration(started_at),
                "active": status in TASK_ACTIVE_STATUSES,
                "can_cancel": False,
                "cancel_kind": "",
                "dry_run": False,
                "log_available": False,
                "error": job.get("error", "") or "",
                "current": "",
                "current_at": "",
            }
        )
        seen.add(job.get("id", ""))

    # MIDGARD/NETMAP viven fuera de los JOBS de ROVSKA y fuera de SQLite.
    for job in integrations.list_jobs():
        job_id = job.get("id", "")
        if not job_id or job_id in seen:
            continue
        status = _integration_task_status(job)
        started_at = job.get("started_at", "")
        finished_at = job.get("finished_at", "") or ""
        target = job.get("target", "") or ""
        if not target:
            label = str(job.get("label", "") or "")
            target = label.split("·", 1)[-1].strip() if "·" in label else "—"
        kind = job.get("kind", "job") or "job"
        tasks.append(
            {
                "id": job_id,
                "entity_id": job_id,
                "operation_id": "",
                "scan_id": "",
                "type": kind,
                "target": target,
                "label": job.get("label", "") or kind,
                "profile": "",
                "tool": kind.upper(),
                "status": status,
                "status_label": TASK_STATUS_LABELS.get(status, status),
                "started_at": started_at,
                "finished_at": finished_at,
                "duration_seconds": _task_duration(started_at, finished_at),
                "active": status in TASK_ACTIVE_STATUSES,
                "can_cancel": status in TASK_ACTIVE_STATUSES or status == "interrupted",
                "cancel_kind": kind,
                "dry_run": False,
                "log_available": True,
                "error": job.get("error", "") or "",
                "current": str(job.get("last_line", "") or "")[:220],
                "current_at": finished_at or started_at,
            }
        )
        seen.add(job_id)

    latest_events = _last_task_events(event_operation_ids, event_scan_ids)
    for task in tasks:
        event = latest_events.get(f"op:{task['operation_id']}") if task["operation_id"] else None
        if not event and task["scan_id"]:
            event = latest_events.get(f"scan:{task['scan_id']}")
        if event:
            message = str(event.get("message", "")).strip().replace("\n", " ")
            task["current"] = message[:220] + ("…" if len(message) > 220 else "")
            task["current_at"] = event.get("ts", "")

    # Las tareas terminadas que el operador haya limpiado se ocultan del
    # listado, pero su historial, evidencia e informes se conservan. Las
    # activas nunca se ocultan.
    dismissed = {row["task_id"] for row in db.query("SELECT task_id FROM task_dismissals")}
    if dismissed:
        tasks = [task for task in tasks if task["active"] or task["id"] not in dismissed]

    # Primero lo que requiere atención (activas e interrumpidas); dentro de
    # cada grupo, la más reciente arriba.
    tasks.sort(key=lambda item: item.get("started_at", ""), reverse=True)
    tasks.sort(
        key=lambda item: 0 if item["active"] or item["status"] == "interrupted" else 1
    )
    counts = Counter(task["status"] for task in tasks)
    return {
        "generated_at": db.utc_now(),
        "tasks": tasks,
        "counts": {
            "total": len(tasks),
            "active": sum(1 for task in tasks if task["active"]),
            **{status: counts.get(status, 0) for status in TASK_STATUS_LABELS},
        },
    }


def _clear_tasks() -> dict:
    """Oculta del listado las tareas terminadas sin borrar su historial.

    No elimina escaneos, operaciones, evidencia ni informes: solo guarda qué
    tareas ya vio el operador. Las tareas activas se mantienen siempre
    visibles.
    """
    payload = tasks_payload()
    finished = [task["id"] for task in payload["tasks"] if not task["active"]]
    active = [task["id"] for task in payload["tasks"] if task["active"]]
    if finished:
        dismissed_at = db.utc_now()
        with db.tx() as conn:
            conn.executemany(
                "INSERT OR REPLACE INTO task_dismissals (task_id, dismissed_at) VALUES (?,?)",
                [(task_id, dismissed_at) for task_id in finished],
            )
    return {"ok": True, "cleared": len(finished), "kept_active": len(active)}


def tools_payload() -> list[dict]:
    now = time.time()
    if now - _TOOLS_CACHE["at"] < 45 and _TOOLS_CACHE["rows"]:
        return _TOOLS_CACHE["rows"]
    runner = get_runner(SETTINGS)
    rows = catalog(runner)
    _TOOLS_CACHE.update({"at": now, "rows": rows})
    return rows


def health_payload() -> dict:
    now = time.time()
    if now - _HEALTH_CACHE["at"] < 10 and _HEALTH_CACHE["data"]:
        return _HEALTH_CACHE["data"]
    runner = get_runner(SETTINGS)
    docker_status = runner.status() if hasattr(runner, "status") else {"docker": False, "running": runner.name == "local"}
    data = {
        "ok": True,
        "version": API_VERSION,
        "time": db.utc_now(),
        "db": str(SETTINGS.db_path),
        "scans": db.query_one("SELECT COUNT(*) AS n FROM scans")["n"],
        "operations": db.query_one("SELECT COUNT(*) AS n FROM operations")["n"],
        "reports": len(list(SETTINGS.reports_dir.glob("informe_*"))),
        "runner": SETTINGS.runner,
        "runner_status": docker_status,
        "opencode": orchestrator.opencode_available(SETTINGS),
        "allow_attack": SETTINGS.allow_attack,
    }
    _HEALTH_CACHE.update({"at": now, "data": data})
    return data


class Handler(BaseHTTPRequestHandler):
    server_version = "ROVSKA/1.0"
    protocol_version = "HTTP/1.1"

    # -- infraestructura ------------------------------------------------
    def log_message(self, fmt, *args):
        if os.environ.get("ROVSKA_DEBUG"):
            print(f"[api] {self.address_string()} {fmt % args}")

    def end_headers(self):
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "SAMEORIGIN")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Permissions-Policy", "geolocation=(), microphone=(), camera=()")
        super().end_headers()

    def send_json(self, status: int, payload) -> None:
        body = json.dumps(payload, ensure_ascii=False, default=str).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def send_error_json(self, status: int, message: str) -> None:
        self.send_json(status, {"error": message, "status": status})

    def read_json(self, limit: int = 2_000_000) -> dict:
        length = int(self.headers.get("Content-Length", "0") or "0")
        if length <= 0:
            return {}
        if length > limit:
            raise ValueError("cuerpo demasiado grande")
        raw = self.rfile.read(length).decode("utf-8", errors="replace")
        value = json.loads(raw)
        if not isinstance(value, dict):
            raise ValueError("se esperaba un objeto JSON")
        return value

    def authorized(self) -> bool:
        if not SETTINGS.api_token:
            return True
        token = self.headers.get("X-ROVSKA-Token", "")
        if not token:
            token = (parse_qs(urlparse(self.path).query).get("token") or [""])[0]
        return token == SETTINGS.api_token

    def same_origin(self) -> bool:
        origin = self.headers.get("Origin")
        if not origin:
            return True
        host = self.headers.get("Host", "")
        return origin.split("://", 1)[-1] == host

    def guard_write(self) -> bool:
        if not self.same_origin():
            self.send_error_json(403, "origen no permitido")
            return False
        if not self.authorized():
            self.send_error_json(401, "token requerido (X-ROVSKA-Token)")
            return False
        return True

    # -- GET ------------------------------------------------------------
    def do_GET(self):
        parsed = urlparse(self.path)
        path = parsed.path
        query = parse_qs(parsed.query)
        try:
            if path == "/api/health":
                return self.send_json(200, health_payload())
            if path == "/api/data":
                return self.send_json(200, build_payload())
            if path == "/api/scans":
                return self.send_json(200, db.query("SELECT * FROM scans ORDER BY started_at DESC"))
            if path.startswith("/api/scans/"):
                scan_id = unquote(path.split("/api/scans/", 1)[1])
                return self.send_json(200, report.build(scan_id))
            if path == "/api/operations":
                rows = db.query("SELECT * FROM operations ORDER BY started_at DESC LIMIT 200")
                for row in rows:
                    row["params"] = db.json_loads(row.pop("params_json", "{}"), {})
                    row["result"] = db.json_loads(row.pop("result_json", "{}"), {})
                return self.send_json(200, rows)
            if path.startswith("/api/operations/") and path.endswith("/stream"):
                operation_id = unquote(path[len("/api/operations/") : -len("/stream")].strip("/"))
                return self.stream_events(operation_id=operation_id)
            if path.startswith("/api/operations/"):
                operation_id = unquote(path.split("/api/operations/", 1)[1])
                row = db.query_one("SELECT * FROM operations WHERE id=?", (operation_id,))
                if not row:
                    return self.send_error_json(404, "operación no encontrada")
                row["params"] = db.json_loads(row.pop("params_json", "{}"), {})
                row["result"] = db.json_loads(row.pop("result_json", "{}"), {})
                return self.send_json(200, row)
            if path == "/api/events":
                return self.stream_events()
            if path == "/api/findings":
                scan_id = (query.get("scan_id") or [""])[0]
                severity = (query.get("severity") or [""])[0].upper()
                host = (query.get("host") or [""])[0]
                if scan_id:
                    data = report.build(scan_id)
                else:
                    data = build_payload()
                    data = {"findings": data["global"]["findings"]}
                findings = [
                    f
                    for f in data.get("findings", [])
                    if (not severity or f.get("severity") == severity)
                    and (not host or f.get("host") == host)
                ]
                return self.send_json(200, findings)
            if path == "/api/attack":
                scan_id = (query.get("scan_id") or [""])[0]
                data = report.build(scan_id) if scan_id else build_payload()["global"]
                return self.send_json(200, data.get("attack", {}))
            if path == "/api/frameworks":
                scan_id = (query.get("scan_id") or [""])[0]
                data = report.build(scan_id) if scan_id else build_payload()["global"]
                return self.send_json(200, data.get("frameworks", {}))
            if path == "/api/compare":
                base_id = (query.get("base") or [""])[0]
                target_id = (query.get("target") or [""])[0]
                return self.send_json(200, compare.compare_scans(base_id, target_id))
            if path == "/api/stats":
                return self.send_json(200, _stats_payload())
            if path == "/api/tools":
                return self.send_json(200, tools_payload())
            if path == "/api/config":
                return self.send_json(200, _public_settings())
            if path == "/api/proxmox":
                force = (query.get("refresh") or ["0"])[0] in {"1", "true", "yes"}
                return self.send_json(200, proxmox.status(force=force))
            if path == "/api/scope":
                target = (query.get("target") or [""])[0]
                authorization = (query.get("authorization") or ["0"])[0] in {"1", "true", "yes"}
                return self.send_json(200, check_target(target, SETTINGS, authorization).to_dict())
            if path == "/api/narrate":
                scan_id = (query.get("scan_id") or [""])[0]
                return self.send_json(200, orchestrator.narrate(scan_id))
            if path == "/api/reports":
                return self.send_json(200, _reports_payload())
            if path == "/api/jobs":
                return self.send_json(200, JOBS.list())
            if path == "/api/integrations":
                return self.send_json(200, integrations.overview())
            if path == "/api/midgard/profiles":
                return self.send_json(200, integrations.profiles())
            if path == "/api/midgard/runs":
                return self.send_json(200, integrations.midgard_runs())
            if path.startswith("/api/midgard/runs/"):
                run_id = unquote(path[len("/api/midgard/runs/") :]).strip("/")
                try:
                    return self.send_json(200, integrations.midgard_run(run_id))
                except FileNotFoundError:
                    return self.send_error_json(404, "ejecución no encontrada")
            if path == "/api/midgard/jobs":
                return self.send_json(200, integrations.list_jobs("midgard"))
            if path.startswith("/api/midgard/jobs/"):
                job_id = unquote(path[len("/api/midgard/jobs/") :]).strip("/")
                job = integrations.get_job(job_id)
                if not job:
                    return self.send_error_json(404, "trabajo no encontrado")
                return self.send_json(200, job)
            if path == "/api/netmap":
                return self.send_json(200, integrations.netmap_data())
            if path == "/api/netmap/jobs":
                return self.send_json(200, integrations.list_jobs("netmap"))
            if path.startswith("/api/netmap/jobs/"):
                job_id = unquote(path[len("/api/netmap/jobs/") :]).strip("/")
                job = integrations.get_job(job_id)
                if not job:
                    return self.send_error_json(404, "trabajo no encontrado")
                return self.send_json(200, job)
            if path == "/api/tasks":
                return self.send_json(200, tasks_payload())
            if path.startswith("/reports/"):
                return self.serve_report(path[len("/reports/") :])
            if path == "/netmap":
                self.send_response(302)
                self.send_header("Location", "/netmap/")
                self.end_headers()
                return
            if path.startswith("/netmap/"):
                return self.serve_netmap(path[len("/netmap/") :])
            # Las antiguas páginas sueltas abren la vista interna del SPA.
            if path in {"/midgard.html", "/netmap.html"}:
                target = "/#midgard" if path == "/midgard.html" else "/#netmap"
                self.send_response(302)
                self.send_header("Location", target)
                self.send_header("Content-Length", "0")
                self.end_headers()
                return
            if path.startswith("/api/"):
                return self.send_error_json(404, "ruta no encontrada")
            return self.serve_static(path)
        except KeyError as exc:
            return self.send_error_json(404, str(exc))
        except ScopeError as exc:
            return self.send_error_json(400, str(exc))
        except (ValueError, json.JSONDecodeError) as exc:
            return self.send_error_json(400, str(exc))
        except (BrokenPipeError, ConnectionResetError):
            return
        except Exception as exc:  # noqa: BLE001
            if os.environ.get("ROVSKA_DEBUG"):
                traceback.print_exc()
            return self.send_error_json(500, str(exc))

    # -- POST -----------------------------------------------------------
    def do_POST(self):
        path = urlparse(self.path).path
        if not self.guard_write():
            return
        try:
            body_limit = (
                8_000_000
                if path == "/api/import-report"
                else 6_000_000
                if path == "/api/operations"
                else 2_000_000
            )
            body = self.read_json(limit=body_limit)
            if path == "/api/scans":
                return self.start_scan(body)
            if path == "/api/operations":
                return self.start_operation(body)
            if path == "/api/import-report":
                return self.import_report(body)
            if path.startswith("/api/operations/") and path.endswith("/cancel"):
                operation_id = unquote(path[len("/api/operations/") : -len("/cancel")].strip("/"))
                return self.cancel_operation(operation_id)
            if path.startswith("/api/scans/") and path.endswith("/cancel"):
                scan_id = unquote(path[len("/api/scans/") : -len("/cancel")].strip("/"))
                JOBS.cancel(scan_id)
                db.execute(
                    "UPDATE scans SET status='cancelled', finished_at=? WHERE id=? AND status IN ('queued','running')",
                    (db.utc_now(), scan_id),
                )
                return self.send_json(200, {"ok": True, "scan_id": scan_id})
            if path.startswith("/api/midgard/jobs/") and path.endswith("/cancel"):
                job_id = unquote(path[len("/api/midgard/jobs/") : -len("/cancel")].strip("/"))
                job = integrations.cancel_job(job_id)
                if not job:
                    return self.send_error_json(404, "trabajo no encontrado")
                return self.send_json(200, {"ok": True, "job": job})
            if path.startswith("/api/netmap/jobs/") and path.endswith("/cancel"):
                job_id = unquote(path[len("/api/netmap/jobs/") : -len("/cancel")].strip("/"))
                job = integrations.cancel_job(job_id)
                if not job:
                    return self.send_error_json(404, "trabajo no encontrado")
                return self.send_json(200, {"ok": True, "job": job})
            if path == "/api/annotations":
                return self.save_annotation(body)
            if path == "/api/reports":
                scan_id = str(body.get("scan_id", ""))
                return self.send_json(200, report.write_reports(scan_id))
            if path == "/api/reports/delete":
                if body.get("confirm") is not True:
                    return self.send_error_json(400, "confirmación requerida")
                result = _delete_reports(purge_history=body.get("purge_history", True) is not False)
                history = result.get("history") or {}
                db.record_event(
                    "Informes borrados del historial: "
                    f"{result['deleted']}; escaneos: {history.get('scans', 0)}; "
                    f"hosts: {history.get('hosts', 0)}",
                    "warn",
                )
                return self.send_json(200, result)
            if path == "/api/tasks/clear":
                if body.get("confirm") is not True:
                    return self.send_error_json(400, "confirmación requerida")
                result = _clear_tasks()
                db.record_event(
                    f"Tareas terminadas ocultadas del listado: {result['cleared']}",
                    "info",
                )
                return self.send_json(200, result)
            if path == "/api/proxmox/config":
                try:
                    saved = proxmox.save_config(body)
                except (ValueError, proxmox.ProxmoxError) as exc:
                    return self.send_error_json(400, str(exc))
                result = {"ok": True, "config": proxmox.public_config(saved)}
                if body.get("validate"):
                    result["test"] = proxmox.test_connection(saved)
                return self.send_json(200, result)
            if path == "/api/proxmox/test":
                try:
                    cfg = proxmox.merged_config(body)
                except (ValueError, proxmox.ProxmoxError) as exc:
                    return self.send_json(200, {"ok": False, "error": str(exc)})
                return self.send_json(200, proxmox.test_connection(cfg))
            if path == "/api/proxmox/preferences":
                try:
                    saved = proxmox.save_config(
                        {"include_in_scans": body.get("include_in_scans")}
                    )
                except (ValueError, proxmox.ProxmoxError) as exc:
                    return self.send_error_json(400, str(exc))
                return self.send_json(200, {"ok": True, "config": proxmox.public_config(saved)})
            if path == "/api/proxmox/refresh":
                proxmox.invalidate_cache()
                return self.send_json(200, proxmox.status(force=True))
            if path == "/api/orchestrate":
                return self.orchestrate(body)
            if path == "/api/midgard/run":
                return self.start_midgard(body)
            if path == "/api/netmap/scan":
                return self.start_netmap(body)
            return self.send_error_json(404, "ruta no encontrada")
        except (ValueError, json.JSONDecodeError) as exc:
            return self.send_error_json(400, str(exc))
        except ScopeError as exc:
            return self.send_error_json(403, str(exc))
        except KeyError as exc:
            return self.send_error_json(404, str(exc))
        except Exception as exc:  # noqa: BLE001
            if os.environ.get("ROVSKA_DEBUG"):
                traceback.print_exc()
            return self.send_error_json(500, str(exc))

    def do_OPTIONS(self):
        self.send_response(204)
        self.send_header("Allow", "GET, POST, OPTIONS")
        self.end_headers()

    # -- acciones -------------------------------------------------------
    def start_scan(self, body: dict) -> None:
        target = str(body.get("target", "")).strip()
        profile = str(body.get("profile", "quick")).strip()
        authorization = bool(body.get("authorization"))
        options = body.get("options") if isinstance(body.get("options"), dict) else {}
        if profile not in scanner.PROFILES:
            return self.send_error_json(400, f"perfil no válido: {profile}")
        decision = check_target(target, SETTINGS, authorization)
        if not decision.allowed:
            return self.send_error_json(403, decision.reason)
        scan_id = db.new_id("scan")
        db.execute(
            "INSERT INTO scans (id, target, profile, mode, status, started_at, options_json, stats_json) "
            "VALUES (?,?,?,?,?,?,?,?)",
            (
                scan_id,
                target,
                profile,
                scanner.PROFILES[profile].get("nmap_profile", "quick"),
                "queued",
                db.utc_now(),
                db.json_dumps(options),
                "{}",
            ),
        )
        JOBS.submit(
            scan_id,
            "scan",
            scanner.run_scan,
            target,
            profile,
            options,
            authorization,
            scan_id=scan_id,
            target=target,
        )
        self.send_json(202, {"scan_id": scan_id, "status": "queued", "scope": decision.to_dict()})

    def import_report(self, body: dict) -> None:
        content = body.get("content")
        if not isinstance(content, str) or not content.strip():
            return self.send_error_json(400, "falta el contenido del informe")
        filename = str(body.get("filename", "") or "informe")
        fmt = str(body.get("format", "") or "")
        result = importer.import_text(content, filename=filename, fmt=fmt)
        self.send_json(200, result)

    def start_operation(self, body: dict) -> None:
        tool_name = str(body.get("tool", "")).strip()
        target = str(body.get("target", "")).strip()
        params = dict(body.get("params") or {}) if isinstance(body.get("params"), dict) else {}
        authorization = bool(body.get("authorization"))
        dry_run = bool(body.get("dry_run", True))
        scan_id = body.get("scan_id") or None
        tool = get_tool(tool_name)
        if tool is None:
            return self.send_error_json(400, f"herramienta desconocida: {tool_name}")
        decision = check_target(target, SETTINGS, authorization)
        if not decision.allowed:
            return self.send_error_json(403, decision.reason)
        if tool.spec.requires_attack and not SETTINGS.allow_attack:
            dry_run = True
        operation_id = db.new_id("op")
        files = body.get("files") if isinstance(body.get("files"), dict) else {}
        if files:
            if tool_name != "hydra":
                return self.send_error_json(400, "esta herramienta no admite ficheros")
            stored, error = _store_operation_files(operation_id, files)
            if error:
                return self.send_error_json(400, error)
            params.update(stored)
        db.execute(
            "INSERT INTO operations (id, scan_id, kind, tool, target, params_json, status, risk_level, dry_run, started_at) "
            "VALUES (?,?,?,?,?,?,?,?,?,?)",
            (
                operation_id,
                scan_id,
                "tool",
                tool_name,
                target,
                db.json_dumps(params),
                "queued",
                "attack" if tool.spec.requires_attack else "safe",
                1 if dry_run else 0,
                db.utc_now(),
            ),
        )
        JOBS.submit(
            operation_id,
            "operation",
            scanner.run_operation,
            tool_name,
            target,
            params,
            authorization,
            dry_run,
            scan_id=scan_id,
            operation_id=operation_id,
            target=target,
        )
        self.send_json(
            202,
            {
                "operation_id": operation_id,
                "status": "queued",
                "dry_run": dry_run,
                "requires_attack": tool.spec.requires_attack,
                "scope": decision.to_dict(),
            },
        )

    def cancel_operation(self, operation_id: str) -> None:
        JOBS.cancel(operation_id)
        db.execute(
            "UPDATE operations SET status='cancelled', finished_at=? WHERE id=? AND status IN ('queued','running')",
            (db.utc_now(), operation_id),
        )
        db.record_event("Operación cancelada por el usuario", "warn", operation_id=operation_id)
        self.send_json(200, {"ok": True, "operation_id": operation_id})

    def save_annotation(self, body: dict) -> None:
        ip = str(body.get("ip", "")).strip()
        ipaddress.ip_address(ip)
        type_value = str(body.get("type", "")).strip()
        name = str(body.get("name", "")).strip()[:80]
        if type_value and type_value not in TYPE_OPTIONS:
            return self.send_error_json(400, "tipo no permitido")
        db.save_annotation(ip, type_value, name)
        self.send_json(200, {"ok": True, "annotations": db.load_annotations()})

    def orchestrate(self, body: dict) -> None:
        goal = str(body.get("goal", "")).strip()
        target = str(body.get("target", "")).strip()
        scan_id = str(body.get("scan_id", "")).strip()
        mode = str(body.get("mode", "plan")).strip()
        authorization = bool(body.get("authorization"))
        if not goal or not target:
            return self.send_error_json(400, "goal y target son obligatorios")
        decision = check_target(target, SETTINGS, authorization)
        if not decision.allowed:
            return self.send_error_json(403, decision.reason)
        context = orchestrator.build_context(scan_id) if scan_id else None
        plan = orchestrator.plan(goal, target, context)
        if mode != "execute":
            return self.send_json(200, {"plan": plan, "scope": decision.to_dict()})
        job_id = db.new_id("orch")
        JOBS.submit(
            job_id,
            "orchestration",
            orchestrator.execute_plan,
            plan,
            SETTINGS,
            authorization,
            scan_id or None,
            target=target,
        )
        self.send_json(
            202,
            {"plan": plan, "job_id": job_id, "status": "queued", "scope": decision.to_dict()},
        )

    # -- SSE ------------------------------------------------------------
    def stream_events(self, operation_id: str | None = None) -> None:
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream; charset=utf-8")
        self.send_header("Cache-Control", "no-cache")
        self.send_header("Connection", "keep-alive")
        self.send_header("X-Accel-Buffering", "no")
        self.end_headers()
        last_id = 0
        idle = 0
        try:
            while True:
                events = db.events_since(last_id, operation_id=operation_id, limit=200)
                for event in events:
                    last_id = event["id"]
                    data = json.dumps(event, ensure_ascii=False)
                    self.wfile.write(f"id: {event['id']}\ndata: {data}\n\n".encode("utf-8"))
                if events:
                    idle = 0
                    self.wfile.flush()
                else:
                    idle += 1
                    if idle % 15 == 0:
                        self.wfile.write(b": keepalive\n\n")
                        self.wfile.flush()
                if operation_id:
                    op = db.query_one("SELECT status FROM operations WHERE id=?", (operation_id,))
                    if op and op["status"] in {"done", "error", "cancelled"} and not events:
                        self.wfile.write(b"event: end\ndata: {}\n\n")
                        self.wfile.flush()
                        break
                time.sleep(1)
        except (BrokenPipeError, ConnectionResetError, OSError):
            return

    # -- ficheros -------------------------------------------------------
    def serve_static(self, path: str) -> None:
        if path in {"", "/"}:
            file_path = SETTINGS.web_dir / "index.html"
        else:
            safe = Path(unquote(path.lstrip("/")))
            if ".." in safe.parts:
                return self.send_error_json(404, "no encontrado")
            file_path = SETTINGS.web_dir / safe
        if not file_path.is_file():
            return self.send_error_json(404, "no encontrado")
        self._send_file(file_path)

    def start_midgard(self, body: dict) -> None:
        try:
            job = integrations.start_midgard(
                str(body.get("target", "")),
                str(body.get("profile", "quick")),
                bool(body.get("authorized")),
            )
        except RuntimeError as exc:
            return self.send_error_json(409, str(exc))
        except ValueError as exc:
            return self.send_error_json(400, str(exc))
        return self.send_json(202, job)

    def start_netmap(self, body: dict) -> None:
        try:
            job = integrations.start_netmap(str(body.get("iface", "wlan0")))
        except RuntimeError as exc:
            return self.send_error_json(409, str(exc))
        except ValueError as exc:
            return self.send_error_json(400, str(exc))
        return self.send_json(202, job)

    def serve_netmap(self, name: str) -> None:
        safe = Path(unquote(name.lstrip("/")))
        if ".." in safe.parts:
            return self.send_error_json(404, "no encontrado")
        file_path = integrations.NETMAP_MAP / safe
        if not file_path.is_file():
            return self.send_error_json(404, "no encontrado")
        self._send_file(file_path)

    def serve_report(self, name: str) -> None:
        safe = _safe_report_name(unquote(name))
        if not safe:
            return self.send_error_json(404, "informe no encontrado")
        file_path = SETTINGS.reports_dir / safe
        if not file_path.is_file():
            return self.send_error_json(404, "informe no encontrado")
        self._send_file(file_path)

    def _send_file(self, file_path: Path) -> None:
        data = file_path.read_bytes()
        content_type = mimetypes.guess_type(str(file_path))[0] or "application/octet-stream"
        self.send_response(200)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(data)


def _reports_payload() -> list[dict]:
    rows = []
    for path in sorted(
        SETTINGS.reports_dir.glob("informe_*"),
        key=lambda p: p.stat().st_mtime if p.exists() else 0,
        reverse=True,
    ):
        try:
            stat = path.stat()
        except OSError:
            continue
        rows.append(
            {
                "name": path.name,
                "size": stat.st_size,
                "mtime": datetime.fromtimestamp(stat.st_mtime).strftime("%Y-%m-%d %H:%M:%S"),
                "url": f"/reports/{path.name}",
                "ext": path.suffix.lstrip("."),
            }
        )
    return rows


def _purge_scan_history() -> dict:
    """Vacía el historial de escaneos para empezar de cero.

    Elimina los datos derivados de los escaneos (hosts, puertos, hallazgos,
    comprobaciones correctas y runs de herramientas). Conserva anotaciones,
    eventos, operaciones y la evidencia en disco como registro de auditoría.
    """
    active_scan = db.query_one(
        "SELECT id FROM scans WHERE status IN ('queued','running','cancelling') LIMIT 1"
    )
    active_job = next(
        (
            job
            for job in JOBS.list()
            if str(job.get("status", "")).lower() in {"queued", "running", "cancelling"}
        ),
        None,
    )
    if active_scan or active_job:
        raise ValueError("hay una tarea o escaneo activo; espera a que termine antes de borrar el historial")

    counts: dict[str, int] = {}
    with db.tx() as conn:
        for table in ("findings", "good_checks", "ports", "hosts"):
            counts[table] = conn.execute(f"DELETE FROM {table}").rowcount
        counts["scans"] = conn.execute("DELETE FROM scans").rowcount
        counts["tool_runs"] = conn.execute("DELETE FROM tool_runs").rowcount
    return counts


def _delete_reports(purge_history: bool = True) -> dict:
    """Borra los informes generados del historial, nunca los importados.

    Con ``purge_history`` también vacía la tabla de IPs y el historial de
    escaneos para que el panel quede listo para un escaneo nuevo.
    """
    history: dict[str, int] = {}
    if purge_history:
        history = _purge_scan_history()

    deleted: list[str] = []
    errors: list[dict] = []
    for path in sorted(SETTINGS.reports_dir.glob("informe_*")):
        if not path.is_file():
            continue
        try:
            path.unlink()
            deleted.append(path.name)
        except OSError as exc:
            errors.append({"name": path.name, "error": str(exc)})
    return {
        "ok": not errors,
        "deleted": len(deleted),
        "names": deleted,
        "errors": errors,
        "history": history,
        "reports_count": len(list(SETTINGS.reports_dir.glob("informe_*"))),
    }


def _stats_payload() -> dict:
    scans = db.query("SELECT * FROM scans ORDER BY started_at ASC")
    findings = db.query("SELECT severity, source, ip FROM findings")
    counts = {sev: 0 for sev in SEV_ORDER}
    sources: Counter[str] = Counter()
    for finding in findings:
        counts[finding["severity"]] = counts.get(finding["severity"], 0) + 1
        sources[finding["source"]] += 1
    trend = []
    for scan in scans:
        rep_counts = db.query(
            "SELECT severity, COUNT(*) AS n FROM findings WHERE scan_id=? GROUP BY severity",
            (scan["id"],),
        )
        item = {sev: 0 for sev in SEV_ORDER}
        for row in rep_counts:
            item[row["severity"]] = row["n"]
        trend.append(
            {
                "scan_id": scan["id"],
                "scanned_at": scan["started_at"],
                "target": scan["target"],
                "profile": scan["profile"],
                "status": scan["status"],
                "counts": item,
                "total": sum(item.values()),
            }
        )
    operations = db.query("SELECT status, tool FROM operations")
    op_status: Counter[str] = Counter(row["status"] for row in operations)
    op_tools: Counter[str] = Counter(row["tool"] for row in operations)
    return {
        "scans": len(scans),
        "hosts": db.query_one("SELECT COUNT(DISTINCT ip) AS n FROM hosts")["n"],
        "findings": len(findings),
        "counts": counts,
        "sources": dict(sources.most_common()),
        "trend": trend,
        "operations": {"total": len(operations), "status": dict(op_status), "tools": dict(op_tools.most_common())},
    }


def serve(host: str | None = None, port: int | None = None, open_browser: bool = False) -> int:
    host = host or SETTINGS.host
    port = port or SETTINGS.port
    db.init_db()
    server = ThreadingHTTPServer((host, port), Handler)
    server.daemon_threads = True
    url = f"http://{host}:{port}/"
    print("=" * 64)
    print("  ROVSKA — auditoría ofensiva y defensiva")
    print(f"  Panel:   {url}")
    print(f"  Datos:   {SETTINGS.data_dir}")
    print(f"  Runner:  {SETTINGS.runner} ({SETTINGS.container if SETTINGS.runner == 'docker' else 'local'})")
    print(f"  Ataque:  {'HABILITADO' if SETTINGS.allow_attack else 'dry-run'}")
    print("  Ctrl+C para parar")
    print("=" * 64)
    if open_browser:
        threading.Timer(0.8, lambda: webbrowser.open(url)).start()
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n[!] Servidor detenido.")
    finally:
        server.server_close()
        JOBS.shutdown()
    return 0


if __name__ == "__main__":
    raise SystemExit(serve())
