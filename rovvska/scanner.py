#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Orquestación de escaneos y operaciones.

Un escaneo ejecuta una cadena de herramientas, fusiona hosts/puertos, analiza
los resultados, los persiste y genera informes. Cada paso se registra como
evento para que el panel pueda seguirlo en vivo.
"""

from __future__ import annotations

import concurrent.futures
import json
import re
import shutil
import subprocess
import threading
import time
import urllib.error
import urllib.request
from pathlib import Path

from . import analyzer, db, report
from .config import SETTINGS, Settings
from .models import Host, Port, SEV_WEIGHT, counts_by_severity, risk_meta
from .runner import get_runner
from .scope import ScopeDecision, ScopeError, assert_target
from .tools import REGISTRY, get_tool
from .tools.base import ToolContext


PROFILES: dict[str, dict] = {
    "discovery": {
        "label": "Descubrimiento",
        "description": "Hosts activos, MAC/fabricante y nombres. No escanea puertos.",
        "nmap_profile": "discovery",
        "tools": ["arp_scan", "nmap"],
    },
    "quick": {
        "label": "Rápido",
        "description": "Top-1000 + puertos curados, versiones, scripts seguros y sonda HTTP.",
        "nmap_profile": "quick",
        "tools": ["arp_scan", "nmap", "http_probe"],
    },
    "full": {
        "label": "Completo",
        "description": "Los 65535 puertos TCP (lento) y detección de versiones.",
        "nmap_profile": "full",
        "tools": ["arp_scan", "masscan", "nmap", "http_probe"],
    },
    "web": {
        "label": "Web",
        "description": "WhatWeb, Nikto, Nuclei, testssl.sh y ffuf sobre los servicios web.",
        "nmap_profile": "quick",
        "nmap_ports": "80,443,8000,8006,8080,8081,8082,8443,8888,9000,9080,9090,9443,10000,15672",
        "tools": ["nmap", "http_probe", "whatweb", "nikto", "nuclei", "testssl", "web_fuzz"],
    },
    "infra": {
        "label": "Infraestructura",
        "description": "SSH, SMB, SNMP, DNS y servicios de gestión.",
        "nmap_profile": "quick",
        "nmap_ports": "22,53,111,135,139,161,389,443,445,636,1433,2049,3306,3389,5432,5900,5985,5986,6379,9200,27017",
        "tools": ["nmap", "http_probe", "ssh_audit", "smb", "snmp", "dns"],
    },
    "deep": {
        "label": "Profundo",
        "description": "Cadena completa de auditoría: red, web, infraestructura y exploits públicos.",
        "nmap_profile": "quick",
        "tools": [
            "arp_scan", "nmap", "http_probe", "whatweb", "nikto", "nuclei",
            "testssl", "web_fuzz", "ssh_audit", "smb", "snmp", "dns", "searchsploit",
        ],
    },
    "attack": {
        "label": "Ataque controlado",
        "description": "Reconocimiento + hydra/metasploit en dry-run (ejecución real solo con autorización).",
        "nmap_profile": "quick",
        "tools": ["arp_scan", "nmap", "http_probe", "ssh_audit", "smb", "snmp", "hydra", "metasploit"],
        "requires_attack": True,
    },
}


def _apply_snmp_meta(hosts_map: dict[str, Host], meta: dict) -> None:
    """Ajusta el SO con el sysDescr de SNMP (versión exacta si está disponible)."""
    snmp = (meta or {}).get("snmp") or {}
    if not isinstance(snmp, dict):
        return
    for ip, values in snmp.items():
        host = hosts_map.get(ip)
        if host is None or not isinstance(values, dict):
            continue
        os_name = analyzer.os_from_sysdescr(str(values.get("sysDescr", "")))
        if os_name:
            host.os = os_name


TTL_RE = re.compile(r"\bttl[= ](\d+)\b", re.I)


def _ping_ttl(ping: str, ip: str) -> int:
    try:
        result = subprocess.run(  # noqa: S603 - argv sin shell
            [ping, "-c", "1", "-W", "1", "-n", ip],
            capture_output=True,
            text=True,
            timeout=2,
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


def _probe_ttl(hosts: list[Host], log, cancel_event=None) -> int:
    """Sonda ICMP best-effort para desempatar SO cuando `-O` no da nada."""
    ping = shutil.which("ping")
    candidates = [host for host in hosts if host.ip and ":" not in host.ip]
    if not ping or not candidates:
        return 0
    if cancel_event is not None and cancel_event.is_set():
        return 0
    updated = 0
    with concurrent.futures.ThreadPoolExecutor(max_workers=min(32, len(candidates))) as pool:
        futures = {pool.submit(_ping_ttl, ping, host.ip): host for host in candidates}
        for future in concurrent.futures.as_completed(futures):
            host = futures[future]
            try:
                ttl = future.result()
            except Exception:  # noqa: BLE001 - sonda best-effort
                ttl = 0
            if ttl:
                host.extra["ttl"] = ttl
                updated += 1
    if updated:
        log(f"TTL obtenido en {updated}/{len(candidates)} hosts para afinar el SO", "info")
    return updated


def _merge_hosts(hosts_map: dict[str, Host], incoming: list[Host]) -> None:
    for host in incoming:
        current = hosts_map.get(host.ip)
        if current is None:
            hosts_map[host.ip] = host
            continue
        for port in host.ports:
            current.add_port(port)
        current.hostscripts.update(host.hostscripts or {})
        current.hostnames = sorted(set(current.hostnames + host.hostnames))
        current.mac = current.mac or host.mac
        current.vendor = current.vendor or host.vendor
        current.os = current.os or host.os
        current.type = current.type or host.type
        current.extra.update(host.extra or {})


def _scope_decision(target: str, authorization: bool) -> ScopeDecision:
    return assert_target(target, SETTINGS, authorization)


def run_scan(
    target: str,
    profile: str = "quick",
    options: dict | None = None,
    authorization: bool = False,
    progress=None,
    scan_id: str | None = None,
    cancel_event: threading.Event | None = None,
    settings: Settings | None = None,
) -> dict:
    settings = settings or SETTINGS
    options = dict(options or {})
    if profile not in PROFILES:
        raise ValueError(f"perfil desconocido: {profile}")
    decision = _scope_decision(target, authorization)

    scan_id = scan_id or db.new_id("scan")
    operation_id = db.new_id("op")
    started = db.utc_now()
    config = PROFILES[profile]
    mode = config.get("nmap_profile", "quick")
    if mode == "quick":
        mode = f"top-ports-{int(options.get('top_ports', 1000))}"
    elif mode == "full":
        mode = "full"
    elif mode == "discovery":
        mode = "discovery"

    with db.tx() as conn:
        conn.execute(
            "INSERT INTO scans (id, target, profile, mode, status, started_at, options_json, stats_json) "
            "VALUES (?,?,?,?,?,?,?,?) "
            "ON CONFLICT(id) DO UPDATE SET status='running', started_at=excluded.started_at, "
            "target=excluded.target, profile=excluded.profile, mode=excluded.mode, "
            "options_json=excluded.options_json",
            (scan_id, target, profile, mode, "running", started, db.json_dumps(options), "{}"),
        )
        conn.execute(
            "INSERT INTO operations (id, scan_id, kind, tool, target, params_json, status, risk_level, dry_run, started_at) "
            "VALUES (?,?,?,?,?,?,?,?,?,?)",
            (
                operation_id,
                scan_id,
                "scan",
                profile,
                target,
                db.json_dumps(options),
                "running",
                "safe" if profile != "attack" else "attack",
                1 if profile != "attack" else 0,
                started,
            ),
        )

    def log(message: str, level: str = "info") -> None:
        db.record_event(message, level, operation_id=operation_id, scan_id=scan_id)
        if progress:
            try:
                progress(message, level)
            except Exception:  # noqa: BLE001
                pass

    runner = get_runner(settings)
    hosts_map: dict[str, Host] = {}
    tool_findings = []
    tool_good: list[str] = []
    tool_summary: list[dict] = []
    proxmox: dict = {
        "cluster": "",
        "nodes_count": "",
        "quorate": "",
        "version": "",
        "source_ip": "",
        "nodes": [],
        "guests": [],
    }

    log(
        f"Escaneo {profile} sobre {target} · runner={runner.name} · {decision.host_count} hosts",
        "start",
    )

    try:
        for tool_name in config["tools"]:
            if cancel_event is not None and cancel_event.is_set():
                raise RuntimeError("escaneo cancelado por el usuario")
            tool = get_tool(tool_name)
            if tool is None:
                continue
            tool_options = dict(options)
            tool_options.setdefault("nmap_profile", config.get("nmap_profile", "quick"))
            if config.get("nmap_ports"):
                tool_options.setdefault("nmap_ports", config["nmap_ports"])
            if profile == "attack":
                tool_options.setdefault("authorization", authorization)

            if not tool.available(runner):
                log(f"{tool_name}: no disponible, se omite", "warn")
                tool_summary.append(
                    {"tool": tool_name, "status": "missing", "duration": 0, "error": "binario no disponible"}
                )
                continue

            if tool.spec.requires_attack and not settings.allow_attack:
                log(
                    f"{tool_name}: operación ofensiva real deshabilitada; se ejecutará en dry-run",
                    "warn",
                )

            ctx = ToolContext(
                runner=runner,
                target=target,
                workdir=runner.workdir(operation_id),
                options=tool_options,
                log=lambda message, level="info": log(f"{tool_name}: {message}", level),
                scan_id=scan_id,
                operation_id=operation_id,
                timeout=settings.tool_timeout,
                settings=settings,
                hosts=list(hosts_map.values()),
                cancel_event=cancel_event,
            )
            started_tool = time.monotonic()
            run_id = db.new_id("tr")
            try:
                result = tool.run(ctx)
            except Exception as exc:  # noqa: BLE001
                duration = time.monotonic() - started_tool
                log(f"{tool_name}: error inesperado: {exc}", "error")
                tool_summary.append(
                    {"tool": tool_name, "status": "error", "duration": round(duration, 2), "error": str(exc)}
                )
                db.execute(
                    "INSERT INTO tool_runs (id, scan_id, operation_id, tool, argv_json, started_at, finished_at, exit_code, error) "
                    "VALUES (?,?,?,?,?,?,?,?,?)",
                    (run_id, scan_id, operation_id, tool_name, "[]", db.utc_now(), db.utc_now(), -1, str(exc)),
                )
                continue
            duration = time.monotonic() - started_tool

            _merge_hosts(hosts_map, result.hosts)
            _apply_snmp_meta(hosts_map, result.meta)
            tool_findings.extend(result.findings)
            tool_good.extend(result.good)
            for raw_path in result.raw:
                _record_evidence(raw_path, operation_id, scan_id)

            status = "skipped" if result.skipped else ("ok" if result.ok else "error")
            tool_summary.append(
                {
                    "tool": tool_name,
                    "status": status,
                    "duration": round(duration, 2),
                    "error": result.error,
                    "hosts": len(result.hosts),
                    "findings": len(result.findings),
                }
            )
            db.execute(
                "INSERT INTO tool_runs (id, scan_id, operation_id, tool, argv_json, started_at, finished_at, exit_code, output_path, parsed, error) "
                "VALUES (?,?,?,?,?,?,?,?,?,?,?)",
                (
                    run_id,
                    scan_id,
                    operation_id,
                    tool_name,
                    db.json_dumps(result.command),
                    db.utc_now(),
                    db.utc_now(),
                    0 if result.ok else 1,
                    "",
                    1,
                    result.error,
                ),
            )
            log(
                f"{tool_name}: {status} · {len(result.hosts)} hosts · {len(result.findings)} hallazgos · {duration:.1f}s",
                "ok" if result.ok else "warn",
            )

        if cancel_event is not None and cancel_event.is_set():
            raise RuntimeError("escaneo cancelado por el usuario")

        if not hosts_map:
            log("No se detectaron hosts activos.", "warn")

        hosts = sorted(hosts_map.values(), key=lambda h: _ip_key(h.ip))
        if profile != "discovery" and not options.get("no_os"):
            _probe_ttl(hosts, log, cancel_event)
        proxmox = _proxmox_probe(hosts, log)
        analysis = analyzer.analyze(hosts, tool_findings, tool_good, proxmox)
        findings = analysis["findings"]
        good = analysis["good_checks"]
        counts = analysis["counts"]
        score = min(100, sum(SEV_WEIGHT.get(f.severity, 0) for f in findings))
        risk = risk_meta(score, counts, len(findings))

        _persist_results(scan_id, hosts, findings, good)
        stats = {
            "counts": counts,
            "risk": risk,
            "proxmox": proxmox,
            "scope": decision.to_dict(),
            "tools": tool_summary,
            "total_hosts": len(hosts),
            "total_ports": sum(len(h.ports) for h in hosts),
            "unique_services": len({p.service for h in hosts for p in h.ports if p.service}),
            "finished_at": db.utc_now(),
        }
        with db.tx() as conn:
            conn.execute(
                "UPDATE scans SET status='done', finished_at=?, stats_json=? WHERE id=?",
                (db.utc_now(), db.json_dumps(stats), scan_id),
            )
            conn.execute(
                "UPDATE operations SET status='done', finished_at=? WHERE id=?",
                (db.utc_now(), operation_id),
            )
        log(
            f"Escaneo completado: {len(hosts)} hosts, {len(findings)} hallazgos, riesgo {risk['score']}",
            "done",
        )
        paths = report.write_reports(scan_id)
        stats["reports"] = paths
        with db.tx() as conn:
            conn.execute("UPDATE scans SET stats_json=? WHERE id=?", (db.json_dumps(stats), scan_id))
        return report.build(scan_id)

    except Exception as exc:  # noqa: BLE001
        cancelled = bool(cancel_event is not None and cancel_event.is_set())
        status = "cancelled" if cancelled else "error"
        log(f"Escaneo {'cancelado' if cancelled else 'fallido'}: {exc}", "warn" if cancelled else "error")
        with db.tx() as conn:
            conn.execute(
                "UPDATE scans SET status=?, finished_at=?, error=? WHERE id=?",
                (status, db.utc_now(), None if cancelled else str(exc), scan_id),
            )
            conn.execute(
                "UPDATE operations SET status=?, finished_at=?, error=? WHERE id=?",
                (status, db.utc_now(), None if cancelled else str(exc), operation_id),
            )
        raise


def _persist_results(scan_id: str, hosts: list[Host], findings, good: list[str]) -> None:
    host_rows = []
    port_rows = []
    for host in hosts:
        extra = dict(host.extra)
        extra["risk"] = host.extra.get("risk", 0)
        host_rows.append(
            (
                scan_id,
                host.ip,
                host.mac,
                host.vendor,
                db.json_dumps(host.hostnames),
                host.os,
                host.type,
                int(host.extra.get("risk", 0)),
                db.json_dumps(extra),
            )
        )
        for port in host.ports:
            port_rows.append(
                (
                    scan_id,
                    host.ip,
                    port.port,
                    port.proto,
                    port.state,
                    port.service,
                    port.product,
                    port.version,
                    port.extrainfo,
                    db.json_dumps(port.scripts),
                )
            )
    finding_rows = []
    for finding in findings:
        finding_rows.append(
            (
                db.new_id("f"),
                scan_id,
                finding.host,
                finding.severity,
                finding.title,
                finding.evidence,
                finding.recommendation,
                db.json_dumps(finding.cves),
                db.json_dumps(finding.cwe),
                db.json_dumps(finding.attack),
                db.json_dumps(finding.frameworks),
                finding.source,
                finding.confidence,
                db.json_dumps(finding.tags),
                db.utc_now(),
            )
        )
    with db.tx() as conn:
        conn.execute("DELETE FROM hosts WHERE scan_id=?", (scan_id,))
        conn.execute("DELETE FROM ports WHERE scan_id=?", (scan_id,))
        conn.execute("DELETE FROM findings WHERE scan_id=?", (scan_id,))
        conn.execute("DELETE FROM good_checks WHERE scan_id=?", (scan_id,))
        conn.executemany(
            "INSERT INTO hosts (scan_id, ip, mac, vendor, hostnames_json, os, type, risk, extra_json) "
            "VALUES (?,?,?,?,?,?,?,?,?)",
            host_rows,
        )
        conn.executemany(
            "INSERT INTO ports (scan_id, ip, port, proto, state, service, product, version, extrainfo, scripts_json) "
            "VALUES (?,?,?,?,?,?,?,?,?,?)",
            port_rows,
        )
        conn.executemany(
            "INSERT INTO findings (id, scan_id, ip, severity, title, evidence, recommendation, cves_json, cwe_json, "
            "attack_json, frameworks_json, source, confidence, tags_json, created_at) "
            "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            finding_rows,
        )
        conn.executemany(
            "INSERT INTO good_checks (scan_id, text) VALUES (?,?)",
            [(scan_id, text) for text in good],
        )


def _record_evidence(path: str, operation_id: str, scan_id: str) -> None:
    import hashlib

    try:
        data = Path(path).read_bytes()
    except OSError:
        return
    db.execute(
        "INSERT INTO evidence (operation_id, scan_id, kind, path, sha256, created_at) VALUES (?,?,?,?,?,?)",
        (operation_id, scan_id, "tool-output", path, hashlib.sha256(data).hexdigest(), db.utc_now()),
    )


def _proxmox_probe(hosts: list[Host], log) -> dict:
    proxmox = {
        "cluster": "",
        "nodes_count": "",
        "quorate": "",
        "version": "",
        "source_ip": "",
        "nodes": [],
        "guests": [],
    }
    for host in hosts:
        if not any(p.port == 9221 for p in host.ports):
            continue
        url = f"http://{host.ip}:9221/pve?cluster=1"
        try:
            with urllib.request.urlopen(url, timeout=5) as response:
                body = response.read(500_000).decode("utf-8", errors="replace")
        except (urllib.error.URLError, TimeoutError, ValueError):
            continue
        version_match = re.search(r'pve_version_info\{[^}]*version="([^"]+)"', body)
        if version_match:
            proxmox["version"] = version_match.group(1)
        cluster_match = re.search(r"pve_cluster_info\{([^}]+)\}", body)
        if cluster_match:
            attrs = _prom_attrs(cluster_match.group(1))
            proxmox["cluster"] = attrs.get("id", "").replace("cluster/", "")
            proxmox["nodes_count"] = attrs.get("nodes", "")
            proxmox["quorate"] = attrs.get("quorate", "")
            proxmox["source_ip"] = host.ip
        for node_match in re.finditer(r"pve_node_info\{([^}]+)\}", body):
            attrs = _prom_attrs(node_match.group(1))
            if attrs.get("name") and all(n.get("name") != attrs["name"] for n in proxmox["nodes"]):
                proxmox["nodes"].append(attrs)
        for guest_match in re.finditer(r"pve_guest_info\{([^}]+)\}", body):
            attrs = _prom_attrs(guest_match.group(1))
            if attrs.get("id") and all(g.get("id") != attrs["id"] for g in proxmox["guests"]):
                proxmox["guests"].append(attrs)
        if proxmox["cluster"] or proxmox["version"]:
            log(f"Proxmox detectado en {host.ip}: {proxmox['cluster']} {proxmox['version']}", "ok")
            break
    return proxmox


def _prom_attrs(raw: str) -> dict:
    attrs = {}
    for part in raw.split(","):
        if "=" not in part:
            continue
        key, value = part.split("=", 1)
        attrs[key.strip()] = value.strip().strip('"')
    return attrs


def _ip_key(ip: str):
    import ipaddress

    try:
        value = ipaddress.ip_address(ip)
        return (value.version, int(value))
    except ValueError:
        return (99, ip)


# --- operaciones individuales ---------------------------------------------


def run_operation(
    tool_name: str,
    target: str,
    params: dict | None = None,
    authorization: bool = False,
    dry_run: bool = True,
    scan_id: str | None = None,
    settings: Settings | None = None,
    progress=None,
    cancel_event: threading.Event | None = None,
    operation_id: str | None = None,
) -> dict:
    settings = settings or SETTINGS
    params = dict(params or {})
    decision = _scope_decision(target, authorization)
    tool = get_tool(tool_name)
    if tool is None:
        raise ValueError(f"herramienta desconocida: {tool_name}")
    if tool.spec.requires_attack and not settings.allow_attack:
        dry_run = True
    params.setdefault("execute", not dry_run)
    params.setdefault("authorization", authorization)

    operation_id = operation_id or db.new_id("op")
    started = db.utc_now()
    db.execute(
        "INSERT INTO operations (id, scan_id, kind, tool, target, params_json, status, risk_level, dry_run, started_at) "
        "VALUES (?,?,?,?,?,?,?,?,?,?) "
        "ON CONFLICT(id) DO UPDATE SET status='running', started_at=excluded.started_at, "
        "target=excluded.target, params_json=excluded.params_json, dry_run=excluded.dry_run",
        (
            operation_id,
            scan_id,
            "tool",
            tool_name,
            target,
            db.json_dumps(params),
            "running",
            "attack" if tool.spec.requires_attack else "safe",
            1 if dry_run else 0,
            started,
        ),
    )

    def log(message: str, level: str = "info") -> None:
        db.record_event(message, level, operation_id=operation_id, scan_id=scan_id)
        if progress:
            try:
                progress(message, level)
            except Exception:  # noqa: BLE001
                pass

    runner = get_runner(settings)
    if not tool.available(runner):
        message = f"{tool_name} no está disponible en el runner {runner.name}"
        db.execute(
            "UPDATE operations SET status='error', finished_at=?, error=? WHERE id=?",
            (db.utc_now(), message, operation_id),
        )
        log(message, "error")
        return _load_operation(operation_id)

    hosts = _hosts_from_params(params, target)
    ctx = ToolContext(
        runner=runner,
        target=target,
        workdir=runner.workdir(operation_id),
        options=params,
        log=lambda message, level="info": log(f"{tool_name}: {message}", level),
        scan_id=scan_id or "",
        operation_id=operation_id,
        timeout=settings.tool_timeout,
        settings=settings,
        hosts=hosts,
        cancel_event=cancel_event,
    )
    log(f"Operación {tool_name} sobre {target} (dry_run={dry_run})", "start")
    if cancel_event is not None and cancel_event.is_set():
        db.execute(
            "UPDATE operations SET status='cancelled', finished_at=? WHERE id=?",
            (db.utc_now(), operation_id),
        )
        log(f"Operación {tool_name} cancelada antes de ejecutar", "warn")
        return _load_operation(operation_id)
    try:
        result = tool.run(ctx)
        if cancel_event is not None and cancel_event.is_set():
            db.execute(
                "UPDATE operations SET status='cancelled', finished_at=? WHERE id=?",
                (db.utc_now(), operation_id),
            )
            log(f"Operación {tool_name} cancelada por el usuario", "warn")
            return _load_operation(operation_id)
        log_text = "\n".join(
            [f"$ {' '.join(result.command)}"] if result.command else []
        )
        if result.error:
            log_text += ("\n" if log_text else "") + result.error
        for finding in result.findings:
            log_text += f"\n[{finding.severity}] {finding.title}: {finding.evidence}"
        db.execute(
            "UPDATE operations SET status=?, finished_at=?, exit_code=?, log=?, result_json=? WHERE id=?",
            (
                "done" if result.ok else "error",
                db.utc_now(),
                0 if result.ok else 1,
                log_text[-20000:],
                db.json_dumps(result.to_dict()),
                operation_id,
            ),
        )
        log(f"Operación {tool_name} terminada", "done" if result.ok else "warn")
    except Exception as exc:  # noqa: BLE001
        cancelled = bool(cancel_event is not None and cancel_event.is_set())
        db.execute(
            "UPDATE operations SET status=?, finished_at=?, error=? WHERE id=?",
            ("cancelled" if cancelled else "error", db.utc_now(), None if cancelled else str(exc), operation_id),
        )
        log(
            f"Operación {tool_name} {'cancelada' if cancelled else 'fallida'}: {exc}",
            "warn" if cancelled else "error",
        )
    return _load_operation(operation_id)


def _hosts_from_params(params: dict, target: str) -> list[Host]:
    raw_hosts = params.get("hosts")
    hosts: list[Host] = []
    if isinstance(raw_hosts, list):
        for item in raw_hosts:
            if isinstance(item, dict) and item.get("ip"):
                host = Host(ip=str(item["ip"]))
                for port in item.get("ports", []) or []:
                    if isinstance(port, dict):
                        host.add_port(
                            Port(
                                port=int(port.get("port", 0)),
                                proto=port.get("proto", "tcp"),
                                service=port.get("name") or port.get("service", ""),
                                product=port.get("product", ""),
                                version=port.get("version", ""),
                            )
                        )
                    elif isinstance(port, int):
                        host.add_port(Port(port=port))
                hosts.append(host)
    if not hosts:
        host = Host(ip=target)
        for port in params.get("ports", []) or []:
            try:
                host.add_port(Port(port=int(port)))
            except (TypeError, ValueError):
                continue
        hosts.append(host)
    return hosts


def _load_operation(operation_id: str) -> dict:
    row = db.query_one("SELECT * FROM operations WHERE id=?", (operation_id,))
    if not row:
        raise KeyError(operation_id)
    row["params"] = db.json_loads(row.pop("params_json", "{}"), {})
    row["result"] = db.json_loads(row.pop("result_json", "{}"), {})
    return row
