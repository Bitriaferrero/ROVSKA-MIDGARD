#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Comparación de dos escaneos: qué aparece, qué desaparece y cómo cambia el riesgo.

La comparación se calcula sobre los informes normalizados, no sobre SQL, para
que funcione igual con escaneos propios y con informes importados.
"""

from __future__ import annotations

from . import db, report
from .models import SEV_ORDER, normalize_severity


def _finding_key(finding: dict) -> tuple[str, str, str]:
    return (
        str(finding.get("host", "")),
        str(finding.get("source", "")),
        str(finding.get("title", "")).strip().lower(),
    )


def _finding_index(items: list[dict]) -> dict[tuple[str, str, str], dict]:
    index: dict[tuple[str, str, str], dict] = {}
    order = {sev: i for i, sev in enumerate(SEV_ORDER)}
    for finding in items:
        item = dict(finding)
        item["severity"] = normalize_severity(item.get("severity"), "INFO")
        key = _finding_key(item)
        current = index.get(key)
        if current is None or order.get(item["severity"], 9) < order.get(current["severity"], 9):
            index[key] = item
    return index


def _host_index(items: list[dict]) -> dict[str, dict]:
    return {str(host.get("ip", "")): host for host in items if host.get("ip")}


def _port_index(items: list[dict]) -> dict[tuple[str, int, str], dict]:
    index: dict[tuple[str, int, str], dict] = {}
    for host in items:
        ip = str(host.get("ip", ""))
        for port in host.get("ports", []) or []:
            try:
                number = int(port.get("port"))
            except (TypeError, ValueError):
                continue
            proto = str(port.get("proto") or "tcp")
            index[(ip, number, proto)] = {
                "ip": ip,
                "port": number,
                "proto": proto,
                "state": port.get("state", ""),
                "name": port.get("name") or port.get("service") or "",
                "product": port.get("product", ""),
                "version": port.get("version", ""),
            }
    return index


def _technique_index(rep: dict) -> dict[str, dict]:
    index: dict[str, dict] = {}
    for tactic in rep.get("attack", {}).get("matrix", {}).get("tactics", []) or []:
        for technique in tactic.get("techniques", []) or []:
            ident = str(technique.get("id", ""))
            if not ident:
                continue
            item = index.setdefault(
                ident,
                {
                    "id": ident,
                    "name": technique.get("name", ""),
                    "tactics": [],
                    "count": 0,
                },
            )
            if tactic.get("name") not in item["tactics"]:
                item["tactics"].append(tactic.get("name", ""))
            item["count"] += int(technique.get("count", 0) or 0)
    return index


def _counts_delta(base: dict, target: dict) -> dict:
    return {sev: int(target.get(sev, 0) or 0) - int(base.get(sev, 0) or 0) for sev in SEV_ORDER}


def _summary(rep: dict) -> dict:
    return {
        "scan_id": rep.get("scan_id", ""),
        "target": rep.get("target", ""),
        "scanned_at": rep.get("scanned_at", ""),
        "profile": rep.get("profile", ""),
        "status": rep.get("status", ""),
        "hosts": len(rep.get("hosts", [])),
        "ports": rep.get("stats", {}).get("total_ports", 0),
        "findings": len(rep.get("findings", [])),
        "counts": rep.get("counts", {}),
        "risk": rep.get("risk", {}),
    }


def compare_scans(base_id: str = "", target_id: str = "") -> dict:
    """Devuelve el diff entre dos escaneos.

    Sin argumentos usa los dos últimos. Si solo se indica uno, el otro se
    resuelve con el escaneo más reciente o el inmediatamente anterior.
    """
    scans = db.query("SELECT id FROM scans ORDER BY started_at ASC")
    ids = [row["id"] for row in scans if row.get("id")]
    if not ids:
        raise ValueError("no hay escaneos para comparar")

    if target_id and target_id not in ids:
        raise KeyError(f"escaneo no encontrado: {target_id}")
    if base_id and base_id not in ids:
        raise KeyError(f"escaneo no encontrado: {base_id}")

    if not base_id and not target_id:
        if len(ids) < 2:
            raise ValueError("se necesitan al menos dos escaneos para comparar")
        base_id, target_id = ids[-2], ids[-1]
    elif not target_id:
        target_id = ids[-1] if ids[-1] != base_id else ids[-2]
    elif not base_id:
        position = ids.index(target_id)
        base_id = ids[position - 1] if position > 0 else ids[position]

    base = report.build(base_id)
    target = report.build(target_id)

    base_findings = _finding_index(base.get("findings", []))
    target_findings = _finding_index(target.get("findings", []))
    base_hosts = _host_index(base.get("hosts", []))
    target_hosts = _host_index(target.get("hosts", []))
    base_ports = _port_index(base.get("hosts", []))
    target_ports = _port_index(target.get("hosts", []))
    base_techniques = _technique_index(base)
    target_techniques = _technique_index(target)

    added_findings = [target_findings[key] for key in target_findings.keys() - base_findings.keys()]
    removed_findings = [base_findings[key] for key in base_findings.keys() - target_findings.keys()]
    persistent: list[dict] = []
    changed: list[dict] = []
    for key in base_findings.keys() & target_findings.keys():
        before = base_findings[key]
        after = target_findings[key]
        if before["severity"] != after["severity"]:
            changed.append(
                {
                    "host": after.get("host", ""),
                    "title": after.get("title", ""),
                    "source": after.get("source", ""),
                    "before": before["severity"],
                    "after": after["severity"],
                    "direction": "sube"
                    if SEV_ORDER.index(after["severity"]) < SEV_ORDER.index(before["severity"])
                    else "baja",
                }
            )
        else:
            persistent.append(after)

    added_hosts = [target_hosts[ip] for ip in target_hosts.keys() - base_hosts.keys()]
    removed_hosts = [base_hosts[ip] for ip in base_hosts.keys() - target_hosts.keys()]
    added_ports = [target_ports[key] for key in target_ports.keys() - base_ports.keys()]
    removed_ports = [base_ports[key] for key in base_ports.keys() - target_ports.keys()]
    changed_ports = []
    for key in base_ports.keys() & target_ports.keys():
        before = base_ports[key]
        after = target_ports[key]
        differences = {
            field: {"before": before[field], "after": after[field]}
            for field in ("name", "product", "version", "state")
            if before[field] != after[field]
        }
        if differences:
            changed_ports.append({**after, "changes": differences})

    added_techniques = [
        target_techniques[key] for key in target_techniques.keys() - base_techniques.keys()
    ]
    removed_techniques = [
        base_techniques[key] for key in base_techniques.keys() - target_techniques.keys()
    ]

    base_risk = int(base.get("risk", {}).get("score", 0) or 0)
    target_risk = int(target.get("risk", {}).get("score", 0) or 0)
    delta = target_risk - base_risk
    direction = "empeora" if delta > 0 else "mejora" if delta < 0 else "igual"
    headline = (
        f"Riesgo {delta:+d} · {len(added_findings)} nuevos · "
        f"{len(removed_findings)} cerrados · {len(changed)} con severidad distinta"
    )

    counts_delta = _counts_delta(base.get("counts", {}), target.get("counts", {}))

    return {
        "generated_at": db.utc_now(),
        "base": _summary(base),
        "target": _summary(target),
        "delta": {
            "risk": delta,
            "direction": direction,
            "headline": headline,
            "counts": counts_delta,
            "hosts": len(target_hosts) - len(base_hosts),
            "ports": len(target_ports) - len(base_ports),
            "findings": len(target_findings) - len(base_findings),
        },
        "hosts": {
            "added": sorted(added_hosts, key=lambda h: h.get("ip", "")),
            "removed": sorted(removed_hosts, key=lambda h: h.get("ip", "")),
            "persistent": sorted(
                [target_hosts[ip] for ip in target_hosts.keys() & base_hosts.keys()],
                key=lambda h: h.get("ip", ""),
            ),
        },
        "ports": {
            "added": sorted(added_ports, key=lambda p: (p["ip"], p["port"])),
            "removed": sorted(removed_ports, key=lambda p: (p["ip"], p["port"])),
            "changed": sorted(changed_ports, key=lambda p: (p["ip"], p["port"])),
        },
        "findings": {
            "added": sorted(added_findings, key=lambda f: f.get("title", "")),
            "removed": sorted(removed_findings, key=lambda f: f.get("title", "")),
            "persistent": sorted(persistent, key=lambda f: f.get("title", "")),
            "changed": sorted(changed, key=lambda f: f.get("title", "")),
        },
        "attack": {
            "added": sorted(added_techniques, key=lambda t: t["id"]),
            "removed": sorted(removed_techniques, key=lambda t: t["id"]),
        },
    }
