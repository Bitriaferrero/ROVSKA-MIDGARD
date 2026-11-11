#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Generación de informes: JSON, XML, HTML autocontenido, SARIF y CSV.

El JSON mantiene las claves del proyecto AUDITORIA_PLUS (``target``,
``scanned_at``, ``mode``, ``hosts``, ``findings``, ``good_checks``, ``proxmox``,
``counts``) y añade ATT&CK, marcos, operaciones y estadísticas.
"""

from __future__ import annotations

import csv
import hashlib
import json
import os
import re
import xml.etree.ElementTree as ET
from datetime import datetime
from pathlib import Path
from xml.dom import minidom

from . import attack, frameworks
from .config import SETTINGS
from .db import json_loads, query, query_one, utc_now
from .models import (
    Finding,
    Host,
    Port,
    SEV_ORDER,
    SEV_WEIGHT,
    counts_by_severity,
    risk_meta,
)
from .runner import get_runner


LIMITATIONS = [
    "El SO se obtiene con nmap -O (root/Docker) y se afina con banners, puertos, MAC y SNMP; la versión exacta puede requerir SNMP o acceso autenticado.",
    "Las reglas EOL/CVE son heurísticas: confirma siempre con los avisos oficiales del fabricante.",
    "La asignación exacta IP → invitado de Proxmox requiere DHCP o la API con credenciales.",
    "La exposición desde WAN no se puede comprobar desde la LAN.",
    "Las operaciones ofensivas (hydra/metasploit) son dry-run salvo autorización expresa.",
    "ROVSKA no modifica el objetivo salvo que se habilite explícitamente una operación de ataque.",
]


def safe_name(value: str) -> str:
    return re.sub(r"[^A-Za-z0-9_.-]+", "_", value).strip("_")[:60] or "objetivo"


def load_scan(scan_id: str) -> dict:
    scan = query_one("SELECT * FROM scans WHERE id=?", (scan_id,))
    if not scan:
        raise KeyError(f"escaneo no encontrado: {scan_id}")
    return scan


def load_hosts(scan_id: str) -> list[Host]:
    rows = query("SELECT * FROM hosts WHERE scan_id=? ORDER BY ip", (scan_id,))
    hosts: list[Host] = []
    for row in rows:
        host = Host(
            ip=row["ip"],
            mac=row["mac"],
            vendor=row["vendor"],
            hostnames=json_loads(row["hostnames_json"], []),
            os=row["os"],
            type=row["type"],
            extra=json_loads(row["extra_json"], {}),
        )
        for port_row in query(
            "SELECT * FROM ports WHERE scan_id=? AND ip=? ORDER BY port",
            (scan_id, row["ip"]),
        ):
            host.add_port(
                Port(
                    port=port_row["port"],
                    proto=port_row["proto"],
                    state=port_row["state"],
                    service=port_row["service"],
                    product=port_row["product"],
                    version=port_row["version"],
                    extrainfo=port_row["extrainfo"],
                    scripts=json_loads(port_row["scripts_json"], {}),
                )
            )
        hosts.append(host)
    return hosts


def load_findings(scan_id: str) -> list[Finding]:
    rows = query("SELECT * FROM findings WHERE scan_id=? ORDER BY severity, ip", (scan_id,))
    findings = []
    for row in rows:
        findings.append(
            Finding(
                severity=row["severity"],
                title=row["title"],
                host=row["ip"],
                evidence=row["evidence"],
                recommendation=row["recommendation"],
                cves=json_loads(row["cves_json"], []),
                cwe=json_loads(row["cwe_json"], []),
                attack=json_loads(row["attack_json"], []),
                frameworks=json_loads(row["frameworks_json"], {}),
                source=row["source"],
                confidence=row["confidence"],
                tags=json_loads(row["tags_json"], []),
            )
        )
    order = {sev: i for i, sev in enumerate(SEV_ORDER)}
    findings.sort(key=lambda f: (order.get(f.severity, 9), f.host, f.title))
    return findings


def load_good(scan_id: str) -> list[str]:
    return [row["text"] for row in query("SELECT text FROM good_checks WHERE scan_id=? ORDER BY id", (scan_id,))]


def load_operations(scan_id: str) -> list[dict]:
    rows = query("SELECT * FROM operations WHERE scan_id=? ORDER BY started_at", (scan_id,))
    for row in rows:
        row["params"] = json_loads(row.pop("params_json", "{}"), {})
        row["result"] = json_loads(row.pop("result_json", "{}"), {})
    return rows


def load_tool_runs(scan_id: str) -> list[dict]:
    rows = query("SELECT * FROM tool_runs WHERE scan_id=? ORDER BY started_at", (scan_id,))
    for row in rows:
        row["argv"] = json_loads(row.pop("argv_json", "[]"), [])
    return rows


def build(scan_id: str) -> dict:
    scan = load_scan(scan_id)
    hosts = load_hosts(scan_id)
    findings = load_findings(scan_id)
    good = load_good(scan_id)
    operations = load_operations(scan_id)
    tool_runs = load_tool_runs(scan_id)
    stats = json_loads(scan.get("stats_json"), {})
    proxmox = stats.get("proxmox", {}) or {}

    counts = counts_by_severity(findings)
    total_ports = sum(len(h.ports) for h in hosts)
    services = {p.service for h in hosts for p in h.ports if p.service}
    score = min(100, sum(SEV_WEIGHT.get(f.severity, 0) for f in findings))
    matrix = attack.build_matrix(findings, operations)
    chain = attack.build_kill_chain(hosts, findings, operations)
    fw = frameworks.summary(findings)
    tool_names = [run["tool"] for run in tool_runs if run.get("tool")]

    host_dicts = []
    for host in hosts:
        data = host.to_dict()
        data["risk"] = host.extra.get("risk", 0)
        data["risk_meta"] = host.extra.get("risk_meta", risk_meta(0, {}, 0))
        data["severity_counts"] = host.extra.get(
            "severity_counts", counts_by_severity([f for f in findings if f.host == host.ip])
        )
        host_dicts.append(data)

    report = {
        "schema_version": "2.0",
        "generator": "ROVSKA",
        "scan_id": scan_id,
        "target": scan["target"],
        "scanned_at": scan["started_at"],
        "finished_at": scan.get("finished_at") or "",
        "mode": scan["mode"] or scan["profile"],
        "profile": scan["profile"],
        "status": scan["status"],
        "hosts": host_dicts,
        "findings": [f.to_dict() for f in findings],
        "good_checks": good,
        "proxmox": proxmox,
        "counts": counts,
        "risk": risk_meta(score, counts, len(findings)),
        "attack": {
            "matrix": matrix,
            "kill_chain": chain,
            "summary": attack.summarize(findings),
            "coverage": attack.coverage(tool_names),
        },
        "frameworks": fw,
        "operations": operations,
        "tools": tool_runs,
        "stats": {
            "total_hosts": len(hosts),
            "hosts_with_ports": sum(1 for h in hosts if h.ports),
            "total_ports": total_ports,
            "unique_services": len(services),
            "total_findings": len(findings),
            "severity_counts": counts,
            "risk": risk_meta(score, counts, len(findings)),
            "reports": stats.get("reports", {}),
            "pdf": stats.get("pdf", {}),
            "imported": stats.get("imported", False),
            "source_file": stats.get("source_file", ""),
            "source_format": stats.get("source_format", ""),
        },
        "limitations": LIMITATIONS,
        "scope": stats.get("scope", {}),
    }
    return report


def report_basename(scan: dict) -> str:
    """Nombre base único de los informes de un escaneo.

    Dos escaneos pueden compartir objetivo y segundo de inicio (por ejemplo, un
    escaneo real y la importación de su propio informe). En ese caso se añade
    un sufijo con el id para no sobrescribir la evidencia del otro escaneo.
    """
    stamp = re.sub(r"[^0-9]", "", str(scan.get("started_at", "")))[:14]
    base = f"informe_{safe_name(scan['target'])}_{stamp}"
    scan_id = str(scan.get("id", ""))
    if not scan_id:
        return base

    def owns(candidate: str, stats: dict) -> bool:
        return any(Path(str(path)).stem == candidate for path in (stats.get("reports") or {}).values())

    own_stats = json_loads(scan.get("stats_json"), {}) or {}
    collision = False
    if not owns(base, own_stats):
        for row in query("SELECT id, stats_json FROM scans WHERE id != ?", (scan_id,)):
            if owns(base, json_loads(row.get("stats_json"), {}) or {}):
                collision = True
                break
        # Respaldo por si el otro escaneo aún no persistió sus rutas: si ya
        # existe un fichero con ese nombre, no lo pisamos.
        if not collision:
            collision = any((SETTINGS.reports_dir / f"{base}.{ext}").exists() for ext in ("json", "xml", "pdf"))
    if collision:
        return f"{base}_{safe_name(scan_id.rsplit('_', 1)[-1])[-6:]}"
    return base


def write_reports(scan_id: str, include_pdf: bool = True, runner=None) -> dict:
    """Genera todos los formatos y devuelve las rutas escritas.

    El PDF es opcional: si WeasyPrint no está disponible en el runner, el resto
    de formatos se generan igualmente y el error queda registrado en
    ``stats.pdf``. Así un fallo del renderizador nunca invalida la evidencia.
    """
    report = build(scan_id)
    scan = load_scan(scan_id)
    base = report_basename(scan)
    out = SETTINGS.reports_dir
    out.mkdir(parents=True, exist_ok=True)
    paths = {
        "json": out / f"{base}.json",
        "xml": out / f"{base}.xml",
        "html": out / f"{base}.html",
        "sarif": out / f"{base}.sarif",
        "csv": out / f"{base}.csv",
    }
    paths["html"].write_text(render_html(report), encoding="utf-8")

    pdf_status = {"ok": False, "error": "PDF desactivado"}
    if include_pdf:
        pdf_status = generate_pdf(report, out, base, runner=runner)
        if pdf_status.get("ok"):
            paths["pdf"] = out / f"{base}.pdf"

    report.setdefault("stats", {})["reports"] = {key: str(value) for key, value in paths.items()}
    report["stats"]["pdf"] = pdf_status
    paths["json"].write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
    paths["xml"].write_text(render_xml(report), encoding="utf-8")
    paths["sarif"].write_text(
        json.dumps(render_sarif(report), ensure_ascii=False, indent=2), encoding="utf-8"
    )
    paths["csv"].write_text(render_csv(report), encoding="utf-8")
    return {key: str(value) for key, value in paths.items()}


def generate_pdf(report: dict, out_dir: Path, base: str, runner=None) -> dict:
    """Renderiza ``report`` a PDF con WeasyPrint dentro del runner configurado.

    No lanza excepciones: devuelve ``{"ok": bool, "path"|"error": ...}`` para que
    el escaneo pueda continuar aunque el contenedor no tenga WeasyPrint.
    """
    out_dir = Path(out_dir)
    print_html = out_dir / f".{base}.print.html"
    pdf_path = out_dir / f"{base}.pdf"
    try:
        print_html.write_text(render_html(report, for_pdf=True), encoding="utf-8")
        runner = runner or get_runner(SETTINGS)
        if not runner.available("weasyprint"):
            return {
                "ok": False,
                "error": (
                    "WeasyPrint no está disponible en el runner. "
                    "Reconstruye la imagen: ./run.sh up"
                ),
            }
        cmd = runner.run(
            ["weasyprint", "--encoding", "utf-8", print_html.name, pdf_path.name],
            timeout=180,
            cwd=out_dir,
        )
        if not cmd.ok or not pdf_path.is_file() or pdf_path.stat().st_size < 1000:
            return {
                "ok": False,
                "error": (cmd.output[-1200:] or "WeasyPrint no generó el PDF"),
            }
        # El contenedor ejecuta como root: devuelve el PDF al UID del host para
        # que el usuario pueda abrirlo, moverlo o borrarlo sin sudo.
        if getattr(runner, "name", "") == "docker":
            try:
                runner.run(
                    ["chown", f"{os.getuid()}:{os.getgid()}", pdf_path.name],
                    timeout=30,
                    cwd=out_dir,
                )
            except Exception:  # noqa: BLE001
                pass
        return {
            "ok": True,
            "path": str(pdf_path),
            "bytes": pdf_path.stat().st_size,
            "duration": round(cmd.duration, 2),
        }
    except Exception as exc:  # noqa: BLE001
        return {"ok": False, "error": str(exc)}
    finally:
        try:
            print_html.unlink(missing_ok=True)
        except OSError:
            pass


# --- XML -------------------------------------------------------------------


def render_xml(report: dict) -> str:
    root = ET.Element(
        "rovska-report",
        {
            "schema": report.get("schema_version", "2.0"),
            "generator": report.get("generator", "ROVSKA"),
            "scan-id": report.get("scan_id", ""),
            "target": report.get("target", ""),
            "scanned-at": report.get("scanned_at", ""),
            "profile": report.get("profile", ""),
        },
    )
    summary = ET.SubElement(root, "summary")
    for sev in SEV_ORDER:
        ET.SubElement(
            summary,
            "severity",
            {"name": sev, "count": str(report["counts"].get(sev, 0))},
        )
    risk = report.get("risk", {})
    ET.SubElement(
        summary,
        "risk",
        {"score": str(risk.get("score", 0)), "label": str(risk.get("label", ""))},
    )

    hosts_el = ET.SubElement(root, "hosts")
    for host in report.get("hosts", []):
        h = ET.SubElement(
            hosts_el,
            "host",
            {
                "ip": host.get("ip", ""),
                "mac": host.get("mac", ""),
                "vendor": host.get("vendor", ""),
                "type": host.get("type", ""),
                "os": host.get("os", ""),
                "risk": str(host.get("risk", 0)),
            },
        )
        for name in host.get("hostnames", []):
            ET.SubElement(h, "hostname", {"name": name})
        ports_el = ET.SubElement(h, "ports")
        for port in host.get("ports", []):
            ET.SubElement(
                ports_el,
                "port",
                {
                    "number": str(port.get("port", "")),
                    "proto": port.get("proto", "tcp"),
                    "service": port.get("name", ""),
                    "product": port.get("product", ""),
                    "version": port.get("version", ""),
                },
            )

    findings_el = ET.SubElement(root, "findings")
    for finding in report.get("findings", []):
        f = ET.SubElement(
            findings_el,
            "finding",
            {
                "severity": finding.get("severity", ""),
                "host": finding.get("host", ""),
                "source": finding.get("source", ""),
                "confidence": finding.get("confidence", ""),
            },
        )
        ET.SubElement(f, "title").text = finding.get("title", "")
        ET.SubElement(f, "evidence").text = finding.get("evidence", "")
        ET.SubElement(f, "recommendation").text = finding.get("recommendation", "")
        for cve in finding.get("cves", []):
            ET.SubElement(f, "cve").text = cve
        for cwe in finding.get("cwe", []):
            ET.SubElement(f, "cwe").text = cwe
        for technique in finding.get("attack", []):
            ET.SubElement(f, "attack-technique").text = technique
        fw = finding.get("frameworks", {}) or {}
        ptes = fw.get("ptes", {}) or {}
        if ptes:
            ET.SubElement(f, "ptes", {"phase": ptes.get("phase", "")})
        owasp = fw.get("owasp", {}) or {}
        for item in owasp.get("top10", []):
            ET.SubElement(f, "owasp", {"id": item})

    good_el = ET.SubElement(root, "good-checks")
    for text in report.get("good_checks", []):
        ET.SubElement(good_el, "check").text = text

    attack_el = ET.SubElement(root, "attack")
    for tactic in report.get("attack", {}).get("matrix", {}).get("tactics", []):
        t = ET.SubElement(
            attack_el,
            "tactic",
            {"id": tactic["id"], "name": tactic["name"], "count": str(tactic["count"])},
        )
        for technique in tactic.get("techniques", []):
            ET.SubElement(
                t,
                "technique",
                {
                    "id": technique["id"],
                    "name": technique["name"],
                    "count": str(technique["count"]),
                    "max-severity": technique.get("max_severity", ""),
                },
            )
    chain_el = ET.SubElement(root, "kill-chain")
    for stage in report.get("attack", {}).get("kill_chain", {}).get("stages", []):
        s = ET.SubElement(
            chain_el,
            "stage",
            {"id": stage["id"], "name": stage["name"], "status": stage["status"]},
        )
        for step in stage.get("steps", []):
            ET.SubElement(
                s,
                "step",
                {"technique": step.get("technique", ""), "severity": step.get("severity", "")},
            ).text = step.get("title", "")

    operations_el = ET.SubElement(root, "operations")
    for op in report.get("operations", []):
        ET.SubElement(
            operations_el,
            "operation",
            {
                "id": op.get("id", ""),
                "kind": op.get("kind", ""),
                "tool": op.get("tool", ""),
                "target": op.get("target", ""),
                "status": op.get("status", ""),
                "dry-run": str(op.get("dry_run", 1)),
            },
        )

    raw = ET.tostring(root, encoding="utf-8")
    return minidom.parseString(raw).toprettyxml(indent="  ", encoding="utf-8").decode("utf-8")


# --- SARIF -----------------------------------------------------------------


def render_sarif(report: dict) -> dict:
    rules = []
    rule_index: dict[str, int] = {}
    for finding in report.get("findings", []):
        rule_id = safe_name(finding.get("title", "finding")).lower()
        if rule_id in rule_index:
            continue
        rule_index[rule_id] = len(rules)
        rules.append(
            {
                "id": rule_id,
                "name": finding.get("title", ""),
                "shortDescription": {"text": finding.get("title", "")},
                "fullDescription": {"text": finding.get("evidence", "")},
                "help": {"text": finding.get("recommendation", "")},
                "properties": {
                    "severity": finding.get("severity", ""),
                    "cve": finding.get("cves", []),
                    "cwe": finding.get("cwe", []),
                    "attack": finding.get("attack", []),
                    "source": finding.get("source", ""),
                },
            }
        )
    results = []
    for finding in report.get("findings", []):
        rule_id = safe_name(finding.get("title", "finding")).lower()
        level = {"CRÍTICO": "error", "ALTO": "error", "MEDIO": "warning", "BAJO": "note"}.get(
            finding.get("severity", ""), "note"
        )
        results.append(
            {
                "ruleId": rule_id,
                "ruleIndex": rule_index.get(rule_id, 0),
                "level": level,
                "message": {"text": finding.get("evidence", "")},
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {"uri": f"host://{finding.get('host', '')}"},
                            "region": {"startLine": 1},
                        }
                    }
                ],
                "properties": {
                    "severity": finding.get("severity", ""),
                    "recommendation": finding.get("recommendation", ""),
                    "cve": finding.get("cves", []),
                    "cwe": finding.get("cwe", []),
                    "attack": finding.get("attack", []),
                },
            }
        )
    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "ROVSKA",
                        "informationUri": "https://github.com/",
                        "rules": rules,
                    }
                },
                "results": results,
                "properties": {
                    "target": report.get("target", ""),
                    "scanned_at": report.get("scanned_at", ""),
                    "risk": report.get("risk", {}),
                },
            }
        ],
    }


# --- CSV -------------------------------------------------------------------


def render_csv(report: dict) -> str:
    import io

    buffer = io.StringIO()
    writer = csv.writer(buffer)
    writer.writerow(
        [
            "severidad",
            "host",
            "titulo",
            "evidencia",
            "recomendacion",
            "cve",
            "cwe",
            "attack",
            "ptes",
            "owasp",
            "fuente",
            "confianza",
        ]
    )
    for finding in report.get("findings", []):
        fw = finding.get("frameworks", {}) or {}
        writer.writerow(
            [
                finding.get("severity", ""),
                finding.get("host", ""),
                finding.get("title", ""),
                finding.get("evidence", ""),
                finding.get("recommendation", ""),
                " ".join(finding.get("cves", [])),
                " ".join(finding.get("cwe", [])),
                " ".join(finding.get("attack", [])),
                (fw.get("ptes", {}) or {}).get("phase", ""),
                " ".join((fw.get("owasp", {}) or {}).get("top10", [])),
                finding.get("source", ""),
                finding.get("confidence", ""),
            ]
        )
    return buffer.getvalue()


# --- HTML ------------------------------------------------------------------


def e(value) -> str:
    return (
        str(value if value is not None else "")
        .replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
    )


def render_html(report: dict, for_pdf: bool = False) -> str:
    counts = report.get("counts", {})
    total = sum(counts.values())
    risk = report.get("risk", {})
    host_count = len(report.get("hosts", []))
    port_count = report["stats"].get("total_ports", 0)
    findings = report.get("findings", [])
    matrix = report.get("attack", {}).get("matrix", {}).get("tactics", [])
    chain = report.get("attack", {}).get("kill_chain", {}).get("stages", [])
    fw = report.get("frameworks", {})
    cover = _cover_html(report) if for_pdf else ""
    exec_summary = _exec_summary(report) if for_pdf else ""
    body_class = ' class="pdf"' if for_pdf else ""

    sev_cards = "".join(
        f'<div class="sev {cls}"><div class="n">{counts.get(sev, 0)}</div><div class="l">{sev}</div></div>'
        for sev, cls in zip(SEV_ORDER, ["crit", "high", "med", "low", "info"])
    )

    host_rows = "".join(
        f"<tr><td class='mono'>{e(h.get('ip'))}</td><td>{e(h.get('type'))}</td>"
        f"<td>{e(h.get('os'))}</td><td>{e(', '.join(h.get('hostnames', [])))}</td>"
        f"<td>{len(h.get('ports', []))}</td><td class='num'>{h.get('risk', 0)}</td></tr>"
        for h in report.get("hosts", [])
    )

    finding_cards = "".join(
        f"""<article class="finding {_sev_cls(f.get('severity'))}">
          <div class="fhead"><span class="badge {_sev_cls(f.get('severity'))}">{e(f.get('severity'))}</span>
          <b>{e(f.get('title'))}</b><span class="fhost">{e(f.get('host'))}</span></div>
          <p>{e(f.get('evidence'))}</p>
          <p class="rec"><b>Recomendación:</b> {e(f.get('recommendation'))}</p>
          {_chips("CVE", f.get("cves", []))}{_chips("CWE", f.get("cwe", []))}{_chips("ATT&CK", f.get("attack", []))}
        </article>"""
        for f in findings
    ) or "<p class='muted'>Sin hallazgos.</p>"

    matrix_rows = ""
    for tactic in matrix:
        if not tactic.get("techniques"):
            continue
        cells = "".join(
            f"<span class='tech {_sev_cls(t.get('max_severity'))}' title='{e(t.get('name'))}'>"
            f"{e(t.get('id'))}<i>{t.get('count')}</i></span>"
            for t in tactic["techniques"]
        )
        matrix_rows += f"<tr><th>{e(tactic.get('name'))}</th><td>{cells}</td></tr>"

    chain_html = "".join(
        f"""<div class="stage {('done' if s.get('status') == 'observado' else 'idle')}">
          <div class="stname">{e(s.get('name'))}<span>{e(s.get('status'))}</span></div>
          {''.join(f"<div class='step'><b>{e(x.get('technique'))}</b> {e(x.get('title'))} <em>{e(x.get('host'))}</em></div>" for x in s.get('steps', [])[:6])}
        </div>"""
        for s in chain
    )

    ptes_rows = "".join(
        f"<tr><td>{e(p.get('name'))}</td><td>{e(p.get('description'))}</td><td class='num'>{p.get('count', 0)}</td></tr>"
        for p in fw.get("ptes", [])
    )
    owasp_rows = "".join(
        f"<tr><td>{e(o.get('id'))}</td><td>{e(o.get('name'))}</td><td class='num'>{o.get('count', 0)}</td></tr>"
        for o in fw.get("owasp", {}).get("top10", [])
        if o.get("count", 0)
    )
    cwe_rows = "".join(
        f"<tr><td>{e(c.get('id'))}</td><td>{e(c.get('name'))}</td><td class='num'>{c.get('count', 0)}</td></tr>"
        for c in fw.get("cwe", [])[:12]
    )

    operations_rows = "".join(
        f"<tr><td>{e(o.get('tool'))}</td><td>{e(o.get('kind'))}</td><td>{e(o.get('target'))}</td>"
        f"<td>{e(o.get('status'))}</td><td>{'sí' if o.get('dry_run') else 'no'}</td></tr>"
        for o in report.get("operations", [])
    ) or "<tr><td colspan='5' class='muted'>Sin operaciones registradas.</td></tr>"

    good = "".join(f"<li>{e(g)}</li>" for g in report.get("good_checks", []))

    return f"""<!DOCTYPE html>
<html lang="es"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>ROVSKA · {e(report.get('target'))} · {e(report.get('scanned_at'))}</title>
<style>{REPORT_CSS}{PDF_CSS if for_pdf else ""}</style></head>
<body{body_class}>
{cover}
<header class="top">
  <div><div class="brand">▚ ROVSKA</div><h1>{e(report.get('target'))}</h1>
  <p>{e(report.get('scanned_at'))} · perfil {e(report.get('profile'))} · {host_count} hosts · {port_count} puertos</p></div>
  <div class="risk {_sev_cls(risk.get('label'))}"><div class="score">{risk.get('score', 0)}</div><div>{e(risk.get('label'))}</div></div>
</header>
<main>
{exec_summary}
<section><h2>Resumen</h2><div class="sevs">{sev_cards}</div>
<p class="muted">Generado por ROVSKA · {total} hallazgos · {report['stats'].get('unique_services', 0)} servicios únicos.</p></section>

<section><h2>Matriz MITRE ATT&amp;CK</h2><table class="matrix"><tbody>{matrix_rows or '<tr><td class="muted">Sin técnicas observadas.</td></tr>'}</tbody></table></section>

<section><h2>Cadena de ataque reconstruida</h2><div class="chain">{chain_html}</div></section>

<section><h2>Hosts</h2><table><thead><tr><th>IP</th><th>Tipo</th><th>SO</th><th>DNS</th><th>Puertos</th><th>Riesgo</th></tr></thead><tbody>{host_rows or '<tr><td colspan="6" class="muted">Sin hosts.</td></tr>'}</tbody></table></section>

<section><h2>Hallazgos</h2>{finding_cards}</section>

<section class="pb"><h2>Metodologías</h2><table><thead><tr><th>PTES</th><th>Fase</th><th>Hallazgos</th></tr></thead><tbody>{ptes_rows}</tbody></table>
<table><thead><tr><th>OWASP Top 10</th><th>Categoría</th><th>Hallazgos</th></tr></thead><tbody>{owasp_rows or '<tr><td colspan="3" class="muted">Sin hallazgos web mapeados.</td></tr>'}</tbody></table>
<table><thead><tr><th>CWE</th><th>Debilidad</th><th>Hallazgos</th></tr></thead><tbody>{cwe_rows or '<tr><td colspan="3" class="muted">Sin CWE.</td></tr>'}</tbody></table></section>

<section><h2>Operaciones</h2><table><thead><tr><th>Herramienta</th><th>Tipo</th><th>Objetivo</th><th>Estado</th><th>Dry-run</th></tr></thead><tbody>{operations_rows}</tbody></table></section>

<section><h2>Comprobaciones positivas</h2><ul class="good">{good or '<li class="muted">Sin comprobaciones positivas.</li>'}</ul></section>

<section><h2>Metodología y limitaciones</h2>
<p>ROVSKA combina descubrimiento activo, fingerprinting, análisis de configuración y correlación con ATT&amp;CK, PTES, OSSTMM, OWASP y CWE. Las operaciones ofensivas son dry-run por defecto.</p>
<ul>{''.join(f'<li>{e(x)}</li>' for x in report.get('limitations', []))}</ul></section>

<section class="doc-control"><h2>Control del documento</h2>
<table><tbody>
<tr><th>Identificador</th><td class="mono">{e(report.get('scan_id'))}</td><th>Versión</th><td>1.0</td></tr>
<tr><th>Generado</th><td>{e(report.get('finished_at') or report.get('scanned_at'))}</td><th>Perfil</th><td>{e(report.get('profile'))}</td></tr>
<tr><th>Alcance</th><td>{e((report.get('scope') or {}).get('reason') or 'objetivo autorizado')}</td><th>Clasificación</th><td>Confidencial · uso interno y cliente autorizado</td></tr>
<tr><th>Metodología</th><td colspan="3">PTES · OSSTMM · OWASP Top 10 / WSTG · MITRE ATT&amp;CK · CWE / CVE</td></tr>
<tr><th>Generador</th><td colspan="3">ROVSKA 1.0.0 · informe reconstruido desde la base de datos y la evidencia registrada</td></tr>
</tbody></table></section>
</main>
<footer>ROVSKA · informe generado automáticamente · <button onclick="window.print()">Imprimir / PDF</button></footer>
</body></html>"""


def _cover_html(report: dict) -> str:
    counts = report.get("counts", {})
    risk = report.get("risk", {})
    scope = report.get("scope", {}) or {}
    return f"""<div class="cover">
  <div class="cover-band"></div>
  <div class="cover-brand">▚ ROVSKA</div>
  <div class="cover-kicker">Informe de auditoría de seguridad</div>
  <h1>{e(report.get('target'))}</h1>
  <p class="cover-sub">Evaluación de superficie de ataque, configuración y exposición</p>
  <div class="cover-risk {_sev_cls(risk.get('label'))}">
    <div class="cover-score">{risk.get('score', 0)}</div>
    <div><b>{e(risk.get('label', 'Sin datos'))}</b><span>riesgo global · escala 0–100</span></div>
  </div>
  <table class="cover-meta">
    <tr><th>Fecha del escaneo</th><td>{e(report.get('scanned_at'))}</td></tr>
    <tr><th>Perfil</th><td>{e(report.get('profile'))}</td></tr>
    <tr><th>Alcance</th><td>{e(scope.get('reason') or 'objetivo autorizado')}</td></tr>
    <tr><th>Hosts / puertos</th><td>{len(report.get('hosts', []))} hosts · {report.get('stats', {}).get('total_ports', 0)} puertos</td></tr>
    <tr><th>Hallazgos</th><td>{sum(counts.values())} · {counts.get('CRÍTICO', 0)} críticos · {counts.get('ALTO', 0)} altos</td></tr>
    <tr><th>Clasificación</th><td>Confidencial · uso interno y cliente autorizado</td></tr>
  </table>
  <div class="cover-foot">
    <span>Generado por ROVSKA · MITRE ATT&amp;CK · PTES · OSSTMM · OWASP · CWE</span>
    <span>Documento generado automáticamente a partir de evidencia verificable</span>
  </div>
</div>"""


def _exec_summary(report: dict) -> str:
    counts = report.get("counts", {})
    risk = report.get("risk", {})
    findings = sorted(
        report.get("findings", []),
        key=lambda f: (SEV_ORDER.index(f.get("severity", "INFO")) if f.get("severity") in SEV_ORDER else 9,
                       f.get("host", ""), f.get("title", "")),
    )
    top_rows = "".join(
        f"<tr><td><span class='badge {_sev_cls(f.get('severity'))}'>{e(f.get('severity'))}</span></td>"
        f"<td>{e(f.get('title'))}</td><td class='mono'>{e(f.get('host'))}</td>"
        f"<td>{e(', '.join(f.get('cwe', [])[:2]))}</td></tr>"
        for f in findings[:8]
    ) or "<tr><td colspan='4' class='muted'>Sin hallazgos.</td></tr>"
    good = report.get("good_checks", [])[:8]
    good_html = "".join(f"<li>{e(item)}</li>" for item in good) or "<li class='muted'>Sin comprobaciones positivas.</li>"
    total = sum(counts.values())
    return f"""<section class="exec">
  <h2>Resumen ejecutivo</h2>
  <p class="lead">Se auditaron <b>{len(report.get('hosts', []))} hosts</b> y
  <b>{report.get('stats', {}).get('total_ports', 0)} puertos</b> sobre el objetivo
  <b>{e(report.get('target'))}</b>. Se identificaron <b>{total} hallazgos</b>:
  {counts.get('CRÍTICO', 0)} críticos, {counts.get('ALTO', 0)} altos,
  {counts.get('MEDIO', 0)} medios, {counts.get('BAJO', 0)} bajos y
  {counts.get('INFO', 0)} informativos. El riesgo global calculado es
  <b>{risk.get('score', 0)}/100 ({e(risk.get('label', 'Sin datos'))})</b>.</p>
  <div class="exec-grid">
    <div class="exec-kpi"><span>Riesgo</span><b>{risk.get('score', 0)}</b><i>{e(risk.get('label', ''))}</i></div>
    <div class="exec-kpi crit"><span>Críticos</span><b>{counts.get('CRÍTICO', 0)}</b><i>prioridad inmediata</i></div>
    <div class="exec-kpi high"><span>Altos</span><b>{counts.get('ALTO', 0)}</b><i>prioridad alta</i></div>
    <div class="exec-kpi"><span>Hosts</span><b>{len(report.get('hosts', []))}</b><i>{report.get('stats', {}).get('total_ports', 0)} puertos</i></div>
  </div>
  <h3>Hallazgos prioritarios</h3>
  <table class="exec-table"><thead><tr><th>Severidad</th><th>Hallazgo</th><th>Host</th><th>CWE</th></tr></thead>
  <tbody>{top_rows}</tbody></table>
  <h3>Comprobaciones positivas</h3>
  <ul class="good">{good_html}</ul>
</section>"""


def _sev_cls(value) -> str:
    return {
        "CRÍTICO": "crit",
        "ALTO": "high",
        "MEDIO": "med",
        "BAJO": "low",
        "INFO": "info",
        "Crítico": "crit",
        "Muy alto": "high",
        "Alto": "high",
        "Medio": "med",
        "Bajo": "low",
    }.get(str(value), "info")


def _chips(label: str, values: list[str]) -> str:
    if not values:
        return ""
    return f"<div class='chips'><span>{e(label)}</span>{''.join(f'<i>{e(v)}</i>' for v in values)}</div>"


REPORT_CSS = """
:root{--bg:#0a0a0a;--panel:#141414;--panel2:#1e1e1e;--line:#3c3c3c;--text:#eee;--muted:#8a8a8a;
--primary:#fab283;--red:#e06c75;--orange:#f5a742;--yellow:#e5c07b;--cyan:#56b6c2;--blue:#5c9cf5;--green:#7fd88f}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--text);font:13px/1.55 ui-monospace,Menlo,Consolas,monospace}
.top{display:flex;justify-content:space-between;gap:20px;align-items:center;padding:22px 28px;border-bottom:1px solid var(--line);
background:radial-gradient(800px 300px at 10% 0,rgba(250,178,131,.08),transparent 70%),var(--panel)}
.brand{color:var(--primary);letter-spacing:.2em;font-weight:700}.top h1{margin:6px 0 2px;font-size:26px}.top p{margin:0;color:var(--muted);font-size:11px}
.risk{text-align:center;border:1px solid currentColor;border-radius:12px;padding:10px 18px}.risk .score{font-size:30px;font-weight:700}.risk.crit{color:var(--red)}.risk.high{color:var(--orange)}.risk.med{color:var(--yellow)}.risk.low{color:var(--cyan)}.risk.info{color:var(--blue)}
main{padding:22px 28px 60px;max-width:1180px;margin:0 auto}h2{font-size:11px;letter-spacing:.16em;text-transform:uppercase;color:var(--muted);border-bottom:1px solid var(--line);padding-bottom:7px;margin:30px 0 14px}
.sevs{display:grid;grid-template-columns:repeat(5,1fr);gap:9px}.sev{border:1px solid var(--line);border-radius:9px;padding:12px;background:var(--panel)}
.sev .n{font-size:24px;font-weight:700}.sev .l{font-size:9px;letter-spacing:.12em;color:var(--muted)}.sev.crit .n{color:var(--red)}.sev.high .n{color:var(--orange)}.sev.med .n{color:var(--yellow)}.sev.low .n{color:var(--cyan)}.sev.info .n{color:var(--blue)}
table{width:100%;border-collapse:collapse;margin:8px 0 16px;font-size:11px}th,td{text-align:left;padding:7px 9px;border-bottom:1px solid #2c2c2c;vertical-align:top}
th{color:var(--muted);font-size:9px;letter-spacing:.1em;text-transform:uppercase;background:var(--panel2)}.num{text-align:right}.mono{font-family:inherit}
.matrix th{width:150px}.tech{display:inline-flex;gap:5px;align-items:center;border:1px solid var(--line);border-radius:5px;padding:2px 6px;margin:2px;font-size:10px}
.tech i{font-style:normal;color:var(--muted)}.tech.crit{border-color:var(--red);color:var(--red)}.tech.high{border-color:var(--orange);color:var(--orange)}.tech.med{border-color:var(--yellow);color:var(--yellow)}.tech.low{border-color:var(--cyan);color:var(--cyan)}
.chain{display:grid;grid-template-columns:repeat(7,1fr);gap:7px}.stage{border:1px solid var(--line);border-radius:8px;padding:8px;background:var(--panel);min-height:80px}
.stage.done{border-color:rgba(250,178,131,.55)}.stname{font-size:10px;font-weight:700;margin-bottom:5px}.stname span{display:block;font-weight:400;color:var(--muted);font-size:8px;text-transform:uppercase}
.step{font-size:9px;color:var(--muted);margin:4px 0;border-top:1px dashed #333;padding-top:3px}.step b{color:var(--cyan)}.step em{color:var(--muted);font-style:normal}
.finding{border:1px solid var(--line);border-left:3px solid var(--muted);border-radius:8px;padding:11px 13px;margin:8px 0;background:var(--panel)}
.finding.crit{border-left-color:var(--red)}.finding.high{border-left-color:var(--orange)}.finding.med{border-left-color:var(--yellow)}.finding.low{border-left-color:var(--cyan)}
.fhead{display:flex;gap:8px;align-items:center;flex-wrap:wrap}.fhead b{font-size:12.5px}.fhost{margin-left:auto;color:var(--muted);font-size:10px}
.finding p{margin:6px 0;font-size:11px}.rec{color:var(--muted)}.badge{font-size:8px;font-weight:700;letter-spacing:.1em;border:1px solid currentColor;border-radius:4px;padding:2px 6px}
.badge.crit{color:var(--red)}.badge.high{color:var(--orange)}.badge.med{color:var(--yellow)}.badge.low{color:var(--cyan)}.badge.info{color:var(--blue)}
.chips{display:flex;gap:5px;flex-wrap:wrap;margin-top:6px;font-size:9px}.chips span{color:var(--muted);text-transform:uppercase;letter-spacing:.1em}.chips i{font-style:normal;color:var(--cyan);border:1px solid rgba(86,182,194,.35);border-radius:4px;padding:1px 5px}
.good{list-style:none;padding:0}.good li{padding:4px 0;color:var(--muted)}.good li::before{content:"✓ ";color:var(--green)}
.muted{color:var(--muted)}footer{position:fixed;bottom:0;left:0;right:0;padding:8px 20px;background:rgba(10,10,10,.9);border-top:1px solid var(--line);font-size:10px;color:var(--muted);display:flex;justify-content:space-between}
footer button{background:var(--panel2);border:1px solid var(--line);color:var(--text);border-radius:6px;padding:4px 9px;cursor:pointer}
@media(max-width:800px){.chain{grid-template-columns:1fr 1fr}.sevs{grid-template-columns:1fr 1fr}.top{flex-direction:column;align-items:flex-start}}
@media print{body{background:#fff;color:#111}footer{display:none}.top,.sev,.stage,.finding,table{background:#fff;border-color:#ccc}}
"""


# CSS específico del PDF. WeasyPrint aplica reglas de página (A4, cabeceras,
# pies y numeración) que el navegador ignora en pantalla.
PDF_CSS = """
@page {
  size: A4;
  margin: 20mm 16mm 18mm;
  @top-left {
    content: "ROVSKA · Informe de auditoría";
    font-family: "DejaVu Sans", sans-serif;
    font-size: 7.5pt;
    color: #64748b;
    letter-spacing: .06em;
  }
  @top-right {
    content: "Confidencial";
    font-family: "DejaVu Sans", sans-serif;
    font-size: 7.5pt;
    color: #b45309;
    letter-spacing: .08em;
  }
  @bottom-left {
    content: "Documento generado automáticamente · ROVSKA";
    font-family: "DejaVu Sans", sans-serif;
    font-size: 7pt;
    color: #94a3b8;
  }
  @bottom-right {
    content: "Página " counter(page) " de " counter(pages);
    font-family: "DejaVu Sans", sans-serif;
    font-size: 7.5pt;
    color: #64748b;
  }
}
@page cover {
  margin: 0;
  @top-left { content: none; }
  @top-right { content: none; }
  @bottom-left { content: none; }
  @bottom-right { content: none; }
}
body.pdf {
  background: #ffffff;
  color: #0f172a;
  font: 10.2pt/1.48 "DejaVu Sans", "Liberation Sans", sans-serif;
}
body.pdf .top { display: none; }
body.pdf main { max-width: none; margin: 0; padding: 0; }
body.pdf section { margin: 0 0 8mm; break-inside: auto; }
body.pdf section.pb { break-before: page; }
body.pdf h2 {
  color: #0f172a;
  font-size: 13pt;
  letter-spacing: .08em;
  text-transform: uppercase;
  border-bottom: 1.2px solid #cbd5e1;
  padding-bottom: 2mm;
  margin: 0 0 4mm;
  break-after: avoid;
}
body.pdf h3 {
  color: #334155;
  font-size: 10.5pt;
  margin: 6mm 0 2.5mm;
  break-after: avoid;
}
body.pdf p { margin: 0 0 3mm; }
body.pdf .muted { color: #64748b; }
body.pdf table {
  width: 100%;
  border-collapse: collapse;
  margin: 2mm 0 5mm;
  font-size: 8.4pt;
  background: transparent;
}
body.pdf th, body.pdf td {
  text-align: left;
  padding: 2mm 2.4mm;
  border-bottom: .6px solid #dbe3ee;
  vertical-align: top;
}
body.pdf th {
  background: #eef2f7;
  color: #334155;
  font-size: 7.2pt;
  letter-spacing: .06em;
  text-transform: uppercase;
}
body.pdf thead { display: table-header-group; }
body.pdf tr { break-inside: avoid; }
body.pdf .sevs { display: grid; grid-template-columns: repeat(5, 1fr); gap: 2.5mm; }
body.pdf .sev {
  background: #f8fafc;
  border: 1px solid #dbe3ee;
  border-radius: 2mm;
  padding: 3mm;
  text-align: center;
}
body.pdf .sev .n { font-size: 18pt; font-weight: 700; line-height: 1.1; }
body.pdf .sev .l { color: #64748b; font-size: 6.8pt; letter-spacing: .08em; }
body.pdf .sev.crit .n { color: #b91c1c; }
body.pdf .sev.high .n { color: #c2410c; }
body.pdf .sev.med .n { color: #a16207; }
body.pdf .sev.low .n { color: #0e7490; }
body.pdf .sev.info .n { color: #1d4ed8; }
body.pdf .matrix th { width: 34mm; }
body.pdf .tech {
  display: inline-block;
  border: .6px solid #cbd5e1;
  border-radius: 1mm;
  padding: .5mm 1.4mm;
  margin: .5mm;
  font-size: 7.2pt;
  color: #334155;
}
body.pdf .tech i { font-style: normal; color: #64748b; margin-left: 1mm; }
body.pdf .chain { display: grid; grid-template-columns: repeat(4, 1fr); gap: 2mm; }
body.pdf .stage {
  background: #f8fafc;
  border: 1px solid #dbe3ee;
  border-radius: 1.5mm;
  padding: 2mm;
  min-height: 18mm;
}
body.pdf .stage.done { border-color: #f59e0b; background: #fffbeb; }
body.pdf .stname { font-size: 7.6pt; font-weight: 700; }
body.pdf .stname span { display: block; color: #64748b; font-size: 6.2pt; text-transform: uppercase; }
body.pdf .step { font-size: 6.8pt; color: #475569; border-top: .5px dashed #cbd5e1; padding-top: 1mm; margin-top: 1mm; }
body.pdf .step b { color: #0e7490; }
body.pdf .step em { font-style: normal; color: #94a3b8; }
body.pdf .finding {
  background: #ffffff;
  border: .7px solid #dbe3ee;
  border-left: 3px solid #64748b;
  border-radius: 1.5mm;
  padding: 3mm 3.5mm;
  margin: 0 0 3mm;
  break-inside: avoid;
}
body.pdf .finding.crit { border-left-color: #b91c1c; }
body.pdf .finding.high { border-left-color: #c2410c; }
body.pdf .finding.med { border-left-color: #a16207; }
body.pdf .finding.low { border-left-color: #0e7490; }
body.pdf .finding.info { border-left-color: #1d4ed8; }
body.pdf .fhead b { font-size: 9.4pt; color: #0f172a; }
body.pdf .fhost { color: #64748b; font-size: 7.6pt; }
body.pdf .finding p { font-size: 8.4pt; margin: 1.5mm 0; }
body.pdf .rec { color: #475569; }
body.pdf .badge {
  font-size: 6.6pt;
  font-weight: 700;
  border: .7px solid currentColor;
  border-radius: 1mm;
  padding: .4mm 1.4mm;
}
body.pdf .badge.crit { color: #b91c1c; }
body.pdf .badge.high { color: #c2410c; }
body.pdf .badge.med { color: #a16207; }
body.pdf .badge.low { color: #0e7490; }
body.pdf .badge.info { color: #1d4ed8; }
body.pdf .chips { margin-top: 1.5mm; gap: 1mm; font-size: 6.8pt; }
body.pdf .chips i { color: #0e7490; border: .5px solid #bae6fd; border-radius: 1mm; padding: .3mm 1mm; }
body.pdf .good { list-style: none; padding: 0; margin: 0; }
body.pdf .good li { color: #334155; font-size: 8.8pt; padding: 1mm 0 1mm 5mm; position: relative; }
body.pdf .good li::before { content: "✓"; color: #15803d; position: absolute; left: 0; font-weight: 700; }
body.pdf footer { display: none; }
body.pdf .exec { padding-top: 2mm; }
body.pdf .exec .lead {
  font-size: 10pt;
  line-height: 1.6;
  color: #1e293b;
  border-left: 3px solid #f59e0b;
  background: #f8fafc;
  padding: 4mm 5mm;
  margin: 0 0 5mm;
}
body.pdf .exec-grid { display: grid; grid-template-columns: repeat(4, 1fr); gap: 3mm; margin: 0 0 5mm; }
body.pdf .exec-kpi {
  background: #f8fafc;
  border: 1px solid #dbe3ee;
  border-radius: 2mm;
  padding: 3mm;
}
body.pdf .exec-kpi span { display: block; color: #64748b; font-size: 7pt; text-transform: uppercase; letter-spacing: .08em; }
body.pdf .exec-kpi b { display: block; font-size: 18pt; line-height: 1.2; color: #0f172a; }
body.pdf .exec-kpi i { display: block; color: #64748b; font-size: 7pt; font-style: normal; }
body.pdf .exec-kpi.crit b { color: #b91c1c; }
body.pdf .exec-kpi.high b { color: #c2410c; }
body.pdf .exec-table td { font-size: 8.4pt; }
body.pdf .doc-control { margin-top: 10mm; }
body.pdf .doc-control th { width: 32mm; }
body.pdf .doc-control td { font-size: 8.2pt; }

/* Portada */
body.pdf .cover {
  page: cover;
  width: 210mm;
  height: 297mm;
  box-sizing: border-box;
  background: #0b1220;
  color: #f8fafc;
  position: relative;
  overflow: hidden;
  break-after: page;
}
body.pdf .cover-band {
  position: absolute;
  top: 0; left: 0; right: 0;
  height: 9mm;
  background: #f59e0b;
}
body.pdf .cover-brand {
  margin: 34mm 22mm 0;
  color: #fbbf24;
  font-size: 13pt;
  font-weight: 700;
  letter-spacing: .28em;
}
body.pdf .cover-kicker {
  margin: 20mm 22mm 0;
  color: #94a3b8;
  font-size: 9pt;
  letter-spacing: .14em;
  text-transform: uppercase;
}
body.pdf .cover h1 {
  margin: 4mm 22mm 0;
  font-size: 31pt;
  line-height: 1.12;
  max-width: 165mm;
  color: #ffffff;
  letter-spacing: -.01em;
}
body.pdf .cover-sub {
  margin: 5mm 22mm 0;
  color: #cbd5e1;
  font-size: 11pt;
  max-width: 150mm;
}
body.pdf .cover-risk {
  margin: 14mm 22mm 0;
  padding: 5mm 6mm;
  border: 1px solid #334155;
  border-left: 4px solid #f59e0b;
  border-radius: 2mm;
  background: #111c30;
  display: flex;
  align-items: center;
  gap: 6mm;
}
body.pdf .cover-score { font-size: 34pt; font-weight: 700; line-height: 1; color: #fbbf24; }
body.pdf .cover-risk b { display: block; font-size: 13pt; color: #ffffff; }
body.pdf .cover-risk span { display: block; color: #94a3b8; font-size: 8pt; margin-top: 1mm; }
body.pdf .cover-risk.crit .cover-score { color: #f87171; }
body.pdf .cover-risk.high .cover-score { color: #fb923c; }
body.pdf .cover-risk.med .cover-score { color: #facc15; }
body.pdf .cover-risk.low .cover-score { color: #22d3ee; }
body.pdf .cover-meta {
  margin: 12mm 22mm 0;
  width: 166mm;
  border-top: 1px solid #334155;
  border-bottom: 1px solid #334155;
  background: transparent !important;
}
body.pdf .cover-meta tr {
  background: transparent !important;
}
body.pdf .cover-meta th,
body.pdf .cover-meta td {
  border-bottom: 1px solid #1e293b;
  color: #e2e8f0 !important;
  padding: 2.4mm 0;
  font-size: 8.4pt;
  background: transparent !important;
}
body.pdf .cover-meta th {
  background: transparent !important;
  color: #94a3b8 !important;
  width: 42mm;
  font-size: 7.2pt;
  letter-spacing: .06em;
}
body.pdf .cover-foot {
  position: absolute;
  left: 22mm;
  right: 22mm;
  bottom: 18mm;
  display: flex;
  justify-content: space-between;
  gap: 8mm;
  color: #64748b;
  font-size: 6.8pt;
  border-top: 1px solid #1e293b;
  padding-top: 3mm;
}
"""
