#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Importación de informes JSON/XML externos al modelo interno de ROVSKA.

Convierte informes de ROVSKA, AUDITORIA_PLUS o de terceros (claves habituales
como ``vulnerabilities``, ``issues``, ``assets``…) en un escaneo normal. Así el
panel, la comparativa y la exportación funcionan igual que con un escaneo real.
"""

from __future__ import annotations

import json
import re
import xml.etree.ElementTree as ET
from pathlib import Path

from . import analyzer, attack, db, frameworks, report, scanner
from .config import SETTINGS
from .models import (
    Finding,
    Host,
    Port,
    SEV_WEIGHT,
    counts_by_severity,
    merge_findings,
    normalize_severity,
    risk_meta,
)

MAX_HOSTS = 2048
MAX_FINDINGS = 5000
MAX_PORTS_PER_HOST = 65535


def _text(value) -> str:
    if value is None:
        return ""
    if isinstance(value, (dict, list)):
        return json.dumps(value, ensure_ascii=False)
    return str(value).strip()


def _first(data: dict, *keys, default=""):
    for key in keys:
        if key in data and data[key] not in (None, ""):
            return data[key]
    return default


def _strings(value) -> list[str]:
    if value in (None, ""):
        return []
    if isinstance(value, str):
        parts = re.split(r"[,;\s]+", value)
        return [part.strip() for part in parts if part.strip()]
    if isinstance(value, (list, tuple, set)):
        out: list[str] = []
        for item in value:
            out.extend(_strings(item))
        return out
    return [str(value)]


def _cve_list(value) -> list[str]:
    return [item.upper() for item in _strings(value) if re.match(r"^CVE-\d{4}-\d{4,}$", item, re.I)]


def _cwe_list(value) -> list[str]:
    out = []
    for item in _strings(value):
        match = re.search(r"CWE[-_ ]?(\d+)", item, re.I)
        if match:
            out.append(f"CWE-{match.group(1)}")
        elif item.isdigit():
            out.append(f"CWE-{item}")
    return out


def _attack_list(value) -> list[str]:
    out = []
    for item in _strings(value):
        match = re.search(r"T\d{4}(?:\.\d{3})?", item, re.I)
        if match:
            out.append(match.group(0).upper())
    return out


def _int(value, default=0) -> int:
    try:
        return int(str(value).strip())
    except (TypeError, ValueError):
        return default


def _port_from_json(value, key=None) -> Port | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, (int, float)):
        number = int(value)
        return Port(port=number) if 0 < number <= 65535 else None
    if isinstance(value, str):
        if value.isdigit():
            number = int(value)
            return Port(port=number) if 0 < number <= 65535 else None
        return None
    if not isinstance(value, dict):
        return None
    number = _int(_first(value, "port", "number", "id", "port_number", default=key), 0)
    if not 0 < number <= 65535:
        return None
    return Port(
        port=number,
        proto=_text(_first(value, "proto", "protocol", "transport", default="tcp")).lower() or "tcp",
        state=_text(_first(value, "state", "status", default="open")).lower() or "open",
        service=_text(_first(value, "name", "service", "service_name", "app", default="")),
        product=_text(_first(value, "product", "product_name", "banner", default="")),
        version=_text(_first(value, "version", "product_version", default="")),
        extrainfo=_text(_first(value, "extrainfo", "info", "extra", default="")),
        scripts=value.get("scripts") if isinstance(value.get("scripts"), dict) else {},
    )


def _host_from_json(raw: dict, fallback_ip: str = "") -> Host | None:
    if not isinstance(raw, dict):
        return None
    ip = _text(_first(raw, "ip", "address", "ip_address", "host", "target", default=fallback_ip))
    if not ip:
        return None
    hostnames = _strings(_first(raw, "hostnames", "hostname", "dns", "names", "fqdn", default=[]))
    host = Host(
        ip=ip[:120],
        mac=_text(_first(raw, "mac", "mac_address", default="")),
        vendor=_text(_first(raw, "vendor", "manufacturer", "oui", default=""))[:160],
        hostnames=[name[:255] for name in hostnames],
        os=_text(_first(raw, "os", "operating_system", "platform", default=""))[:160],
        type=_text(_first(raw, "type", "device_type", "category", default=""))[:80],
        hostscripts=raw.get("hostscripts") if isinstance(raw.get("hostscripts"), dict) else {},
    )
    raw_ports = _first(raw, "ports", "services", "open_ports", "port_list", default=[])
    if isinstance(raw_ports, dict):
        for key, value in raw_ports.items():
            port = _port_from_json(value, key)
            if port:
                host.add_port(port)
    elif isinstance(raw_ports, list):
        for value in raw_ports[:MAX_PORTS_PER_HOST]:
            port = _port_from_json(value)
            if port:
                host.add_port(port)
    return host


def _finding_from_json(raw: dict, fallback_host: str = "") -> Finding | None:
    if not isinstance(raw, dict):
        return None
    title = _text(
        _first(raw, "title", "name", "vulnerability", "issue", "alert", "summary", default="")
    )
    if not title:
        return None
    host = _text(_first(raw, "host", "ip", "ip_address", "target", "asset", default=fallback_host))
    frameworks_data = raw.get("frameworks") if isinstance(raw.get("frameworks"), dict) else {}
    return Finding(
        severity=normalize_severity(
            _first(raw, "severity", "risk", "level", "criticality", default="INFO"), "INFO"
        ),
        title=title[:300],
        host=host[:120],
        evidence=_text(_first(raw, "evidence", "description", "details", "output", "proof", default=""))[:12000],
        recommendation=_text(
            _first(raw, "recommendation", "remediation", "solution", "fix", "advice", default="")
        )[:4000],
        cves=_cve_list(_first(raw, "cves", "cve", "cve_ids", default=[])),
        cwe=_cwe_list(_first(raw, "cwe", "cwes", "cwe_id", default=[])),
        attack=_attack_list(_first(raw, "attack", "mitre", "techniques", "ttp", default=[])),
        frameworks=frameworks_data,
        source=_text(_first(raw, "source", "scanner", "tool", "engine", default="import"))[:80] or "import",
        confidence=_text(_first(raw, "confidence", "certainty", default="media"))[:40] or "media",
        tags=_strings(_first(raw, "tags", "labels", "categories", default=[])),
    )


def _normalize_json(data) -> dict:
    if isinstance(data, list):
        data = {"findings": data}
    if not isinstance(data, dict):
        raise ValueError("el JSON debe ser un objeto o una lista de hallazgos")
    nested = data.get("report")
    if isinstance(nested, dict) and not _first(data, "target", "hosts", "findings"):
        data = nested

    target = _text(
        _first(data, "target", "scope", "asset", "host", "ip", default="importado")
    )[:160] or "importado"
    hosts = []
    raw_hosts = _first(data, "hosts", "assets", "machines", "devices", default=[])
    if isinstance(raw_hosts, dict):
        converted = []
        for key, value in raw_hosts.items():
            item = dict(value) if isinstance(value, dict) else {"ip": value}
            item.setdefault("ip", key)
            converted.append(item)
        raw_hosts = converted
    if isinstance(raw_hosts, list):
        for raw in raw_hosts[:MAX_HOSTS]:
            host = _host_from_json(raw if isinstance(raw, dict) else {"ip": raw})
            if host:
                hosts.append(host)

    findings = []
    raw_findings = _first(
        data, "findings", "vulnerabilities", "issues", "alerts", "results", default=[]
    )
    if isinstance(raw_findings, dict):
        raw_findings = list(raw_findings.values())
    if isinstance(raw_findings, list):
        for raw in raw_findings[:MAX_FINDINGS]:
            finding = _finding_from_json(raw if isinstance(raw, dict) else {"title": raw})
            if finding:
                findings.append(finding)

    good = _strings(_first(data, "good_checks", "good", "passes", "positive_checks", default=[]))
    return {
        "target": target,
        "scanned_at": _text(_first(data, "scanned_at", "started_at", "date", "timestamp", default="")),
        "finished_at": _text(_first(data, "finished_at", "end_time", default="")),
        "profile": _text(_first(data, "profile", "mode", default="import")) or "import",
        "mode": _text(_first(data, "mode", "profile", default="import")) or "import",
        "hosts": hosts,
        "findings": findings,
        "good_checks": good,
        "source_format": "json",
    }


def _lower_attrs(element: ET.Element) -> dict:
    return {str(key).lower(): value for key, value in element.attrib.items()}


def _child_text(element: ET.Element, *names: str) -> str:
    wanted = {name.lower() for name in names}
    for child in list(element):
        if child.tag.lower() in wanted and (child.text or "").strip():
            return (child.text or "").strip()
    return ""


def _descendants(element: ET.Element, *names: str) -> list[ET.Element]:
    wanted = {name.lower() for name in names}
    return [child for child in element.iter() if child.tag.lower() in wanted]


def _normalize_xml(content: str) -> dict:
    try:
        root = ET.fromstring(content)
    except ET.ParseError as exc:
        raise ValueError(f"XML no válido: {exc}") from exc

    attrs = _lower_attrs(root)
    target = (
        attrs.get("target")
        or _child_text(root, "target", "scope", "asset")
        or "importado"
    )[:160]
    scanned_at = attrs.get("scanned-at") or attrs.get("scanned_at") or _child_text(root, "scanned-at", "scanned_at", "date")
    profile = attrs.get("profile") or "import"

    host_containers = [el for el in root.iter() if el.tag.lower() in {"hosts", "assets", "machines"}]
    host_elements: list[ET.Element] = []
    if host_containers:
        for container in host_containers:
            host_elements.extend(
                [child for child in list(container) if child.tag.lower() in {"host", "asset", "machine"}]
            )
    else:
        host_elements = [el for el in root.iter() if el.tag.lower() in {"host", "asset", "machine"}]

    hosts: list[Host] = []
    for element in host_elements[:MAX_HOSTS]:
        attrs = _lower_attrs(element)
        ip = attrs.get("ip") or attrs.get("address") or attrs.get("ip-address") or attrs.get("hostname")
        if not ip:
            continue
        host = Host(
            ip=ip[:120],
            mac=attrs.get("mac", ""),
            vendor=attrs.get("vendor", "")[:160],
            os=(attrs.get("os") or _child_text(element, "os", "operating-system"))[:160],
            type=(attrs.get("type") or _child_text(element, "type"))[:80],
        )
        for port_el in _descendants(element, "port"):
            p = _lower_attrs(port_el)
            number = _int(p.get("number") or p.get("port") or p.get("id"), 0)
            if not 0 < number <= 65535:
                continue
            host.add_port(
                Port(
                    port=number,
                    proto=(p.get("proto") or p.get("protocol") or "tcp").lower(),
                    state=(p.get("state") or "open").lower(),
                    service=p.get("service") or p.get("name") or "",
                    product=p.get("product", ""),
                    version=p.get("version", ""),
                )
            )
        for name_el in _descendants(element, "hostname", "dns"):
            name = (name_el.text or "").strip() or _lower_attrs(name_el).get("name", "")
            if name:
                host.hostnames.append(name[:255])
        hosts.append(host)

    finding_containers = [
        el for el in root.iter() if el.tag.lower() in {"findings", "issues", "vulnerabilities", "alerts"}
    ]
    finding_elements: list[ET.Element] = []
    if finding_containers:
        for container in finding_containers:
            finding_elements.extend(
                [
                    child
                    for child in list(container)
                    if child.tag.lower() in {"finding", "issue", "vulnerability", "alert"}
                ]
            )
    else:
        finding_elements = _descendants(root, "finding", "issue", "vulnerability", "alert")

    findings: list[Finding] = []
    for element in finding_elements[:MAX_FINDINGS]:
        attrs = _lower_attrs(element)
        title = (
            attrs.get("title")
            or attrs.get("name")
            or _child_text(element, "title", "name", "summary")
        )
        if not title:
            continue
        cves = [
            (child.text or "").strip()
            for child in list(element)
            if child.tag.lower() in {"cve", "cve-id"}
        ] or [attrs.get("cve", "")]
        cwes = [
            (child.text or "").strip()
            for child in list(element)
            if child.tag.lower() in {"cwe", "cwe-id"}
        ] or [attrs.get("cwe", "")]
        techniques = [
            (child.text or "").strip()
            for child in list(element)
            if child.tag.lower() in {"attack-technique", "technique", "mitre"}
        ] or [attrs.get("attack", "")]
        findings.append(
            Finding(
                severity=normalize_severity(attrs.get("severity") or attrs.get("risk") or "INFO", "INFO"),
                title=title[:300],
                host=(attrs.get("host") or attrs.get("ip") or _child_text(element, "host", "ip"))[:120],
                evidence=_child_text(element, "evidence", "description", "details", "output")[:12000],
                recommendation=_child_text(element, "recommendation", "remediation", "solution")[:4000],
                cves=_cve_list(cves),
                cwe=_cwe_list(cwes),
                attack=_attack_list(techniques),
                source=(attrs.get("source") or "import")[:80],
                confidence=(attrs.get("confidence") or "media")[:40],
            )
        )

    good = [
        (element.text or "").strip()
        for element in root.iter()
        if element.tag.lower() in {"check", "good-check", "positive"}
        and (element.text or "").strip()
    ]
    return {
        "target": target,
        "scanned_at": scanned_at,
        "finished_at": "",
        "profile": profile,
        "mode": profile,
        "hosts": hosts,
        "findings": findings,
        "good_checks": good,
        "source_format": "xml",
    }


def parse_text(content: str, filename: str = "", fmt: str = "") -> dict:
    """Convierte el texto de un informe en el modelo normalizado de ROVSKA."""
    content = (content or "").strip()
    if not content:
        raise ValueError("el informe está vacío")
    suffix = Path(filename).suffix.lower().lstrip(".")
    fmt = (fmt or suffix or "").lower()
    if fmt not in {"json", "xml"}:
        fmt = "xml" if content.startswith("<") else "json"
    if fmt == "json":
        try:
            data = json.loads(content)
        except json.JSONDecodeError as exc:
            raise ValueError(f"JSON no válido: {exc}") from exc
        return _normalize_json(data)
    return _normalize_xml(content)


def import_text(
    content: str,
    filename: str = "",
    fmt: str = "",
    include_pdf: bool = True,
    runner=None,
) -> dict:
    """Importa un informe y lo persiste como un escaneo más.

    Devuelve un resumen con ``scan_id``, recuentos y rutas de los informes
    regenerados. Lanza ``ValueError`` si el contenido no es válido.
    """
    parsed = parse_text(content, filename=filename, fmt=fmt)
    hosts: dict[str, Host] = {}
    for host in parsed["hosts"]:
        if host.ip in hosts:
            for port in host.ports:
                hosts[host.ip].add_port(port)
        else:
            hosts[host.ip] = host

    findings = list(parsed["findings"])
    # Si el informe solo trae hallazgos, se sintetiza el host para que el panel
    # y la comparativa tengan una entidad a la que asociarlos.
    for finding in findings:
        if finding.host and finding.host not in hosts:
            hosts[finding.host] = Host(ip=finding.host[:120])

    findings = merge_findings(findings)
    for finding in findings:
        frameworks.enrich(finding)
        if not finding.attack:
            finding.attack = attack.techniques_for_finding(finding)

    for host in hosts.values():
        if not host.type:
            analyzer.classify_host(host)
        host_findings = [finding for finding in findings if finding.host == host.ip]
        host_counts = counts_by_severity(host_findings)
        score = min(100, sum(SEV_WEIGHT.get(finding.severity, 0) for finding in host_findings))
        host.extra["risk"] = score
        host.extra["risk_meta"] = risk_meta(score, host_counts, len(host_findings))
        host.extra["severity_counts"] = host_counts

    scan_id = db.new_id("scan")
    now = db.utc_now()
    started_at = parsed["scanned_at"] or now
    target = parsed["target"] or "importado"
    source_file = _save_original(content, filename, parsed["source_format"])

    db.execute(
        "INSERT INTO scans (id, target, profile, mode, status, started_at, finished_at, "
        "options_json, stats_json, created_by) VALUES (?,?,?,?,?,?,?,?,?,?)",
        (
            scan_id,
            target,
            "import",
            parsed["mode"] or "import",
            "done",
            started_at,
            now,
            "{}",
            "{}",
            "import",
        ),
    )
    scanner._persist_results(scan_id, list(hosts.values()), findings, parsed["good_checks"])

    counts = counts_by_severity(findings)
    total_ports = sum(len(host.ports) for host in hosts.values())
    services = {port.service for host in hosts.values() for port in host.ports if port.service}
    score = min(100, sum(SEV_WEIGHT.get(finding.severity, 0) for finding in findings))
    risk = risk_meta(score, counts, len(findings))
    stats = {
        "counts": counts,
        "risk": risk,
        "imported": True,
        "source_file": str(source_file),
        "source_format": parsed["source_format"],
        "scope": {"allowed": True, "reason": "informe importado"},
        "total_hosts": len(hosts),
        "total_ports": total_ports,
        "unique_services": len(services),
        "finished_at": now,
    }
    db.execute(
        "UPDATE scans SET stats_json=? WHERE id=?",
        (db.json_dumps(stats), scan_id),
    )
    paths = report.write_reports(scan_id, include_pdf=include_pdf, runner=runner)
    stats["reports"] = paths
    db.execute(
        "UPDATE scans SET stats_json=? WHERE id=?",
        (db.json_dumps(stats), scan_id),
    )
    return {
        "ok": True,
        "scan_id": scan_id,
        "target": target,
        "format": parsed["source_format"],
        "source_file": str(source_file),
        "hosts": len(hosts),
        "ports": total_ports,
        "findings": len(findings),
        "counts": counts,
        "risk": risk,
        "reports": paths,
    }


def _save_original(content: str, filename: str, fmt: str) -> Path:
    directory = SETTINGS.reports_dir / "imports"
    directory.mkdir(parents=True, exist_ok=True)
    safe = report.safe_name(Path(filename or f"informe.{fmt}").name)[:80]
    stamp = re.sub(r"[^0-9]", "", db.utc_now())[:14]
    path = directory / f"{stamp}_{safe}"
    path.write_text(content, encoding="utf-8")
    return path
