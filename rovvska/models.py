#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Modelos internos de ROVSKA (dataclasses sin dependencias)."""

from __future__ import annotations

from dataclasses import dataclass, field, asdict
from typing import Any


SEV_ORDER = ["CRÍTICO", "ALTO", "MEDIO", "BAJO", "INFO"]
SEV_WEIGHT = {"CRÍTICO": 30, "ALTO": 15, "MEDIO": 6, "BAJO": 2, "INFO": 0}
SEV_CLASS = {"CRÍTICO": "crit", "ALTO": "high", "MEDIO": "med", "BAJO": "low", "INFO": "info"}

SEV_ALIASES = {
    "CRITICAL": "CRÍTICO",
    "CRIT": "CRÍTICO",
    "CRÍTICO": "CRÍTICO",
    "CRITICO": "CRÍTICO",
    "HIGH": "ALTO",
    "ALTO": "ALTO",
    "MEDIUM": "MEDIO",
    "MED": "MEDIO",
    "MEDIO": "MEDIO",
    "LOW": "BAJO",
    "BAJO": "BAJO",
    "INFO": "INFO",
    "INFORMATIONAL": "INFO",
    "UNKNOWN": "INFO",
}


def normalize_severity(value: str | None, default: str = "INFO") -> str:
    return SEV_ALIASES.get(str(value or "").strip().upper(), default)


def severity_weight(value: str) -> int:
    return SEV_WEIGHT.get(normalize_severity(value), 0)


def risk_meta(score: int, counts: dict[str, int], total: int) -> dict:
    crit = counts.get("CRÍTICO", 0)
    if total == 0:
        label, cls = "Sin hallazgos", "ok"
    elif score >= 70 and crit > 0:
        label, cls = "Crítico", "crit"
    elif score >= 70:
        label, cls = "Muy alto", "high"
    elif crit > 0 or score >= 40:
        label, cls = "Alto", "high"
    elif score >= 20:
        label, cls = "Medio", "med"
    elif score > 0:
        label, cls = "Bajo", "low"
    else:
        label, cls = "Informativo", "info"
    return {"score": min(100, score), "label": label, "cls": cls}


@dataclass
class Port:
    port: int
    proto: str = "tcp"
    state: str = "open"
    service: str = ""
    product: str = ""
    version: str = ""
    extrainfo: str = ""
    scripts: dict[str, str] = field(default_factory=dict)

    @property
    def label(self) -> str:
        return f"{self.port}/{self.proto}"

    @property
    def service_str(self) -> str:
        return " ".join(p for p in (self.product, self.version, self.extrainfo) if p).strip()

    def to_dict(self) -> dict:
        return {
            "port": self.port,
            "proto": self.proto,
            "state": self.state,
            "name": self.service,
            "product": self.product,
            "version": self.version,
            "extrainfo": self.extrainfo,
            "service_str": self.service_str or self.service,
            "scripts": dict(self.scripts),
        }


@dataclass
class Host:
    ip: str
    mac: str = ""
    vendor: str = ""
    hostnames: list[str] = field(default_factory=list)
    os: str = ""
    type: str = ""
    ports: list[Port] = field(default_factory=list)
    hostscripts: dict[str, str] = field(default_factory=dict)
    extra: dict[str, Any] = field(default_factory=dict)

    def add_port(self, port: Port) -> None:
        key = (port.port, port.proto)
        for existing in self.ports:
            if (existing.port, existing.proto) == key:
                # fusiona sin perder datos de otro escáner
                existing.state = port.state or existing.state
                existing.service = port.service or existing.service
                existing.product = port.product or existing.product
                existing.version = port.version or existing.version
                existing.extrainfo = port.extrainfo or existing.extrainfo
                existing.scripts.update(port.scripts or {})
                return
        self.ports.append(port)

    def to_dict(self) -> dict:
        return {
            "ip": self.ip,
            "mac": self.mac,
            "vendor": self.vendor,
            "hostnames": list(self.hostnames),
            "os": self.os,
            "type": self.type,
            "ports": [p.to_dict() for p in sorted(self.ports, key=lambda x: x.port)],
            "hostscripts": dict(self.hostscripts),
            "extra": dict(self.extra),
        }


@dataclass
class Finding:
    severity: str
    title: str
    host: str = ""
    evidence: str = ""
    recommendation: str = ""
    cves: list[str] = field(default_factory=list)
    cwe: list[str] = field(default_factory=list)
    attack: list[str] = field(default_factory=list)
    frameworks: dict[str, Any] = field(default_factory=dict)
    source: str = "heuristic"
    confidence: str = "media"
    tags: list[str] = field(default_factory=list)

    def __post_init__(self) -> None:
        self.severity = normalize_severity(self.severity)
        self.cves = _unique(self.cves)
        self.cwe = _unique(self.cwe)
        self.attack = _unique(self.attack)
        self.tags = _unique(self.tags)

    @property
    def dedup_key(self) -> tuple[str, str]:
        return (self.host, self.title.strip().lower())

    def to_dict(self) -> dict:
        data = asdict(self)
        data["cves"] = list(self.cves)
        data["cwe"] = list(self.cwe)
        data["attack"] = list(self.attack)
        data["frameworks"] = dict(self.frameworks)
        data["tags"] = list(self.tags)
        return data


@dataclass
class ToolResult:
    tool: str
    ok: bool = True
    skipped: bool = False
    error: str = ""
    hosts: list[Host] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    good: list[str] = field(default_factory=list)
    raw: list[str] = field(default_factory=list)
    meta: dict[str, Any] = field(default_factory=dict)
    command: list[str] = field(default_factory=list)
    duration: float = 0.0
    output: str = ""

    def to_dict(self) -> dict:
        return {
            "tool": self.tool,
            "ok": self.ok,
            "skipped": self.skipped,
            "error": self.error,
            "hosts": [h.to_dict() for h in self.hosts],
            "findings": [f.to_dict() for f in self.findings],
            "good": list(self.good),
            "raw": list(self.raw),
            "meta": dict(self.meta),
            "command": list(self.command),
            "duration": self.duration,
        }


def _unique(values: list[str] | None) -> list[str]:
    seen: set[str] = set()
    out: list[str] = []
    for value in values or []:
        text = str(value).strip()
        if text and text not in seen:
            seen.add(text)
            out.append(text)
    return out


def merge_findings(findings: list[Finding]) -> list[Finding]:
    """Elimina duplicados por host+título conservando la severidad más alta."""
    best: dict[tuple[str, str], Finding] = {}
    for finding in findings:
        key = finding.dedup_key
        current = best.get(key)
        if current is None:
            best[key] = finding
            continue
        if severity_weight(finding.severity) > severity_weight(current.severity):
            finding.cves = _unique(finding.cves + current.cves)
            finding.cwe = _unique(finding.cwe + current.cwe)
            finding.attack = _unique(finding.attack + current.attack)
            finding.tags = _unique(finding.tags + current.tags)
            best[key] = finding
        else:
            current.cves = _unique(current.cves + finding.cves)
            current.cwe = _unique(current.cwe + finding.cwe)
            current.attack = _unique(current.attack + finding.attack)
            current.tags = _unique(current.tags + finding.tags)
    order = {sev: i for i, sev in enumerate(SEV_ORDER)}
    return sorted(
        best.values(),
        key=lambda f: (order.get(f.severity, 9), f.host, f.title),
    )


def counts_by_severity(findings: list[Finding]) -> dict[str, int]:
    return {sev: sum(1 for f in findings if f.severity == sev) for sev in SEV_ORDER}
