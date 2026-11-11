#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Nikto: comprobaciones web clásicas."""

from __future__ import annotations

import re
from urllib.parse import urlparse

from ..models import normalize_severity
from .base import Tool, ToolContext, ToolResult, ToolSpec, finding, http_urls, read_json


CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)


class NiktoTool(Tool):
    spec = ToolSpec(
        name="nikto",
        binary="nikto",
        category="web",
        description="Escaneo web de configuraciones, ficheros y vulnerabilidades conocidas.",
        phase="vuln",
        profiles=("web", "deep", "attack"),
        attack=("T1595.002", "T1190"),
    )

    def run(self, ctx: ToolContext) -> ToolResult:
        if not self.available(ctx.runner):
            return self.missing(ctx)
        result = ToolResult(tool=self.name)
        for host in ctx.hosts:
            for url in http_urls(host)[:8]:
                self._scan_url(ctx, host.ip, url, result)
        return result

    def _scan_url(self, ctx: ToolContext, ip: str, url: str, result: ToolResult) -> None:
        out = ctx.path(f"nikto_{_safe(url)}.json")
        argv = [
            "nikto",
            "-h",
            url,
            "-Format",
            "json",
            "-output",
            out.name,
            "-nointeractive",
            "-maxtime",
            "120s",
            "-Tuning",
            "123bde",
        ]
        cmd = ctx.run(argv, timeout=min(ctx.timeout, 300))
        data = read_json(out)
        if data is None:
            if cmd.returncode not in (0, 1):
                ctx.warn(f"nikto falló para {url}: {cmd.output[-300:]}")
            return
        entries = data if isinstance(data, list) else data.get("vulnerabilities", [])
        if isinstance(entries, dict):
            entries = [entries]
        for entry in entries or []:
            if not isinstance(entry, dict):
                continue
            message = str(entry.get("msg") or entry.get("message") or entry.get("id") or "").strip()
            if not message:
                continue
            severity = _severity(message)
            cves = sorted(set(CVE_RE.findall(message)))
            uri = entry.get("url") or entry.get("uri") or url
            result.findings.append(
                finding(
                    severity,
                    "Nikto: " + _short(message),
                    ip,
                    f"{url}{uri}: {message}",
                    "Revisar la configuración del servidor web y aplicar el parche o la "
                    "restricción indicada por Nikto.",
                    cves=cves,
                    tags=["web", "vuln-scan"],
                    source="nikto",
                    confidence="media",
                )
            )


def _severity(message: str) -> str:
    text = message.lower()
    if any(k in text for k in ("remote code", "rce", "sql injection", "command execution", "backdoor")):
        return "CRÍTICO"
    if any(k in text for k in ("vulnerable", "outdated", "default", "traversal", "xss", "injection")):
        return "ALTO"
    if any(k in text for k in ("exposed", "disclosure", "missing", "allowed", "directory")):
        return "MEDIO"
    return "INFO"


def _short(message: str, limit: int = 110) -> str:
    text = re.sub(r"\s+", " ", message).strip()
    return text[:limit] + ("…" if len(text) > limit else "")


def _safe(value: str) -> str:
    return re.sub(r"[^A-Za-z0-9_.-]", "_", value)[:60]
