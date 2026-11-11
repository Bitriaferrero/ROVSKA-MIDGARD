#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Nuclei: plantillas de vulnerabilidades y CVEs."""

from __future__ import annotations

from urllib.parse import urlparse

from ..models import normalize_severity
from .base import Tool, ToolContext, ToolResult, ToolSpec, finding, http_urls, read_json_lines


class NucleiTool(Tool):
    spec = ToolSpec(
        name="nuclei",
        binary="nuclei",
        category="web",
        description="Detección de CVEs y vulnerabilidades web con plantillas Nuclei.",
        phase="vuln",
        profiles=("web", "deep", "attack"),
        attack=("T1595.002", "T1190"),
    )

    def run(self, ctx: ToolContext) -> ToolResult:
        if not self.available(ctx.runner):
            return self.missing(ctx)
        urls: list[str] = []
        for host in ctx.hosts:
            urls.extend(http_urls(host))
        if not urls:
            return self.result(skipped=True, ok=True, error="sin servicios web que analizar")

        list_file = ctx.path("nuclei_targets.txt")
        list_file.write_text("\n".join(urls[:100]), encoding="utf-8")
        out = ctx.path("nuclei.jsonl")
        argv = [
            "nuclei",
            "-l",
            list_file.name,
            "-jsonl",
            "-o",
            out.name,
            "-silent",
            "-severity",
            str(ctx.options.get("nuclei_severity", "critical,high,medium,low")),
            "-rate-limit",
            str(ctx.options.get("nuclei_rate", 50)),
            "-timeout",
            "10",
            "-retries",
            "1",
            "-no-color",
        ]
        cmd = ctx.run(argv, timeout=ctx.timeout)
        result = ToolResult(tool=self.name, command=argv, duration=cmd.duration)
        rows = read_json_lines(out)
        if not rows and cmd.returncode not in (0, 1):
            result.ok = False
            result.error = cmd.output[-2000:]
            return result
        for row in rows:
            info = row.get("info", {}) or {}
            classification = info.get("classification", {}) or {}
            cves = classification.get("cve-id") or []
            if isinstance(cves, str):
                cves = [cves]
            cwes = classification.get("cwe-id") or []
            if isinstance(cwes, str):
                cwes = [cwes]
            cwe_ids = [f"CWE-{str(c).replace('cwe-', '').strip()}" for c in cwes if c]
            title = info.get("name") or row.get("template-id") or "Hallazgo Nuclei"
            severity = normalize_severity(info.get("severity"), "MEDIO")
            matched = row.get("matched-at") or row.get("host") or ""
            host = row.get("host") or _host_from_url(matched)
            description = info.get("description") or ""
            remediation = info.get("remediation") or "Actualizar el componente y revisar la configuración."
            tags = info.get("tags") or []
            if isinstance(tags, str):
                tags = [t.strip() for t in tags.split(",") if t.strip()]
            result.findings.append(
                finding(
                    severity,
                    f"Nuclei: {title}",
                    host,
                    f"{matched}. {description}".strip(),
                    remediation,
                    cves=list(cves),
                    cwe=cwe_ids,
                    tags=["web", "vuln-scan"] + list(tags),
                    source="nuclei",
                    confidence="alta",
                )
            )
        result.meta["templates"] = len(rows)
        return result


def _host_from_url(url: str) -> str:
    try:
        return urlparse(url).hostname or url
    except ValueError:
        return url
