#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""WhatWeb: identificación de tecnologías web."""

from __future__ import annotations

from urllib.parse import urlparse

from .base import Tool, ToolContext, ToolResult, ToolSpec, finding, http_urls, read_json


class WhatWebTool(Tool):
    spec = ToolSpec(
        name="whatweb",
        binary="whatweb",
        category="web",
        description="Fingerprinting de CMS, servidores y frameworks web.",
        phase="recon",
        profiles=("web", "deep", "attack"),
        attack=("T1592.002",),
    )

    def run(self, ctx: ToolContext) -> ToolResult:
        if not self.available(ctx.runner):
            return self.missing(ctx)
        urls: list[str] = []
        by_url: dict[str, str] = {}
        for host in ctx.hosts:
            for url in http_urls(host):
                urls.append(url)
                by_url[url] = host.ip
        if not urls:
            return self.result(skipped=True, ok=True, error="sin servicios web que analizar")

        out = ctx.path("whatweb.json")
        argv = [
            "whatweb",
            "--log-json",
            out.name,
            "--no-errors",
            "--quiet",
            "-a",
            "3",
            *urls[:40],
        ]
        cmd = ctx.run(argv, timeout=min(ctx.timeout, 600))
        result = ToolResult(tool=self.name, command=argv, duration=cmd.duration)
        data = read_json(out)
        if not isinstance(data, list):
            result.ok = False
            result.error = cmd.output[-2000:] or "whatweb no generó JSON"
            return result
        for item in data:
            if not isinstance(item, dict):
                continue
            target = item.get("target", "")
            ip = by_url.get(target) or _ip_from_url(target)
            if not ip:
                continue
            plugins = item.get("plugins", {}) or {}
            techs = []
            for name, info in plugins.items():
                if name in {"Country", "IP", "Title"}:
                    continue
                version = ""
                if isinstance(info, dict):
                    versions = info.get("version") or info.get("string") or []
                    if isinstance(versions, list) and versions:
                        version = str(versions[0])
                    elif versions:
                        version = str(versions)
                techs.append(f"{name}{(' ' + version) if version else ''}".strip())
            if not techs:
                continue
            result.findings.append(
                finding(
                    "INFO",
                    "Tecnologías web detectadas",
                    ip,
                    f"{target}: {', '.join(techs[:12])}.",
                    "Mantener las tecnologías actualizadas y ocultar versiones cuando sea posible.",
                    tags=["web", "service-version"],
                    source="whatweb",
                    confidence="alta",
                )
            )
            result.meta.setdefault("technologies", {})[ip] = techs
        return result


def _ip_from_url(url: str) -> str:
    try:
        return urlparse(url).hostname or ""
    except ValueError:
        return ""
