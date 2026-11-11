#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Descubrimiento de rutas web con ffuf."""

from __future__ import annotations

from .base import Tool, ToolContext, ToolResult, ToolSpec, finding, http_urls, read_json


SENSITIVE = {
    ".git": "CRÍTICO",
    ".env": "CRÍTICO",
    "backup": "ALTO",
    "config": "ALTO",
    "phpmyadmin": "ALTO",
    "server-status": "MEDIO",
    "admin": "MEDIO",
    "login": "INFO",
    "api": "INFO",
    "swagger": "MEDIO",
    "actuator": "ALTO",
    "debug": "ALTO",
    "console": "ALTO",
    "manager": "ALTO",
}

WORDLISTS = (
    "/usr/share/seclists/Discovery/Web-Content/common.txt",
    "/usr/share/wordlists/dirb/common.txt",
    "/usr/share/dirb/wordlists/common.txt",
)


class WebFuzzTool(Tool):
    spec = ToolSpec(
        name="web_fuzz",
        binary="ffuf",
        category="web",
        description="Descubrimiento de rutas y paneles ocultos con ffuf.",
        phase="vuln",
        profiles=("web", "deep", "attack"),
        attack=("T1083", "T1595.002"),
    )

    def run(self, ctx: ToolContext) -> ToolResult:
        if not self.available(ctx.runner):
            return self.missing(ctx)
        wordlist = str(ctx.options.get("wordlist") or WORDLISTS[0])
        result = ToolResult(tool=self.name)
        for host in ctx.hosts:
            for url in http_urls(host)[:4]:
                self._scan(ctx, host.ip, url, wordlist, result)
        return result

    def _scan(self, ctx: ToolContext, ip: str, url: str, wordlist: str, result: ToolResult) -> None:
        out = ctx.path(f"ffuf_{_safe(url)}.json")
        argv = [
            "ffuf",
            "-u",
            f"{url.rstrip('/')}/FUZZ",
            "-w",
            wordlist,
            "-of",
            "json",
            "-o",
            out.name,
            "-mc",
            "200,204,301,302,307,401,403",
            "-t",
            str(ctx.options.get("ffuf_threads", 20)),
            "-timeout",
            "10",
            "-s",
        ]
        cmd = ctx.run(argv, timeout=min(ctx.timeout, 600))
        data = read_json(out)
        if not isinstance(data, dict):
            if cmd.returncode not in (0, 1):
                ctx.warn(f"ffuf falló para {url}: {cmd.output[-300:]}")
            return
        results = data.get("results", []) or []
        for item in results:
            if not isinstance(item, dict):
                continue
            path = str((item.get("input") or {}).get("FUZZ") or "").strip("/")
            status = item.get("status")
            length = item.get("length")
            if not path:
                continue
            severity = "INFO"
            for key, sev in SENSITIVE.items():
                if key in path.lower():
                    severity = sev
                    break
            if severity == "INFO" and status in {401, 403}:
                continue
            result.findings.append(
                finding(
                    severity,
                    f"Ruta web descubierta: /{path}",
                    ip,
                    f"{url.rstrip('/')}/{path} → HTTP {status} ({length} bytes).",
                    "Revisar si la ruta debe ser pública; proteger paneles, backups y "
                    "ficheros de configuración, y añadir autenticación.",
                    tags=["web", "info-disclosure"],
                    source="web_fuzz",
                    confidence="media",
                )
            )
        result.meta.setdefault("paths", {})[url] = len(results)


def _safe(value: str) -> str:
    return "".join(c if c.isalnum() else "_" for c in value)[:60]
