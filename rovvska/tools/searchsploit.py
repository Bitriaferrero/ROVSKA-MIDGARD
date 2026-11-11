#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""searchsploit: correlación con exploits públicos (Exploit-DB)."""

from __future__ import annotations

import re

from .base import Tool, ToolContext, ToolResult, ToolSpec, finding, read_json


class SearchsploitTool(Tool):
    spec = ToolSpec(
        name="searchsploit",
        binary="searchsploit",
        category="vuln",
        description="Busca exploits públicos para productos y versiones detectadas.",
        phase="vuln",
        profiles=("deep", "attack"),
        attack=("T1596", "T1588.005"),
    )

    def run(self, ctx: ToolContext) -> ToolResult:
        if not self.available(ctx.runner):
            return self.missing(ctx)
        result = ToolResult(tool=self.name)
        queries: list[tuple[str, str]] = []
        for host in ctx.hosts:
            for port in host.ports:
                product = (port.product or "").strip()
                version = (port.version or "").strip()
                if not product or product.lower() in {"unknown", "tcpwrapped"}:
                    continue
                query = f"{product} {version}".strip()
                if len(query) >= 4:
                    queries.append((host.ip, query))
        seen: set[tuple[str, str]] = set()
        for ip, query in queries[:10]:
            key = (ip, query.lower())
            if key in seen:
                continue
            seen.add(key)
            self._query(ctx, ip, query, result)
        return result

    def _query(self, ctx: ToolContext, ip: str, query: str, result: ToolResult) -> None:
        out = ctx.path(f"searchsploit_{re.sub(r'[^a-z0-9]+', '_', query.lower())[:40]}.json")
        argv = ["searchsploit", "--json", query]
        cmd = ctx.run(argv, timeout=min(ctx.timeout, 90))
        data = read_json(out)
        if data is None:
            # searchsploit --json escribe a stdout en algunas versiones.
            import json

            try:
                data = json.loads(cmd.stdout)
            except (json.JSONDecodeError, TypeError):
                return
        entries = data.get("RESULTS_EXPLOIT", []) if isinstance(data, dict) else []
        if not entries:
            return
        titles = []
        for entry in entries[:6]:
            if isinstance(entry, dict):
                title = entry.get("Title") or entry.get("title") or ""
                edb = entry.get("EDB-ID") or entry.get("id") or ""
                if title:
                    titles.append(f"{title} (EDB-{edb})" if edb else title)
        if not titles:
            return
        result.findings.append(
            finding(
                "INFO",
                "Exploits públicos potenciales",
                ip,
                f"{query}: {len(entries)} resultados en Exploit-DB. " + "; ".join(titles[:6]),
                "Validar si la versión detectada es realmente vulnerable; no ejecutar exploits "
                "sin autorización y ventana de pruebas.",
                tags=["vuln-scan", "exploit"],
                source="searchsploit",
                confidence="baja",
            )
        )
