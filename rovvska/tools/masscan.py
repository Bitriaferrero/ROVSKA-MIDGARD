#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Masscan: barrido masivo de puertos (opcional, para rangos grandes)."""

from __future__ import annotations

from ..models import Host, Port
from .base import Tool, ToolContext, ToolResult, ToolSpec, read_json


class MasscanTool(Tool):
    spec = ToolSpec(
        name="masscan",
        binary="masscan",
        category="network",
        description="Barrido rápido de puertos TCP en rangos amplios.",
        phase="recon",
        profiles=("full", "deep"),
        attack=("T1595.001", "T1046"),
    )

    def run(self, ctx: ToolContext) -> ToolResult:
        if not self.available(ctx.runner):
            return self.missing(ctx)
        if not ctx.options.get("use_masscan"):
            return self.result(
                skipped=True,
                ok=True,
                error="masscan desactivado (use_masscan=false)",
            )
        ports = str(ctx.options.get("masscan_ports", "1-65535"))
        rate = int(ctx.options.get("masscan_rate", 1000))
        out = ctx.path("masscan.json")
        argv = [
            "masscan",
            ctx.target,
            f"-p{ports}",
            "--rate",
            str(rate),
            "--wait",
            "3",
            "-oJ",
            out.name,
        ]
        cmd = ctx.run(argv, timeout=ctx.timeout)
        result = ToolResult(tool=self.name, command=argv, duration=cmd.duration)
        if not out.exists():
            result.ok = False
            result.error = cmd.output[-2000:] or "masscan no generó el fichero JSON"
            return result
        raw = out.read_text(encoding="utf-8", errors="replace").strip()
        if not raw:
            # Sin puertos abiertos masscan deja el fichero vacío y sale con 0.
            if cmd.ok:
                result.meta["hosts"] = 0
                return result
            result.ok = False
            result.error = cmd.output[-2000:] or "masscan no devolvió resultados"
            return result
        data = read_json(out)
        if not isinstance(data, list):
            result.ok = False
            result.error = f"masscan no devolvió JSON válido: {cmd.output[-500:]}"
            return result
        by_ip: dict[str, Host] = {}
        for item in data:
            if not isinstance(item, dict):
                continue
            ip = item.get("ip")
            if not ip:
                continue
            host = by_ip.setdefault(ip, Host(ip=ip))
            for port_data in item.get("ports", []) or []:
                if port_data.get("status") != "open":
                    continue
                try:
                    number = int(port_data.get("port"))
                except (TypeError, ValueError):
                    continue
                host.add_port(
                    Port(
                        port=number,
                        proto=port_data.get("proto", "tcp"),
                        state="open",
                    )
                )
        result.hosts = list(by_ip.values())
        result.meta["hosts"] = len(result.hosts)
        return result
