#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""DNS: enumeración con dnsrecon."""

from __future__ import annotations

import ipaddress

from .base import Tool, ToolContext, ToolResult, ToolSpec, finding, read_json


class DnsTool(Tool):
    spec = ToolSpec(
        name="dns",
        binary="dnsrecon",
        category="infra",
        description="Enumeración DNS: registros, transferencia de zona y subdominios.",
        phase="recon",
        profiles=("infra", "deep", "attack"),
        attack=("T1590", "T1596"),
    )

    def run(self, ctx: ToolContext) -> ToolResult:
        if not self.available(ctx.runner):
            return self.missing(ctx)
        domain = ctx.options.get("domain") or ctx.target
        try:
            ipaddress.ip_address(domain.split("/")[0])
            return self.result(skipped=True, ok=True, error="el objetivo es una IP; DNS requiere un dominio")
        except ValueError:
            pass
        out = ctx.path("dnsrecon.json")
        argv = ["dnsrecon", "-d", domain, "-j", out.name, "--threads", "4"]
        cmd = ctx.run(argv, timeout=min(ctx.timeout, 300))
        result = ToolResult(tool=self.name, command=argv, duration=cmd.duration)
        data = read_json(out)
        if not isinstance(data, list):
            if cmd.returncode != 0:
                result.ok = False
                result.error = cmd.output[-2000:]
            return result
        records = []
        for entry in data:
            if not isinstance(entry, dict):
                continue
            rtype = str(entry.get("type", "")).upper()
            name = entry.get("name") or entry.get("target") or ""
            address = entry.get("address") or entry.get("target") or ""
            records.append({"type": rtype, "name": name, "address": address})
            if "ZONE TRANSFER" in rtype or "AXFR" in rtype:
                result.findings.append(
                    finding(
                        "ALTO",
                        "Transferencia de zona DNS permitida",
                        str(address or name),
                        f"{domain}: transferencia de zona ({rtype}) desde {name}.",
                        "Restringir AXFR a servidores secundarios autorizados.",
                        cwe=["CWE-200"],
                        tags=["dns", "info-disclosure"],
                        source="dns",
                        confidence="alta",
                    )
                )
        if records:
            result.findings.append(
                finding(
                    "INFO",
                    "Registros DNS enumerados",
                    domain,
                    f"{domain}: {len(records)} registros. "
                    + ", ".join(f"{r['type']} {r['name']}" for r in records[:12]),
                    "Revisar registros antiguos, subdominios olvidados y registros que "
                    "expongan servicios internos.",
                    tags=["dns", "info-disclosure"],
                    source="dns",
                    confidence="alta",
                )
            )
        result.meta["records"] = records[:200]
        return result
