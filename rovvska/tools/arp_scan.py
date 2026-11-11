#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""ARP scan: descubrimiento de hosts en la LAN con MAC y fabricante."""

from __future__ import annotations

import re

from ..models import Host
from .base import Tool, ToolContext, ToolResult, ToolSpec


LINE_RE = re.compile(r"^(\d{1,3}(?:\.\d{1,3}){3})\s+([0-9a-fA-F:]{17})\s*(.*)$")


class ArpScanTool(Tool):
    spec = ToolSpec(
        name="arp_scan",
        binary="arp-scan",
        category="network",
        description="Descubrimiento ARP de hosts locales con MAC y fabricante.",
        phase="recon",
        profiles=("discovery", "quick", "full", "deep", "attack"),
        attack=("T1018",),
    )

    def run(self, ctx: ToolContext) -> ToolResult:
        if not self.available(ctx.runner):
            return self.missing(ctx)
        argv = [
            "arp-scan",
            "--plain",
            "--ignoredups",
            "--retry",
            "2",
            "--timeout",
            "1000",
            ctx.target,
        ]
        cmd = ctx.run(argv, timeout=min(ctx.timeout, 300))
        result = ToolResult(tool=self.name, command=argv, duration=cmd.duration)
        if cmd.returncode != 0 and not cmd.stdout.strip():
            result.ok = False
            result.error = cmd.output[-2000:]
            return result
        for line in cmd.stdout.splitlines():
            match = LINE_RE.match(line.strip())
            if not match:
                continue
            ip, mac, vendor = match.groups()
            result.hosts.append(
                Host(ip=ip, mac=mac.lower(), vendor=vendor.strip(), type="")
            )
        result.meta["hosts"] = len(result.hosts)
        return result
