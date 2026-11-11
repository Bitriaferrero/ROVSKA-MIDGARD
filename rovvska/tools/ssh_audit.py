#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""ssh-audit: configuración del servidor SSH."""

from __future__ import annotations

import json

from .base import Tool, ToolContext, ToolResult, ToolSpec, finding


WEAK_KEX = {"diffie-hellman-group1-sha1", "diffie-hellman-group14-sha1", "diffie-hellman-group-exchange-sha1"}
WEAK_CIPHERS = {"arcfour", "arcfour128", "arcfour256", "3des-cbc", "des-cbc", "blowfish-cbc", "cast128-cbc"}
WEAK_MACS = {"hmac-md5", "hmac-md5-96", "hmac-sha1-96", "umac-64@openssh.com"}


class SshAuditTool(Tool):
    spec = ToolSpec(
        name="ssh_audit",
        binary="ssh-audit",
        category="infra",
        description="Auditoría de algoritmos y configuración de servidores SSH.",
        phase="vuln",
        profiles=("infra", "deep", "attack"),
        attack=("T1592.002", "T1021.004"),
    )

    def run(self, ctx: ToolContext) -> ToolResult:
        if not self.available(ctx.runner):
            return self.missing(ctx)
        result = ToolResult(tool=self.name)
        for host in ctx.hosts:
            for port in [p for p in host.ports if p.port == 22 or p.service == "ssh"]:
                self._scan(ctx, host.ip, port.port, result)
        return result

    def _scan(self, ctx: ToolContext, ip: str, port: int, result: ToolResult) -> None:
        argv = ["ssh-audit", "-j", f"{ip}:{port}"]
        cmd = ctx.run(argv, timeout=min(ctx.timeout, 180))
        try:
            data = json.loads(cmd.stdout)
        except (json.JSONDecodeError, TypeError):
            if cmd.returncode != 0:
                ctx.warn(f"ssh-audit falló para {ip}:{port}: {cmd.output[-300:]}")
            return
        banner = data.get("banner", {}) or {}
        software = banner.get("software") or banner.get("raw") or ""
        if software:
            result.findings.append(
                finding(
                    "INFO",
                    "Banner SSH expuesto",
                    ip,
                    f"{ip}:{port} → {software}",
                    "Ocultar la versión del servidor SSH (DebianBanner no / ServerTokens).",
                    tags=["ssh", "info-disclosure"],
                    source="ssh_audit",
                    confidence="alta",
                )
            )
        weak_kex = _weak(data.get("kex", []), WEAK_KEX)
        weak_enc = _weak(data.get("enc", []), WEAK_CIPHERS)
        weak_mac = _weak(data.get("mac", []), WEAK_MACS)
        if weak_kex or weak_enc or weak_mac:
            parts = []
            if weak_kex:
                parts.append("KEX " + ", ".join(sorted(weak_kex)))
            if weak_enc:
                parts.append("cifrados " + ", ".join(sorted(weak_enc)))
            if weak_mac:
                parts.append("MAC " + ", ".join(sorted(weak_mac)))
            result.findings.append(
                finding(
                    "MEDIO",
                    "SSH con algoritmos débiles",
                    ip,
                    f"{ip}:{port}: " + "; ".join(parts) + ".",
                    "Editar sshd_config y eliminar algoritmos obsoletos (KexAlgorithms, "
                    "Ciphers, MACs); recargar sshd.",
                    cwe=["CWE-327"],
                    tags=["ssh", "weak-crypto"],
                    source="ssh_audit",
                    confidence="alta",
                )
            )
        else:
            result.good.append(f"{ip}:{port}: SSH sin algoritmos débiles conocidos.")


def _weak(values, known: set[str]) -> set[str]:
    found: set[str] = set()
    for item in values or []:
        if isinstance(item, str):
            name = item
        elif isinstance(item, dict):
            name = item.get("algorithm") or item.get("name") or ""
        else:
            continue
        if name in known:
            found.add(name)
    return found
