#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""SNMP: comprobación de comunidad pública y datos del sistema."""

from __future__ import annotations

import re

from .base import Tool, ToolContext, ToolResult, ToolSpec, finding


OID_RE = re.compile(r"^(?:SNMPv2-MIB|SNMPv2-SMI|DISMAN-EVENT-MIB|HOST-RESOURCES-MIB)::(\w+)\.0\s*=\s*(.+)$")
NUMERIC_OID_RE = re.compile(r"^(?:iso|\.?1)\.3\.6\.1\.2\.1\.1\.(\d)\.0\s*=\s*(.+)$")
SYS_OIDS = {
    "1": "sysDescr",
    "2": "sysObjectID",
    "3": "sysUpTime",
    "4": "sysContact",
    "5": "sysName",
    "6": "sysLocation",
}
VALUE_PREFIX_RE = re.compile(
    r"^(?:STRING|INTEGER|OID|Timeticks|Hex-STRING|Gauge32|Counter32|Counter64|IpAddress):\s*",
    re.IGNORECASE,
)


class SnmpTool(Tool):
    spec = ToolSpec(
        name="snmp",
        binary="snmpwalk",
        category="infra",
        description="Comprueba SNMP con comunidad 'public' y extrae información del sistema.",
        phase="recon",
        profiles=("infra", "deep", "attack"),
        attack=("T1082", "T1016"),
    )

    def run(self, ctx: ToolContext) -> ToolResult:
        if not self.available(ctx.runner):
            return self.missing(ctx)
        result = ToolResult(tool=self.name)
        for host in ctx.hosts:
            if not any(p.port == 161 or p.service == "snmp" for p in host.ports):
                continue
            self._scan(ctx, host.ip, result)
        return result

    def _scan(self, ctx: ToolContext, ip: str, result: ToolResult) -> None:
        argv = ["snmpwalk", "-v2c", "-c", "public", "-t", "3", "-r", "1", ip]
        cmd = ctx.run(argv, timeout=min(ctx.timeout, 120))
        if cmd.returncode != 0 and not cmd.stdout.strip():
            result.good.append(f"{ip}: SNMP no responde con la comunidad 'public'.")
            return
        values: dict[str, str] = {}
        for line in cmd.stdout.splitlines():
            text = line.strip()
            match = OID_RE.match(text)
            if match:
                key, value = match.groups()
            else:
                match = NUMERIC_OID_RE.match(text)
                if not match:
                    continue
                key, value = SYS_OIDS.get(match.group(1), match.group(1)), match.group(2)
            values[key] = VALUE_PREFIX_RE.sub("", value.strip()).strip('"')
        if not values:
            return
        result.meta.setdefault("snmp", {})[ip] = values
        sysdescr = values.get("sysDescr", "")
        evidence = f"{ip}: SNMPv2c con comunidad 'public' responde."
        if sysdescr:
            evidence += f" sysDescr={sysdescr[:180]}."
        result.findings.append(
            finding(
                "ALTO",
                "SNMP con comunidad pública",
                ip,
                evidence,
                "Cambiar la comunidad SNMP, usar SNMPv3 con autenticación y cifrado, "
                "y filtrar UDP/161 a la LAN de gestión.",
                cwe=["CWE-1392"],
                tags=["snmp", "default-creds", "info-disclosure"],
                source="snmp",
                confidence="alta",
            )
        )
        for key in ("sysName", "sysLocation", "sysContact"):
            if values.get(key):
                result.findings.append(
                    finding(
                        "INFO",
                        f"SNMP expone {key}",
                        ip,
                        f"{ip}: {key}={values[key][:180]}",
                        "Limitar la información expuesta por SNMP a lo estrictamente necesario.",
                        tags=["snmp", "info-disclosure"],
                        source="snmp",
                        confidence="alta",
                    )
                )
