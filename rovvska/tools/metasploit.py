#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Metasploit: comprobación y explotación controlada (dry-run por defecto)."""

from __future__ import annotations

import re

from .base import Tool, ToolContext, ToolResult, ToolSpec, finding


VULN_RE = re.compile(
    r"(appears to be vulnerable|the target is vulnerable|is vulnerable|vulnerable to)",
    re.IGNORECASE,
)
SESSION_RE = re.compile(r"session \d+ opened|meterpreter session|command shell session", re.IGNORECASE)
SAFE_RE = re.compile(r"(not vulnerable|is not exploitable|the target is not exploitable)", re.IGNORECASE)
MODULE_RE = re.compile(r"^[a-z0-9_-]+/[a-z0-9_/-]+$")


class MetasploitTool(Tool):
    spec = ToolSpec(
        name="metasploit",
        binary="msfconsole",
        category="attack",
        description="Comprobación/explotación con Metasploit (dry-run por defecto).",
        phase="exploit",
        profiles=("attack",),
        requires_attack=True,
        attack=("T1190", "T1210", "T1203"),
    )

    def run(self, ctx: ToolContext) -> ToolResult:
        if not self.available(ctx.runner):
            return self.missing(ctx)
        options = ctx.options or {}
        module = str(options.get("module") or "").strip()
        if not MODULE_RE.match(module):
            return self.result(
                ok=False,
                skipped=True,
                error="metasploit requiere un 'module' válido, p. ej. auxiliary/scanner/ssh/ssh_version",
            )
        action = str(options.get("action") or "check").lower()
        if action not in {"check", "exploit"}:
            return self.result(ok=False, skipped=True, error="action debe ser check o exploit")
        dry_run = not bool(options.get("execute"))
        port = options.get("port")
        payload = str(options.get("payload") or "").strip()
        lhost = str(options.get("lhost") or "").strip()
        lport = str(options.get("lport") or "4444").strip()

        lines = [f"use {module}", f"set RHOSTS {ctx.target}", "set THREADS 1", "set STOP_ON_ERROR true"]
        if port:
            lines.append(f"set RPORT {port}")
        if action == "exploit":
            if not payload:
                return self.result(
                    ok=False,
                    skipped=True,
                    error="exploit requiere 'payload' (y normalmente lhost/lport)",
                )
            lines.append(f"set PAYLOAD {payload}")
            if lhost:
                lines.append(f"set LHOST {lhost}")
            lines.append(f"set LPORT {lport}")
            lines += ["run", "sleep 5", "sessions -l"]
        else:
            # Los módulos auxiliary no implementan `check`: se ejecutan con `run`.
            lines.append("run" if module.startswith("auxiliary/") else "check")
        lines.append("exit -y")
        script = "\n".join(lines) + "\n"

        if dry_run:
            return self.result(
                ok=True,
                meta={
                    "dry_run": True,
                    "planned": {"module": module, "action": action, "target": ctx.target, "script": script},
                    "note": "dry-run: no se ha ejecutado nada en el objetivo",
                },
                findings=[
                    finding(
                        "INFO",
                        "Módulo Metasploit planificado (dry-run)",
                        ctx.target,
                        f"{action} con {module}" + (f" contra el puerto {port}" if port else ""),
                        "Revisar el módulo y relanzar con execute=true solo con autorización expresa.",
                        tags=["exploit"],
                        source="metasploit",
                        confidence="alta",
                    )
                ],
            )

        if not ctx.settings or not ctx.settings.allow_attack:
            return self.result(
                ok=False,
                skipped=True,
                error="operación ofensiva bloqueada: activa ROVSKA_ALLOW_ATTACK=1",
            )
        if not options.get("authorization"):
            return self.result(
                ok=False,
                skipped=True,
                error="falta authorization=true para ejecutar metasploit",
            )

        script_file = ctx.path("msf.rc")
        log_file = ctx.path("msf.log")
        script_file.write_text(script, encoding="utf-8")
        argv = ["msfconsole", "-q", "-r", script_file.name, "-o", log_file.name]
        cmd = ctx.run(argv, timeout=min(ctx.timeout, 1800))
        result = ToolResult(tool=self.name, command=argv, duration=cmd.duration)
        log = log_file.read_text(encoding="utf-8", errors="replace") if log_file.exists() else cmd.output
        result.meta["log_tail"] = log[-4000:]

        if SESSION_RE.search(log):
            result.findings.append(
                finding(
                    "CRÍTICO",
                    "Sesión de Metasploit establecida",
                    ctx.target,
                    f"{module} abrió una sesión contra {ctx.target}.",
                    "Aislar el host, revisar el acceso, parchear la vulnerabilidad y rotar credenciales.",
                    tags=["exploit", "valid-accounts"],
                    source="metasploit",
                    confidence="alta",
                )
            )
        elif VULN_RE.search(log):
            result.findings.append(
                finding(
                    "CRÍTICO",
                    f"Vulnerable a {module}",
                    ctx.target,
                    f"Metasploit indica que el objetivo es vulnerable a {module}.",
                    "Aplicar el parche del fabricante o mitigar el servicio; validar con el equipo responsable.",
                    tags=["exploit"],
                    source="metasploit",
                    confidence="alta",
                )
            )
        elif SAFE_RE.search(log):
            result.good.append(f"{ctx.target}: Metasploit no marca como vulnerable a {module}.")
        else:
            result.findings.append(
                finding(
                    "INFO",
                    "Comprobación Metasploit sin resultado concluyente",
                    ctx.target,
                    f"{module}: no se pudo confirmar explotabilidad (revisar el log).",
                    "Revisar la salida de Metasploit y validar manualmente el servicio.",
                    tags=["exploit"],
                    source="metasploit",
                    confidence="baja",
                )
            )
        return result
