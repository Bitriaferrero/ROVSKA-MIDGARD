#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Hydra: prueba controlada de credenciales (operación ofensiva).

Por defecto es un *dry-run*: solo muestra el comando que se ejecutaría.
Para lanzarla de verdad hacen falta ``execute=true``, ``authorization=true``
y ``ROVSKA_ALLOW_ATTACK=1``.
"""

from __future__ import annotations

import re

from .base import Tool, ToolContext, ToolResult, ToolSpec, finding


SUCCESS_RE = re.compile(r"login:\s*(\S+)\s+password:\s*(\S+)", re.IGNORECASE)


class HydraTool(Tool):
    spec = ToolSpec(
        name="hydra",
        binary="hydra",
        category="attack",
        description="Prueba de credenciales con Hydra (dry-run por defecto).",
        phase="exploit",
        profiles=("attack",),
        requires_attack=True,
        attack=("T1110", "T1078"),
    )

    def run(self, ctx: ToolContext) -> ToolResult:
        if not self.available(ctx.runner):
            return self.missing(ctx)
        options = ctx.options or {}
        service = str(options.get("service") or "ssh")
        port = options.get("port")
        users = _as_list(options.get("users"))
        passwords = _as_list(options.get("passwords"))
        if not users or not passwords:
            return self.result(
                ok=False,
                skipped=True,
                error="hydra requiere 'users' y 'passwords' explícitos; no se usan diccionarios por defecto",
            )

        dry_run = not bool(options.get("execute"))
        if dry_run:
            return self.result(
                ok=True,
                skipped=False,
                meta={
                    "dry_run": True,
                    "planned": {
                        "tool": "hydra",
                        "service": service,
                        "port": port,
                        "users": len(users),
                        "passwords": len(passwords),
                        "target": ctx.target,
                    },
                    "note": "dry-run: no se ha probado ninguna credencial",
                },
                findings=[
                    finding(
                        "INFO",
                        "Prueba de credenciales planificada (dry-run)",
                        ctx.target,
                        f"Hydra contra {service}"
                        + (f":{port}" if port else "")
                        + f" con {len(users)} usuarios y {len(passwords)} contraseñas.",
                        "Revisar el plan y relanzar con execute=true solo con autorización expresa.",
                        tags=["credentials", "brute-force"],
                        source="hydra",
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
                error="falta authorization=true para ejecutar hydra",
            )

        users_file = ctx.path("hydra_users.txt")
        pass_file = ctx.path("hydra_passwords.txt")
        out_file = ctx.path("hydra_result.txt")
        users_file.write_text("\n".join(users), encoding="utf-8")
        pass_file.write_text("\n".join(passwords), encoding="utf-8")
        argv = [
            "hydra",
            "-L",
            users_file.name,
            "-P",
            pass_file.name,
            "-t",
            str(int(options.get("threads", 4))),
            "-f",
            "-o",
            out_file.name,
            "-I",
        ]
        if port:
            argv += ["-s", str(port)]
        argv += [ctx.target, service]
        cmd = ctx.run(argv, timeout=min(ctx.timeout, 900))
        result = ToolResult(tool=self.name, command=argv, duration=cmd.duration)
        text = out_file.read_text(encoding="utf-8", errors="replace") if out_file.exists() else cmd.output
        matches = SUCCESS_RE.findall(text)
        for user, password in matches:
            result.findings.append(
                finding(
                    "CRÍTICO",
                    "Credenciales válidas encontradas",
                    ctx.target,
                    f"Hydra encontró credenciales válidas en {service}: usuario '{user}' / contraseña '{password}'.",
                    "Cambiar la contraseña de inmediato, revisar el acceso en logs, aplicar "
                    "bloqueo por intentos y MFA, y rotar credenciales reutilizadas.",
                    cwe=["CWE-521", "CWE-1392"],
                    tags=["credentials", "brute-force", "valid-accounts"],
                    source="hydra",
                    confidence="alta",
                )
            )
        if not matches:
            result.good.append(f"{ctx.target}: Hydra no encontró credenciales con el diccionario usado.")
        result.meta["attempts"] = f"{len(users)}x{len(passwords)}"
        return result


def _as_list(value) -> list[str]:
    if not value:
        return []
    if isinstance(value, str):
        return [part.strip() for part in value.split(",") if part.strip()]
    if isinstance(value, (list, tuple)):
        return [str(item).strip() for item in value if str(item).strip()]
    return []
