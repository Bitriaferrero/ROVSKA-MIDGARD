#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Hydra: prueba controlada de credenciales (operación ofensiva).

Por defecto es un *dry-run*: solo muestra el comando que se ejecutaría.
Para lanzarla de verdad hacen falta ``execute=true``, ``authorization=true``
y ``ROVSKA_ALLOW_ATTACK=1``.

Las listas pueden venir del JSON (``users``/``passwords``) o de ficheros
subidos al panel (``users_file``/``passwords_file``) o de un fichero combinado
``usuario:contraseña`` (``combo_file``). Los ficheros tienen prioridad sobre
el JSON. No se usan diccionarios por defecto.
"""

from __future__ import annotations

import os
import re
from pathlib import Path

from .. import hibp
from .base import Tool, ToolContext, ToolResult, ToolSpec, finding


SUCCESS_RE = re.compile(r"login:\s*(\S+)\s+password:\s*(\S+)", re.IGNORECASE)

MAX_LINES = 200_000
MAX_LINE_LENGTH = 4_096
WARN_LINES = 5_000


class HydraTool(Tool):
    spec = ToolSpec(
        name="hydra",
        binary="hydra",
        category="attack",
        description="Prueba de credenciales con Hydra (dry-run por defecto; listas JSON o ficheros).",
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

        users: list[str] = []
        passwords: list[str] = []
        combo: list[str] = []
        source = "json"
        skipped_combo = 0

        combo_name = str(options.get("combo_file") or "").strip()
        if combo_name:
            combo, error, skipped_combo = _load_file_list(
                ctx, combo_name, "pares usuario:contraseña", combinado=True
            )
            if error:
                return self.result(ok=False, skipped=True, error=error)
            source = "combo"
            if _has_separate_lists(options):
                ctx.warn(
                    "hydra: se usa el fichero combinado; se ignoran las listas "
                    "de usuarios y contraseñas"
                )
        else:
            users_file = str(options.get("users_file") or "").strip()
            pass_file = str(options.get("passwords_file") or "").strip()
            if users_file:
                users, error, _ = _load_file_list(ctx, users_file, "usuarios")
                if error:
                    return self.result(ok=False, skipped=True, error=error)
                source = "file"
            else:
                users = _as_list(options.get("users"))
            if pass_file:
                passwords, error, _ = _load_file_list(ctx, pass_file, "contraseñas")
                if error:
                    return self.result(ok=False, skipped=True, error=error)
                source = "file"
            else:
                passwords = _as_list(options.get("passwords"))

        if not combo and (not users or not passwords):
            return self.result(
                ok=False,
                skipped=True,
                error="hydra requiere 'users' y 'passwords' explícitos; no se usan diccionarios por defecto",
            )

        if combo:
            if skipped_combo:
                ctx.warn(
                    f"hydra: {skipped_combo} líneas sin formato usuario:contraseña, se omiten"
                )
            total = len(combo)
            description = f"con {total} pares usuario:contraseña"
        else:
            total = len(users) * len(passwords)
            description = f"con {len(users)} usuarios y {len(passwords)} contraseñas"
        if total > WARN_LINES:
            ctx.warn(
                f"hydra: {total} intentos online; puede tardar horas y disparar "
                "bloqueos de cuenta o fail2ban"
            )

        dry_run = not bool(options.get("execute"))
        if dry_run:
            planned = {
                "tool": "hydra",
                "service": service,
                "port": port,
                "target": ctx.target,
                "source": source,
            }
            if combo:
                planned["combos"] = len(combo)
            else:
                planned["users"] = len(users)
                planned["passwords"] = len(passwords)
            return self.result(
                ok=True,
                skipped=False,
                meta={
                    "dry_run": True,
                    "planned": planned,
                    "note": "dry-run: no se ha probado ninguna credencial",
                },
                findings=[
                    finding(
                        "INFO",
                        "Prueba de credenciales planificada (dry-run)",
                        ctx.target,
                        f"Hydra contra {service}"
                        + (f":{port}" if port else "")
                        + f" {description}.",
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

        out_file = ctx.path("hydra_result.txt")
        try:
            threads = max(1, min(int(options.get("threads", 4) or 4), 16))
        except (TypeError, ValueError):
            threads = 4
        argv = ["hydra"]
        if combo:
            combo_path = ctx.path("hydra_combo.txt")
            _write_private(combo_path, "\n".join(combo))
            argv += ["-C", combo_path.name]
        else:
            users_file = ctx.path("hydra_users.txt")
            pass_file = ctx.path("hydra_passwords.txt")
            _write_private(users_file, "\n".join(users))
            _write_private(pass_file, "\n".join(passwords))
            argv += ["-L", users_file.name, "-P", pass_file.name]
        argv += ["-t", str(threads), "-f", "-o", out_file.name, "-I"]
        wait = options.get("wait")
        if wait:
            try:
                argv += ["-W", str(max(0, int(wait)))]
            except (TypeError, ValueError):
                pass
        if port:
            argv += ["-s", str(port)]
        argv += [ctx.target, service]
        cmd = ctx.run(argv, timeout=min(ctx.timeout, 900))
        result = ToolResult(tool=self.name, command=argv, duration=cmd.duration)
        text = out_file.read_text(encoding="utf-8", errors="replace") if out_file.exists() else cmd.output
        matches = SUCCESS_RE.findall(text)
        check_breaches = bool(options.get("check_breaches"))
        breach_info: list[dict] = []
        for user, password in matches:
            detail = (
                f"Hydra encontró credenciales válidas en {service}: "
                f"usuario '{user}' / contraseña '{password}'."
            )
            tags = ["credentials", "brute-force", "valid-accounts"]
            breach_entry: dict = {"user": user}
            if check_breaches and ctx.settings and ctx.settings.hibp_enabled:
                breach = hibp.check_password(
                    password,
                    timeout=ctx.settings.hibp_timeout,
                    api_url=ctx.settings.hibp_api,
                )
                breach_entry.update(breach.to_dict())
                if breach.found:
                    detail += (
                        f" La contraseña aparece {breach.count} veces en "
                        "filtraciones conocidas (HIBP)."
                    )
                    tags.append("breached")
                elif breach.checked:
                    detail += " No aparece en el corpus público de filtraciones (HIBP)."
                else:
                    detail += f" No se pudo comprobar filtraciones: {breach.error}."
            breach_info.append(breach_entry)
            result.findings.append(
                finding(
                    "CRÍTICO",
                    "Credenciales válidas encontradas",
                    ctx.target,
                    detail,
                    "Cambiar la contraseña de inmediato, revisar el acceso en logs, aplicar "
                    "bloqueo por intentos y MFA, y rotar credenciales reutilizadas.",
                    cwe=["CWE-521", "CWE-1392"],
                    tags=tags,
                    source="hydra",
                    confidence="alta",
                )
            )
        if not matches:
            result.good.append(f"{ctx.target}: Hydra no encontró credenciales con el diccionario usado.")
        result.meta["attempts"] = f"{len(combo)}" if combo else f"{len(users)}x{len(passwords)}"
        result.meta["source"] = source
        result.meta["hibp"] = breach_info
        return result


def _as_list(value) -> list[str]:
    if not value:
        return []
    if isinstance(value, str):
        return [part.strip() for part in value.split(",") if part.strip()]
    if isinstance(value, (list, tuple)):
        return [str(item).strip() for item in value if str(item).strip()]
    return []


def _has_separate_lists(options: dict) -> bool:
    return any(
        options.get(key)
        for key in ("users", "passwords", "users_file", "passwords_file")
    )


def _load_file_list(
    ctx: ToolContext,
    name: str,
    label: str,
    *,
    combinado: bool = False,
) -> tuple[list[str], str, int]:
    """Lee una lista subida al directorio de la operación.

    Devuelve ``(líneas, error, líneas_descartadas)``. Solo se aceptan nombres
    simples: cualquier ruta con directorios se rechaza para evitar traversal.
    """

    safe = Path(str(name)).name
    if not safe or safe != str(name).strip():
        return [], f"nombre de fichero no válido para {label}", 0
    path = ctx.path(safe)
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return [], f"no se pudo leer el fichero de {label} ({safe})", 0
    lines, skipped = _clean_lines(text, combinado=combinado)
    if not lines:
        return [], f"el fichero de {label} está vacío", 0
    if len(lines) >= MAX_LINES:
        ctx.warn(f"hydra: la lista de {label} se trunca a {MAX_LINES} líneas")
    return lines, "", skipped


def _clean_lines(text: str, *, combinado: bool = False) -> tuple[list[str], int]:
    lines: list[str] = []
    seen: set[str] = set()
    skipped = 0
    for raw in text.splitlines():
        line = raw.replace("\x00", "").strip()
        if not line:
            continue
        if len(line) > MAX_LINE_LENGTH:
            skipped += 1
            continue
        if combinado and ":" not in line:
            skipped += 1
            continue
        if line in seen:
            continue
        seen.add(line)
        lines.append(line)
        if len(lines) >= MAX_LINES:
            break
    return lines, skipped


def _write_private(path: Path, text: str) -> None:
    path.write_text(text, encoding="utf-8")
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass
