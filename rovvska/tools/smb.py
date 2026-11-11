#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Enumeración SMB con enum4linux-ng."""

from __future__ import annotations

from .base import Tool, ToolContext, ToolResult, ToolSpec, finding, read_json


class SmbTool(Tool):
    spec = ToolSpec(
        name="smb",
        binary="enum4linux-ng",
        category="infra",
        description="Enumeración SMB: sesiones nulas, recursos, usuarios y firmado.",
        phase="recon",
        profiles=("infra", "deep", "attack"),
        attack=("T1135", "T1087.002", "T1021.002"),
    )

    def run(self, ctx: ToolContext) -> ToolResult:
        if not self.available(ctx.runner):
            return self.missing(ctx)
        result = ToolResult(tool=self.name)
        for host in ctx.hosts:
            if not any(p.port in {139, 445} for p in host.ports):
                continue
            self._scan(ctx, host.ip, result)
        return result

    def _scan(self, ctx: ToolContext, ip: str, result: ToolResult) -> None:
        out = ctx.path(f"enum4linux_{ip.replace(':', '_')}.json")
        # enum4linux-ng exige que el directorio del fichero de salida exista;
        # con un nombre relativo calcula dirname "" y aborta. "./" lo evita.
        argv = ["enum4linux-ng", "-oJ", f"./{out.name}", ip]
        cmd = ctx.run(argv, timeout=min(ctx.timeout, 600))
        data = read_json(out)
        if not isinstance(data, dict):
            if cmd.returncode != 0:
                ctx.warn(f"enum4linux-ng falló para {ip}: {cmd.output[-300:]}")
            return

        sessions_block = data.get("sessions", {}) or {}
        session_rows = sessions_block.get("sessions") if isinstance(sessions_block, dict) else sessions_block
        if isinstance(session_rows, dict):
            session_rows = list(session_rows.values())
        if isinstance(session_rows, list):
            for session in session_rows:
                if session is None or session is False:
                    continue
                if isinstance(session, dict):
                    success = session.get("auth", session.get("success", True))
                    label = session.get("session") or session.get("type") or "sesión"
                    if not success:
                        continue
                else:
                    label = str(session)
                result.findings.append(
                    finding(
                        "ALTO",
                        "SMB permite sesión nula o anónima",
                        ip,
                        f"{ip}: sesión SMB '{label}' aceptada sin credenciales.",
                        "Deshabilitar sesiones nulas/anónimas, restringir SMB a la LAN "
                        "de gestión y revisar permisos de recursos.",
                        cwe=["CWE-306"],
                        tags=["smb", "valid-accounts"],
                        source="smb",
                        confidence="alta",
                    )
                )

        shares_block = data.get("shares", []) or []
        shares = shares_block.get("shares") if isinstance(shares_block, dict) else shares_block
        if isinstance(shares, dict):
            shares = list(shares.values())
        readable = []
        for share in shares or []:
            if not isinstance(share, dict):
                continue
            name = share.get("name") or share.get("share") or ""
            access = str(share.get("access") or share.get("permissions") or "").lower()
            if name and name not in {"IPC$", "print$"} and ("read" in access or "write" in access):
                readable.append(f"{name} ({access or 'acceso'})")
        if readable:
            result.findings.append(
                finding(
                    "ALTO",
                    "Recursos SMB accesibles",
                    ip,
                    f"{ip}: recursos legibles/escribibles: {', '.join(readable[:12])}.",
                    "Revisar permisos NTFS y de recurso; aplicar mínimo privilegio y auditoría de acceso.",
                    cwe=["CWE-284"],
                    tags=["smb", "shares"],
                    source="smb",
                    confidence="alta",
                )
            )

        users_block = data.get("users", []) or []
        users = users_block.get("users") if isinstance(users_block, dict) else users_block
        if isinstance(users, dict):
            users = list(users.keys())
        usernames = []
        for user in users or []:
            if isinstance(user, dict):
                name = user.get("username") or user.get("name")
            else:
                name = str(user)
            if name:
                usernames.append(str(name))
        if usernames:
            result.findings.append(
                finding(
                    "MEDIO",
                    "Enumeración de usuarios SMB",
                    ip,
                    f"{ip}: {len(usernames)} usuarios enumerados: {', '.join(usernames[:15])}.",
                    "Restringir la enumeración anónima y revisar cuentas antiguas o de servicio.",
                    cwe=["CWE-200"],
                    tags=["smb", "users"],
                    source="smb",
                    confidence="media",
                )
            )

        signing = data.get("signing", {}) or data.get("smb_signing", {})
        if isinstance(signing, dict):
            required = signing.get("required")
            if required is False or str(required).lower() == "false":
                result.findings.append(
                    finding(
                        "MEDIO",
                        "SMB sin firma obligatoria",
                        ip,
                        f"{ip}: el servidor no exige firmado SMB.",
                        "Habilitar 'server signing = mandatory' (Samba) o exigir firma SMB en Windows.",
                        cwe=["CWE-345"],
                        tags=["smb", "misconfig"],
                        source="smb",
                        confidence="media",
                    )
                )
        if data.get("smb1") is True:
            result.findings.append(
                finding(
                    "ALTO",
                    "SMBv1 habilitado",
                    ip,
                    f"{ip}: el servidor acepta SMBv1.",
                    "Deshabilitar SMBv1 y exigir SMB2/SMB3.",
                    cwe=["CWE-1104"],
                    tags=["smb", "misconfig"],
                    source="smb",
                    confidence="alta",
                )
            )

        os_info = data.get("os_info") or data.get("os") or ""
        if os_info:
            result.meta.setdefault("os", {})[ip] = str(os_info)
