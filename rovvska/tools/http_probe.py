#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Sonda HTTP/HTTPS integrada (sin dependencias).

Obtiene cabeceras, título, redirecciones y cookies de los servicios web
detectados. Sirve como base cuando WhatWeb/Nikto no están disponibles.
"""

from __future__ import annotations

import html
import re
import ssl
import urllib.error
import urllib.request

from ..models import Finding, Host
from .base import Tool, ToolContext, ToolResult, ToolSpec, finding, http_urls


TITLE_RE = re.compile(r"<title[^>]*>(.*?)</title>", re.IGNORECASE | re.DOTALL)
SECURITY_HEADERS = {
    "strict-transport-security": "HSTS",
    "content-security-policy": "CSP",
    "x-content-type-options": "X-Content-Type-Options",
    "x-frame-options": "X-Frame-Options",
    "referrer-policy": "Referrer-Policy",
    "permissions-policy": "Permissions-Policy",
}


class HttpProbeTool(Tool):
    spec = ToolSpec(
        name="http_probe",
        binary="python3",
        category="web",
        description="Cabeceras, título, redirecciones y cookies de servicios web.",
        phase="recon",
        profiles=("quick", "web", "deep", "attack"),
        attack=("T1592.002",),
    )

    def available(self, runner) -> bool:
        return True

    def run(self, ctx: ToolContext) -> ToolResult:
        result = ToolResult(tool=self.name)
        for host in list(ctx.hosts):
            for url in http_urls(host):
                data = self._probe(url)
                if not data:
                    continue
                port_number = _port_from_url(url)
                port = next((p for p in host.ports if p.port == port_number), None)
                if port is None:
                    continue
                port.scripts["http-headers"] = data["headers_text"]
                if data["title"]:
                    port.scripts["http-title"] = data["title"]
                if data["server"]:
                    port.scripts["http-server-header"] = data["server"]
                port.extrainfo = port.extrainfo or data["server"]
                self._analyze(host, port_number, data, result)
        return result

    def _probe(self, url: str) -> dict | None:
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        request = urllib.request.Request(
            url,
            method="GET",
            headers={
                "User-Agent": "ROVSKA/1.0 (auditoria autorizada)",
                "Accept": "text/html,application/xhtml+xml,*/*;q=0.8",
            },
        )
        try:
            with urllib.request.urlopen(request, timeout=6, context=context) as response:
                body = response.read(65536).decode("utf-8", errors="replace")
                headers = dict(response.headers.items())
                return {
                    "url": url,
                    "status": response.status,
                    "headers": {k.lower(): v for k, v in headers.items()},
                    "headers_text": "\n" + "\n".join(f"  {k}: {v}" for k, v in headers.items()) + "\n",
                    "server": headers.get("Server", ""),
                    "title": _title(body),
                    "body": body,
                }
        except urllib.error.HTTPError as exc:
            body = exc.read(32768).decode("utf-8", errors="replace") if exc.fp else ""
            headers = dict(exc.headers.items()) if exc.headers else {}
            return {
                "url": url,
                "status": exc.code,
                "headers": {k.lower(): v for k, v in headers.items()},
                "headers_text": "\n" + "\n".join(f"  {k}: {v}" for k, v in headers.items()) + "\n",
                "server": headers.get("Server", ""),
                "title": _title(body),
                "body": body,
            }
        except (urllib.error.URLError, TimeoutError, ssl.SSLError, ValueError):
            return None

    def _analyze(self, host: Host, port: int, data: dict, result: ToolResult) -> None:
        headers = data["headers"]
        server = data.get("server", "")
        url = data["url"]
        missing = [
            label
            for header, label in SECURITY_HEADERS.items()
            if header not in headers and not (header == "strict-transport-security" and port not in {443, 8443})
        ]
        if missing:
            result.findings.append(
                finding(
                    "BAJO",
                    "Cabeceras de seguridad HTTP ausentes",
                    host.ip,
                    f"{url}: faltan {', '.join(missing)}.",
                    "Añadir HSTS, CSP, X-Content-Type-Options, X-Frame-Options, "
                    "Referrer-Policy y Permissions-Policy en el servidor web.",
                    tags=["web", "misconfig"],
                    source="http_probe",
                    confidence="alta",
                )
            )
        if server and re.search(r"\d+\.\d+", server):
            result.findings.append(
                finding(
                    "INFO",
                    "Divulgación de versión en cabecera Server",
                    host.ip,
                    f"{url} responde Server: {server}.",
                    "Minimizar la cabecera Server o usar una versión sin número visible.",
                    tags=["web", "info-disclosure"],
                    source="http_probe",
                    confidence="alta",
                )
            )
        if data["title"] and re.search(
            r"(router|admin|login|panel|config|dashboard|proxmox|mikrotik|zte)",
            data["title"],
            re.IGNORECASE,
        ):
            result.findings.append(
                finding(
                    "INFO",
                    "Panel de administración accesible",
                    host.ip,
                    f"{url} → «{data['title']}» (HTTP {data['status']}).",
                    "Restringir el panel a la LAN de gestión, exigir MFA y revisar credenciales por defecto.",
                    tags=["web", "info-disclosure"],
                    source="http_probe",
                    confidence="media",
                )
            )


def _title(body: str) -> str:
    match = TITLE_RE.search(body or "")
    if not match:
        return ""
    text = re.sub(r"\s+", " ", html.unescape(match.group(1))).strip()
    return text[:160]


def _port_from_url(url: str) -> int:
    try:
        from urllib.parse import urlparse

        parsed = urlparse(url)
        if parsed.port:
            return parsed.port
        return 443 if parsed.scheme == "https" else 80
    except ValueError:
        return 80
