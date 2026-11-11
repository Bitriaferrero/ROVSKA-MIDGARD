#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""testssl.sh: configuración TLS/SSL."""

from __future__ import annotations

from ..models import normalize_severity
from .base import Tool, ToolContext, ToolResult, ToolSpec, finding, http_urls, read_json


# testssl emite una fila por cifrado y por metadato. Incluirlas todas convierte
# el informe en ruido (decenas de hallazgos "offered"), así que se filtran y se
# conservan solo las comprobaciones accionables.
SKIP_IDS = {
    "engine_problem",
    "cert_notAfter",
    "DNS_CAArecord",
    "security_headers",
    "cipher_order",
    "fs",
    "service",
    "protocols",
}
SKIP_PREFIXES = ("cipher-tls", "cipher_")

TITLES = {
    "cipherlist_OBSOLETED": "Cifrados TLS obsoletos ofrecidos",
    "cipherlist_LOW": "Cifrados TLS débiles ofrecidos",
    "cipherlist_EXPORT": "Cifrados de exportación ofrecidos",
    "cipherlist_NULL": "Cifrados nulos ofrecidos",
    "cipherlist_aNULL": "Cifrados anónimos ofrecidos",
    "cipherlist_3DES_IDEA": "Cifrados 3DES/IDEA ofrecidos",
    "HSTS": "HSTS no configurado",
    "overall_grade": "Calificación TLS global",
    "cert_chain_of_trust": "Certificado TLS no confiable",
    "cert_trust": "Certificado TLS no coincide con el dominio",
    "cert_subjectAltName": "Certificado TLS sin SAN",
    "cert_revocation": "Certificado TLS sin CRL/OCSP",
    "cert_expirationStatus": "Certificado TLS próximo a expirar",
    "heartbleed": "Vulnerable a Heartbleed (CVE-2014-0160)",
    "CCS": "Vulnerable a CCS injection (CVE-2014-0224)",
    "ROBOT": "Vulnerable a ROBOT",
    "LUCKY13": "Potencialmente vulnerable a Lucky13 (CVE-2013-0169)",
    "POODLE_SSL": "Vulnerable a POODLE",
    "CRIME_TLS": "Vulnerable a CRIME",
    "BREACH": "Potencialmente vulnerable a BREACH",
    "ticketbleed": "Vulnerable a Ticketbleed",
    "secure_client_renego": "Renegociación TLS insegura",
    "fallback_SCSV": "Fallback SCSV no soportado",
}

CWE_BY_ID = {
    "cipherlist_OBSOLETED": ["CWE-327"],
    "cipherlist_LOW": ["CWE-327"],
    "cipherlist_EXPORT": ["CWE-327"],
    "cipherlist_NULL": ["CWE-327"],
    "cipherlist_aNULL": ["CWE-327"],
    "cipherlist_3DES_IDEA": ["CWE-327"],
    "HSTS": ["CWE-319"],
    "cert_chain_of_trust": ["CWE-295"],
    "cert_trust": ["CWE-295"],
    "cert_subjectAltName": ["CWE-295"],
    "cert_revocation": ["CWE-299"],
    "cert_expirationStatus": ["CWE-298"],
    "LUCKY13": ["CWE-327"],
    "POODLE_SSL": ["CWE-327"],
    "CRIME_TLS": ["CWE-327"],
}

PROTOCOL_IDS = {
    "SSLv2": ("Protocolo TLS obsoleto habilitado: SSLv2", "ALTO"),
    "SSLv3": ("Protocolo TLS obsoleto habilitado: SSLv3", "ALTO"),
    "TLS1": ("Protocolo TLS obsoleto habilitado: TLS 1.0", "MEDIO"),
    "TLS1_1": ("Protocolo TLS obsoleto habilitado: TLS 1.1", "MEDIO"),
}


class TestSslTool(Tool):
    spec = ToolSpec(
        name="testssl",
        binary="testssl",
        category="tls",
        description="Análisis de protocolos, cifrados, certificados y CVEs TLS.",
        phase="vuln",
        profiles=("web", "deep", "attack"),
        attack=("T1595.002", "T1557"),
    )

    def run(self, ctx: ToolContext) -> ToolResult:
        if not self.available(ctx.runner):
            return self.missing(ctx)
        result = ToolResult(tool=self.name)
        for host in ctx.hosts:
            urls = [u for u in http_urls(host) if u.startswith("https://")]
            for url in urls[:4]:
                self._scan(ctx, host.ip, url, result)
        return result

    def _scan(self, ctx: ToolContext, ip: str, url: str, result: ToolResult) -> None:
        out = ctx.path(f"testssl_{_safe(url)}.json")
        argv = [
            "testssl",
            "--jsonfile",
            out.name,
            "--quiet",
            "--color",
            "0",
            "--severity",
            "LOW",
            url,
        ]
        cmd = ctx.run(argv, timeout=min(ctx.timeout, 600))
        data = read_json(out)
        if data is None:
            if cmd.returncode not in (0, 1):
                ctx.warn(f"testssl falló para {url}: {cmd.output[-300:]}")
            return
        entries = data.get("scanResult", []) if isinstance(data, dict) else data
        if isinstance(entries, dict):
            entries = [entries]
        for entry in entries or []:
            if not isinstance(entry, dict):
                continue
            self._add_entry(ip, url, entry, result)

    def _add_entry(self, ip: str, url: str, entry: dict, result: ToolResult) -> None:
        ident = str(entry.get("id", "")).strip()
        detail = str(entry.get("finding", "") or "").strip()
        raw_sev = str(entry.get("severity", "")).upper()
        if not ident or raw_sev in {"OK", "INFO"}:
            return
        if ident in SKIP_IDS or ident.startswith(SKIP_PREFIXES):
            return
        if not detail or detail == "--":
            return

        title = None
        severity = normalize_severity(raw_sev, "BAJO")
        if ident in PROTOCOL_IDS:
            if detail.lower() != "offered":
                return
            title, severity = PROTOCOL_IDS[ident]
        elif ident == "HSTS":
            if "not offered" not in detail.lower():
                return
            title = TITLES[ident]
        elif ident in TITLES:
            title = TITLES[ident]
            if ident == "overall_grade":
                title = f"{TITLES[ident]}: {detail}"
        elif raw_sev in {"CRITICAL", "HIGH", "MEDIUM"}:
            # CVE/defecto desconocido pero relevante: se conserva con contexto.
            title = f"TLS: {detail[:100]}"
        else:
            return

        cwe = entry.get("cwe")
        if isinstance(cwe, str):
            cwes = [cwe] if cwe.upper().startswith("CWE-") else []
        elif isinstance(cwe, list):
            cwes = [str(item) for item in cwe if str(item).upper().startswith("CWE-")]
        else:
            cwes = []
        cwes = cwes or CWE_BY_ID.get(ident, [])

        cve = entry.get("cve")
        cves = []
        if isinstance(cve, str) and cve.upper().startswith("CVE-"):
            cves = [cve]
        elif isinstance(cve, list):
            cves = [str(item) for item in cve if str(item).upper().startswith("CVE-")]

        result.findings.append(
            finding(
                severity,
                title,
                ip,
                f"{url}: {detail} (testssl {raw_sev}).",
                "Deshabilitar protocolos y cifrados obsoletos, renovar el certificado "
                "y aplicar las recomendaciones de testssl.sh.",
                cves=cves,
                cwe=cwes,
                tags=["tls", "vuln-scan"],
                source="testssl",
                confidence="alta",
            )
        )


def _safe(value: str) -> str:
    return "".join(c if c.isalnum() else "_" for c in value)[:60]
