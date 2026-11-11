#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Metodologías y marcos de referencia: PTES, OSSTMM, OWASP y CWE.

Cada hallazgo se enriquece con su fase PTES, canal/módulo OSSTMM, categoría
OWASP (Top 10 + WSTG) y debilidad CWE. El objetivo es que el informe no sea
solo una lista de puertos, sino una auditoría trazable.
"""

from __future__ import annotations

from collections import Counter

from .models import Finding


PTES_PHASES = [
    ("pre-engagement", "Pre-engagement Interactions", "Alcance, reglas de juego y autorización."),
    ("intelligence-gathering", "Intelligence Gathering", "Reconocimiento pasivo y activo."),
    ("threat-modeling", "Threat Modeling", "Modelado de amenazas y activos."),
    ("vulnerability-analysis", "Vulnerability Analysis", "Identificación y validación de vulnerabilidades."),
    ("exploitation", "Exploitation", "Explotación controlada y prueba de credenciales."),
    ("post-exploitation", "Post-Exploitation", "Impacto, persistencia y movimiento lateral."),
    ("reporting", "Reporting", "Informe, evidencia y recomendaciones."),
]

OSSTMM_CHANNELS = {
    "Human Security": ["HUM-SEC", "HUM-SOC"],
    "Physical Security": ["PHY-SEC"],
    "Wireless Communications": ["WIR-SEC", "WIR-COM"],
    "Telecommunications": ["TEL-SEC", "TEL-COM"],
    "Data Networks": ["NET-SEC", "NET-COM", "NET-APP"],
}

OSSTMM_MODULES = {
    "HUM-SEC": "Seguridad humana",
    "HUM-SOC": "Ingeniería social",
    "PHY-SEC": "Seguridad física",
    "WIR-SEC": "Seguridad inalámbrica",
    "WIR-COM": "Comunicaciones inalámbricas",
    "TEL-SEC": "Seguridad de telecomunicaciones",
    "TEL-COM": "Comunicaciones de telecomunicaciones",
    "NET-SEC": "Seguridad de redes de datos",
    "NET-COM": "Comunicaciones de redes de datos",
    "NET-APP": "Aplicaciones en red",
}

OWASP_TOP10 = {
    "A01": "A01:2021 – Broken Access Control",
    "A02": "A02:2021 – Cryptographic Failures",
    "A03": "A03:2021 – Injection",
    "A04": "A04:2021 – Insecure Design",
    "A05": "A05:2021 – Security Misconfiguration",
    "A06": "A06:2021 – Vulnerable and Outdated Components",
    "A07": "A07:2021 – Identification and Authentication Failures",
    "A08": "A08:2021 – Software and Data Integrity Failures",
    "A09": "A09:2021 – Security Logging and Monitoring Failures",
    "A10": "A10:2021 – Server-Side Request Forgery (SSRF)",
}

WSTG = {
    "WSTG-INFO": "Information Gathering",
    "WSTG-CONF": "Configuration and Deployment Management Testing",
    "WSTG-IDNT": "Identity Management Testing",
    "WSTG-ATHN": "Authentication Testing",
    "WSTG-ATHZ": "Authorization Testing",
    "WSTG-SESS": "Session Management Testing",
    "WSTG-INPV": "Input Validation Testing",
    "WSTG-ERRH": "Error Handling",
    "WSTG-CRYP": "Cryptography",
    "WSTG-BUSL": "Business Logic Testing",
    "WSTG-CLNT": "Client-Side Testing",
    "WSTG-APIT": "API Testing",
}

CWE = {
    "CWE-16": "Configuration",
    "CWE-20": "Improper Input Validation",
    "CWE-22": "Path Traversal",
    "CWE-78": "OS Command Injection",
    "CWE-79": "Cross-site Scripting (XSS)",
    "CWE-89": "SQL Injection",
    "CWE-94": "Code Injection",
    "CWE-119": "Buffer Overflow",
    "CWE-200": "Exposure of Sensitive Information",
    "CWE-250": "Execution with Unnecessary Privileges",
    "CWE-269": "Improper Privilege Management",
    "CWE-284": "Improper Access Control",
    "CWE-287": "Improper Authentication",
    "CWE-295": "Improper Certificate Validation",
    "CWE-306": "Missing Authentication for Critical Function",
    "CWE-319": "Cleartext Transmission of Sensitive Information",
    "CWE-326": "Inadequate Encryption Strength",
    "CWE-327": "Use of a Broken or Risky Cryptographic Algorithm",
    "CWE-352": "Cross-Site Request Forgery (CSRF)",
    "CWE-400": "Uncontrolled Resource Consumption",
    "CWE-434": "Unrestricted Upload of File with Dangerous Type",
    "CWE-444": "Inconsistent Interpretation of HTTP Requests",
    "CWE-502": "Deserialization of Untrusted Data",
    "CWE-521": "Weak Password Requirements",
    "CWE-601": "URL Redirection to Untrusted Site",
    "CWE-611": "Improper Restriction of XML External Entity Reference",
    "CWE-668": "Exposure of Resource to Wrong Sphere",
    "CWE-693": "Protection Mechanism Failure",
    "CWE-798": "Use of Hard-coded Credentials",
    "CWE-918": "Server-Side Request Forgery (SSRF)",
    "CWE-1021": "Improper Restriction of Rendered UI Layers",
    "CWE-1104": "Use of Unmaintained Third Party Components",
    "CWE-1188": "Insecure Default Initialization of Resource",
    "CWE-1321": "Improperly Controlled Modification of Object Prototype Attributes",
    "CWE-1392": "Use of Default Credentials",
    "CWE-1393": "Use of Default Password",
}

SOURCE_PTES = {
    "nmap": "intelligence-gathering",
    "masscan": "intelligence-gathering",
    "arp_scan": "intelligence-gathering",
    "http_probe": "intelligence-gathering",
    "whatweb": "intelligence-gathering",
    "dns": "intelligence-gathering",
    "snmp": "intelligence-gathering",
    "smb": "intelligence-gathering",
    "ssh_audit": "vulnerability-analysis",
    "nikto": "vulnerability-analysis",
    "nuclei": "vulnerability-analysis",
    "testssl": "vulnerability-analysis",
    "searchsploit": "vulnerability-analysis",
    "web_fuzz": "vulnerability-analysis",
    "hydra": "exploitation",
    "metasploit": "exploitation",
    "heuristic": "vulnerability-analysis",
}


def _text(finding: Finding) -> str:
    return f"{finding.title} {finding.evidence} {' '.join(finding.tags)}".lower()


def _ptes_phase(finding: Finding) -> str:
    tags = {t.lower() for t in finding.tags}
    text = _text(finding)
    if any(k in tags for k in ("exploit", "brute-force", "valid-accounts", "default-creds")):
        return "exploitation"
    if any(k in text for k in ("explot", "credencial válida", "login correcto", "vulnerable")):
        return "exploitation"
    if any(k in tags for k in ("recon", "port-scan", "service-version")):
        return "intelligence-gathering"
    if any(
        k in text
        for k in (
            "vulnerab",
            "cve-",
            "eol",
            "fin de vida",
            "desactualiz",
            "outdated",
            "ausente",
            "misconfig",
            "exposici",
            "débil",
            "debil",
            "sin soporte",
            "backdoor",
            "obsolet",
        )
    ):
        return "vulnerability-analysis"
    if any(k in tags for k in ("smb", "shares", "users", "snmp", "dns")):
        return "intelligence-gathering"
    return SOURCE_PTES.get((finding.source or "").lower(), "vulnerability-analysis")


def _osstmm(finding: Finding) -> tuple[str, str]:
    text = _text(finding)
    tags = {t.lower() for t in finding.tags}
    if any(k in text for k in ("wifi", "wlan", "wireless", "802.11")):
        return "Wireless Communications", "WIR-SEC"
    if any(k in text for k in ("web", "http", "tls", "ssl", "owasp", "xss", "sql")) or "web" in tags:
        return "Data Networks", "NET-APP"
    if any(k in text for k in ("dns", "snmp", "smb", "ssh", "rdp", "puerto", "servicio")):
        return "Data Networks", "NET-SEC"
    return "Data Networks", "NET-COM"


def _owasp(finding: Finding) -> tuple[list[str], list[str]]:
    text = _text(finding)
    tags = {t.lower() for t in finding.tags}
    top: list[str] = []
    wstg: list[str] = []

    if any(k in text for k in ("xss", "cross-site", "inyección", "injection", "sql", "comando")):
        top.append("A03")
        wstg.append("WSTG-INPV")
    if any(k in text for k in ("autentic", "login", "contraseña", "credencial", "password")):
        top.append("A07")
        wstg.append("WSTG-ATHN")
    if any(k in text for k in ("acceso", "autorización", "permiso", "idor", "directory traversal")):
        top.append("A01")
        wstg.append("WSTG-ATHZ")
    if any(k in text for k in ("tls", "ssl", "certificado", "cifrado", "crypto", "cleartext", "http sin")):
        top.append("A02")
        wstg.append("WSTG-CRYP")
    if any(k in text for k in ("config", "cabecera", "header", "por defecto", "default", "exposici")):
        top.append("A05")
        wstg.append("WSTG-CONF")
    if any(k in text for k in ("versión", "version", "eol", "desactualiz", "outdated", "componente")):
        top.append("A06")
        wstg.append("WSTG-CONF")
    if any(k in text for k in ("ssrf", "server-side request")):
        top.append("A10")
        wstg.append("WSTG-INPV")
    if any(k in text for k in ("integridad", "deserial", "supply chain", "firma")):
        top.append("A08")
    if any(k in text for k in ("log", "monitor", "auditoría")):
        top.append("A09")
        wstg.append("WSTG-ERRH")
    if any(k in text for k in ("diseño", "lógica", "business logic")):
        top.append("A04")
        wstg.append("WSTG-BUSL")
    if any(k in text for k in ("directorio", "fichero", "archivo", "path", "fuzzing")):
        wstg.append("WSTG-INFO")

    if "web" in tags and not top:
        top.append("A05")
        wstg.append("WSTG-CONF")
    return sorted(set(top)), sorted(set(wstg))


def _cwe(finding: Finding) -> list[str]:
    if finding.cwe:
        return list(finding.cwe)
    text = _text(finding)
    tags = {t.lower() for t in finding.tags}
    found: list[str] = []
    if "xss" in text or "cross-site" in text:
        found.append("CWE-79")
    if "sql" in text and "inyección" in text:
        found.append("CWE-89")
    if "command injection" in text or "inyección de comando" in text:
        found.append("CWE-78")
    if "path traversal" in text or "directory traversal" in text:
        found.append("CWE-22")
    if "ssrf" in text:
        found.append("CWE-918")
    if "open redirect" in text or "redirección" in text:
        found.append("CWE-601")
    if "csrf" in text:
        found.append("CWE-352")
    if "deserial" in text:
        found.append("CWE-502")
    if "certificado" in text or "certificate" in text:
        found.append("CWE-295")
    if any(k in text for k in ("tls", "ssl", "cifrado débil", "weak cipher", "cleartext")):
        found.append("CWE-327")
    if any(k in text for k in ("sin autenticación", "sin login", "anonymous", "unauth")):
        found.append("CWE-306")
    if any(k in text for k in ("credencial", "contraseña", "password")) and any(
        k in text for k in ("por defecto", "default", "débil", "debil", "válida")
    ):
        found.append("CWE-1392")
    if any(k in text for k in ("eol", "fin de vida", "desactualiz", "outdated")):
        found.append("CWE-1104")
    if any(k in text for k in ("exposici", "información", "banner", "versión", "version")):
        found.append("CWE-200")
    if any(k in text for k in ("config", "cabecera", "header", "por defecto", "default")):
        found.append("CWE-16")
    if any(k in text for k in ("acceso", "permiso", "autorización")):
        found.append("CWE-284")
    if "web" in tags and not found:
        found.append("CWE-16")
    if any(k in tags for k in ("database", "docker", "kubernetes", "smb", "rdp", "vnc")):
        found.append("CWE-668")
    return sorted(set(found)) or ["CWE-693"]


def enrich(finding: Finding) -> dict:
    """Devuelve y asigna el bloque de marcos de un hallazgo."""
    if finding.frameworks:
        return finding.frameworks
    ptes = _ptes_phase(finding)
    channel, module = _osstmm(finding)
    top10, wstg = _owasp(finding)
    cwe = _cwe(finding)
    if not finding.cwe:
        finding.cwe = cwe
    finding.frameworks = {
        "ptes": {
            "phase": ptes,
            "name": next((name for pid, name, _ in PTES_PHASES if pid == ptes), ptes),
        },
        "osstmm": {
            "channel": channel,
            "module": module,
            "name": OSSTMM_MODULES.get(module, module),
        },
        "owasp": {
            "top10": top10,
            "top10_names": [OWASP_TOP10.get(item, item) for item in top10],
            "wstg": wstg,
        },
        "cwe": cwe,
    }
    return finding.frameworks


def summary(findings: list[Finding]) -> dict:
    ptes: Counter[str] = Counter()
    osstmm: Counter[str] = Counter()
    owasp: Counter[str] = Counter()
    cwe: Counter[str] = Counter()
    wstg: Counter[str] = Counter()
    for finding in findings:
        data = enrich(finding)
        ptes[data["ptes"]["phase"]] += 1
        osstmm[data["osstmm"]["module"]] += 1
        for item in data["owasp"]["top10"]:
            owasp[item] += 1
        for item in data["owasp"]["wstg"]:
            wstg[item] += 1
        for item in data["cwe"]:
            cwe[item] += 1
    return {
        "ptes": [
            {
                "id": pid,
                "name": name,
                "description": desc,
                "count": ptes.get(pid, 0),
            }
            for pid, name, desc in PTES_PHASES
        ],
        "osstmm": {
            "channels": [
                {
                    "name": channel,
                    "modules": [
                        {"id": mod, "name": OSSTMM_MODULES.get(mod, mod), "count": osstmm.get(mod, 0)}
                        for mod in modules
                    ],
                }
                for channel, modules in OSSTMM_CHANNELS.items()
            ],
            "counts": dict(osstmm.most_common()),
        },
        "owasp": {
            "top10": [
                {"id": oid, "name": name, "count": owasp.get(oid, 0)}
                for oid, name in OWASP_TOP10.items()
            ],
            "wstg": [
                {"id": wid, "name": name, "count": wstg.get(wid, 0)}
                for wid, name in WSTG.items()
            ],
        },
        "cwe": [
            {"id": cid, "name": CWE.get(cid, ""), "count": count}
            for cid, count in cwe.most_common()
        ],
    }
