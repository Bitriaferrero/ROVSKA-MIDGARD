"""Auditoría estática de MIDGARD: comprueba que el runtime es offline.

No es criptografía ni una garantía absoluta: es una comprobación
reproducible de que el código no importa clientes de IA, no usa sockets
directos y no contiene endpoints de telemetría.
"""

from __future__ import annotations

import re
from pathlib import Path

from .config import PACKAGE_DIR


FORBIDDEN_MODULES = {
    "requests",
    "httpx",
    "urllib",
    "urllib3",
    "aiohttp",
    "http",  # http.client
    "socket",
    "openai",
    "anthropic",
    "litellm",
    "cohere",
    "google.generativeai",
    "tensorflow",
    "torch",
    "transformers",
}

FORBIDDEN_ENDPOINTS = (
    "api.openai.com",
    "api.anthropic.com",
    "generativelanguage.googleapis.com",
    "api.cohere.ai",
    "api.mistral.ai",
    "sentry.io",
    "posthog.com",
    "segment.io",
    "google-analytics.com",
)

IMPORT_RE = re.compile(r"^\s*(?:import|from)\s+([A-Za-z_][\w.]*)", re.MULTILINE)


def audit(package_dir: Path | None = None) -> dict:
    directory = package_dir or PACKAGE_DIR
    findings: list[dict] = []
    files = sorted(directory.glob("*.py"))

    for path in files:
        if path.name == "audit.py":
            continue
        text = path.read_text(encoding="utf-8", errors="replace")
        for module in sorted(set(IMPORT_RE.findall(text))):
            root = module.split(".")[0]
            if root in FORBIDDEN_MODULES or module in FORBIDDEN_MODULES:
                findings.append(
                    {
                        "file": path.name,
                        "kind": "import",
                        "value": module,
                        "line": _line_of(text, module),
                    }
                )
        lower = text.lower()
        for endpoint in FORBIDDEN_ENDPOINTS:
            if endpoint in lower:
                findings.append(
                    {
                        "file": path.name,
                        "kind": "endpoint",
                        "value": endpoint,
                        "line": _line_of(text, endpoint),
                    }
                )

    return {
        "ok": not findings,
        "files_scanned": len(files),
        "findings": findings,
    }


def _line_of(text: str, needle: str) -> int:
    index = text.lower().find(needle.lower())
    if index < 0:
        return 0
    return text.count("\n", 0, index) + 1
