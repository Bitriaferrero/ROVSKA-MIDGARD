#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Comprobación de contraseñas filtradas con el API de HIBP.

Usa el rango de *Pwned Passwords* con k-anonymity: solo se envía al servidor
el prefijo de 5 caracteres del SHA-1 de la contraseña. La contraseña completa
nunca sale del equipo. No requiere clave de API.

La comprobación es opcional y nunca debe romper una operación: ante cualquier
error de red se devuelve ``checked=False`` con un mensaje corto.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from urllib.request import Request, urlopen

from .config import SETTINGS

API_URL = "https://api.pwnedpasswords.com/range/"
USER_AGENT = "ROVSKA-MIDGARD (auditoria autorizada)"


@dataclass(frozen=True)
class BreachResult:
    """Resultado de consultar una contraseña en el corpus de filtraciones."""

    checked: bool = False
    found: bool = False
    count: int = 0
    error: str = ""

    def to_dict(self) -> dict:
        return {
            "checked": self.checked,
            "found": self.found,
            "count": self.count,
            "error": self.error,
        }


def check_password(
    password: str,
    *,
    timeout: int | None = None,
    api_url: str | None = None,
) -> BreachResult:
    """Comprueba si ``password`` aparece en filtraciones conocidas.

    Devuelve ``found=True`` y el número de apariciones cuando existe. Si la
    consulta falla (sin red, timeout, HTTP 5xx) devuelve ``checked=False`` con
    el error para que quien llama decida cómo mostrarlo.
    """

    if not password:
        return BreachResult(error="contraseña vacía")
    settings = SETTINGS
    url_base = (api_url or settings.hibp_api or API_URL).rstrip("/") + "/"
    digest = hashlib.sha1(password.encode("utf-8", errors="replace")).hexdigest().upper()
    prefix, suffix = digest[:5], digest[5:]
    request = Request(
        url_base + prefix,
        headers={
            "User-Agent": USER_AGENT,
            "Add-Padding": "true",
        },
    )
    try:
        with urlopen(request, timeout=timeout or settings.hibp_timeout) as response:
            body = response.read().decode("ascii", errors="replace")
    except Exception as exc:  # noqa: BLE001 - la comprobación es best-effort
        return BreachResult(error=str(exc)[:200] or "error de red")

    for line in body.splitlines():
        candidate, _, raw_count = line.partition(":")
        if candidate.strip().upper() != suffix:
            continue
        try:
            count = int(raw_count.strip())
        except (TypeError, ValueError):
            count = 1
        return BreachResult(checked=True, found=count > 0, count=max(0, count))
    return BreachResult(checked=True, found=False)
