"""Validación de alcance.

Regla por defecto: solo redes privadas (RFC1918), loopback y enlace local.
Un objetivo público exige `--authorized` y `MIDGARD_ALLOW_PUBLIC=1`, y no
puede ser un rango enorme.
"""

from __future__ import annotations

import ipaddress
from typing import Iterable

from . import config


class ScopeError(ValueError):
    """El objetivo no cumple la política de alcance de MIDGARD."""


# Rangos considerados locales/privados.
_PRIVATE_NETS = (
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("fc00::/7"),
    ipaddress.ip_network("fe80::/10"),
    ipaddress.ip_network("::1/128"),
)


def parse_target(target: str) -> ipaddress._BaseNetwork:
    """Convierte IP o CIDR en una red de `ipaddress`.

    Se rechazan hostnames para no depender de DNS y para que el alcance
    sea siempre explícito y verificable.
    """
    value = (target or "").strip()
    if not value:
        raise ScopeError("objetivo vacío")
    if value.startswith("-"):
        raise ScopeError("el objetivo no puede empezar por '-'")
    if any(ch in value for ch in " ;|&$`\\\"'\n\r\t"):
        raise ScopeError("el objetivo contiene caracteres no permitidos")
    try:
        return ipaddress.ip_network(value, strict=False)
    except ValueError as exc:
        raise ScopeError(
            f"objetivo no válido: {value!r}. Usa una IP o un CIDR, por ejemplo 192.168.1.0/24"
        ) from exc


def is_private(net: ipaddress._BaseNetwork) -> bool:
    if net.is_loopback or net.is_link_local or net.is_private:
        return True
    if net.version == 4 and net.subnet_of(ipaddress.ip_network("169.254.0.0/16")):
        return True
    return any(net.version == p.version and net.subnet_of(p) for p in _PRIVATE_NETS)


def validate(target: str, authorized: bool = False) -> ipaddress._BaseNetwork:
    """Valida el objetivo y devuelve la red normalizada."""
    net = parse_target(target)

    if net.is_multicast or net.is_unspecified:
        raise ScopeError(f"objetivo no permitido: {net}")

    if is_private(net):
        return net

    # A partir de aquí el objetivo es público.
    if not authorized:
        raise ScopeError(
            f"{net} no es una red privada. Añade --authorized solo si tienes "
            "autorización escrita del propietario."
        )
    if not config.allow_public():
        raise ScopeError(
            "objetivo público bloqueado: define MIDGARD_ALLOW_PUBLIC=1 además "
            "de --authorized."
        )
    if net.prefixlen < 24 and net.version == 4:
        raise ScopeError(
            f"rango público demasiado amplio ({net}). Usa como máximo un /24."
        )
    if net.prefixlen < 120 and net.version == 6:
        raise ScopeError(
            f"rango público demasiado amplio ({net}). Usa como máximo un /120."
        )
    return net


def describe(net: ipaddress._BaseNetwork) -> str:
    """Texto legible para mostrar en consola/informes."""
    if net.num_addresses == 1:
        return str(net.network_address)
    return str(net)


def expand_hosts(net: ipaddress._BaseNetwork, limit: int = 4096) -> Iterable[str]:
    """Expande una red pequeña; útil para pasarla a Metasploit."""
    if net.num_addresses > limit:
        return []
    return [str(ip) for ip in net.hosts()]
