#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Control de alcance (scope) y autorización.

Regla de oro: ROVSKA solo debe tocar redes propias o con autorización expresa.
Por defecto se permiten rangos privados; los públicos requieren
``ROVSKA_ALLOW_PUBLIC=1`` y ``authorization=true`` en la petición.
"""

from __future__ import annotations

import ipaddress
import re
import socket
from dataclasses import dataclass, field

from .config import Settings


class ScopeError(ValueError):
    """Objetivo fuera de alcance o con formato no permitido."""


PRIVATE_NETWORKS = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("100.64.0.0/10"),
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fc00::/7"),
    ipaddress.ip_network("fe80::/10"),
]

SAFE_TARGET_RE = re.compile(r"^[A-Za-z0-9_.:/,\-\[\]]+$")


@dataclass
class ScopeDecision:
    allowed: bool
    reason: str
    target: str
    networks: list[ipaddress._BaseNetwork] = field(default_factory=list)
    resolved: list[str] = field(default_factory=list)
    public: bool = False
    host_count: int = 0

    def to_dict(self) -> dict:
        return {
            "allowed": self.allowed,
            "reason": self.reason,
            "target": self.target,
            "networks": [str(n) for n in self.networks],
            "resolved": list(self.resolved),
            "public": self.public,
            "host_count": self.host_count,
        }


def _parse_network(value: str) -> ipaddress._BaseNetwork:
    try:
        if "/" in value:
            return ipaddress.ip_network(value, strict=False)
        ip = ipaddress.ip_address(value)
        return ipaddress.ip_network(f"{ip}/{ip.max_prefixlen}", strict=False)
    except ValueError as exc:
        raise ScopeError(f"objetivo inválido: {value}") from exc


def _is_private(net: ipaddress._BaseNetwork) -> bool:
    return any(
        net.version == private.version and (net.subnet_of(private) or net == private)
        for private in PRIVATE_NETWORKS
    )


def _allowed_by_config(net: ipaddress._BaseNetwork, settings: Settings) -> bool:
    for raw in settings.allowed_cidrs:
        try:
            allowed = ipaddress.ip_network(raw, strict=False)
        except ValueError:
            continue
        if net.version == allowed.version and (
            net.subnet_of(allowed) or net == allowed
        ):
            return True
    return False


def _resolve_hostname(hostname: str) -> list[str]:
    try:
        infos = socket.getaddrinfo(hostname, None, proto=socket.IPPROTO_TCP)
    except socket.gaierror as exc:
        raise ScopeError(f"no se pudo resolver el nombre: {hostname}") from exc
    ips = sorted({info[4][0] for info in infos})
    if not ips:
        raise ScopeError(f"el nombre no resuelve a ninguna IP: {hostname}")
    return ips


def check_target(
    target: str,
    settings: Settings,
    authorization: bool = False,
) -> ScopeDecision:
    """Valida un objetivo (IP, CIDR o hostname) y devuelve la decisión."""

    target = (target or "").strip()
    if not target:
        raise ScopeError("el objetivo está vacío")
    if len(target) > 512:
        raise ScopeError("el objetivo es demasiado largo")
    if not SAFE_TARGET_RE.match(target):
        raise ScopeError("el objetivo contiene caracteres no permitidos")

    networks: list[ipaddress._BaseNetwork] = []
    resolved: list[str] = []
    public = False
    host_count = 0

    for part in [p.strip() for p in target.split(",") if p.strip()]:
        if "/" in part or _looks_like_ip(part):
            net = _parse_network(part)
            networks.append(net)
            host_count += max(1, net.num_addresses if net.prefixlen < net.max_prefixlen else 1)
            if not _is_private(net):
                public = True
        else:
            ips = _resolve_hostname(part)
            resolved.extend(ips)
            host_count += 1
            for ip_text in ips:
                ip = ipaddress.ip_address(ip_text)
                net = ipaddress.ip_network(f"{ip}/{ip.max_prefixlen}", strict=False)
                networks.append(net)
                if not _is_private(net):
                    public = True

    if not networks:
        raise ScopeError("no se pudo interpretar el objetivo")

    if public:
        if not settings.allow_public:
            return ScopeDecision(
                False,
                "objetivo público bloqueado: activa ROVSKA_ALLOW_PUBLIC solo con autorización",
                target,
                networks,
                resolved,
                True,
                host_count,
            )
        if not authorization:
            return ScopeDecision(
                False,
                "objetivo público: se requiere authorization=true y autorización expresa",
                target,
                networks,
                resolved,
                True,
                host_count,
            )

    if settings.allowed_cidrs:
        for net in networks:
            if _is_private(net):
                continue
            if not _allowed_by_config(net, settings):
                return ScopeDecision(
                    False,
                    f"la red {net} no está en ROVSKA_ALLOWED_CIDRS",
                    target,
                    networks,
                    resolved,
                    public,
                    host_count,
                )

    if host_count > settings.max_hosts:
        return ScopeDecision(
            False,
            f"el objetivo expande {host_count} hosts; el máximo es {settings.max_hosts}",
            target,
            networks,
            resolved,
            public,
            host_count,
        )

    return ScopeDecision(
        True,
        "dentro de alcance",
        target,
        networks,
        resolved,
        public,
        host_count,
    )


def assert_target(target: str, settings: Settings, authorization: bool = False) -> ScopeDecision:
    decision = check_target(target, settings, authorization)
    if not decision.allowed:
        raise ScopeError(decision.reason)
    return decision


def _looks_like_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def expand_hosts(target: str, limit: int = 4096) -> list[str]:
    """Expande IPs/CIDR a una lista de IPs (sin resolver hostnames)."""
    hosts: list[str] = []
    for part in [p.strip() for p in target.split(",") if p.strip()]:
        try:
            if "/" in part:
                net = ipaddress.ip_network(part, strict=False)
                for ip in net.hosts():
                    hosts.append(str(ip))
                    if len(hosts) >= limit:
                        return hosts
            else:
                hosts.append(str(ipaddress.ip_address(part)))
        except ValueError:
            hosts.append(part)
    return hosts
