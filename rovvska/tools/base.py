#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Base común de los adaptadores de herramientas."""

from __future__ import annotations

import json
import threading
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable

from ..config import Settings
from ..models import Finding, Host, Port, ToolResult
from ..runner import Cancelled, CommandResult, Runner


@dataclass(frozen=True)
class ToolSpec:
    name: str
    binary: str
    category: str
    description: str
    phase: str = "recon"
    requires_attack: bool = False
    profiles: tuple[str, ...] = ()
    attack: tuple[str, ...] = ()


@dataclass
class ToolContext:
    runner: Runner
    target: str
    workdir: Path
    options: dict = field(default_factory=dict)
    log: Callable[[str, str], None] = lambda message, level="info": None
    scan_id: str = ""
    operation_id: str = ""
    timeout: int = 900
    settings: Settings | None = None
    hosts: list[Host] = field(default_factory=list)
    cancel_event: threading.Event | None = None

    def run(
        self,
        argv: list[str],
        timeout: int | None = None,
        env: dict[str, str] | None = None,
        input_text: str | None = None,
    ) -> CommandResult:
        self.log("$ " + " ".join(argv), "cmd")
        result = self.runner.run(
            argv,
            timeout=timeout or self.timeout,
            cwd=self.workdir,
            env=env,
            input_text=input_text,
            cancel_event=self.cancel_event,
        )
        if result.cancelled:
            raise Cancelled("cancelado por el usuario")
        return result

    def path(self, name: str) -> Path:
        return self.workdir / name

    def info(self, message: str) -> None:
        self.log(message, "info")

    def warn(self, message: str) -> None:
        self.log(message, "warn")

    def error(self, message: str) -> None:
        self.log(message, "error")


class Tool:
    """Adaptador de una herramienta externa."""

    spec: ToolSpec

    @property
    def name(self) -> str:
        return self.spec.name

    def available(self, runner: Runner) -> bool:
        return runner.available(self.spec.binary)

    def run(self, ctx: ToolContext) -> ToolResult:
        raise NotImplementedError

    def missing(self, ctx: ToolContext) -> ToolResult:
        message = (
            f"{self.spec.binary} no está disponible en el runner '{ctx.runner.name}'. "
            "Se omite esta herramienta."
        )
        ctx.warn(message)
        return ToolResult(tool=self.name, ok=False, skipped=True, error=message)

    def result(self, **kwargs) -> ToolResult:
        return ToolResult(tool=self.name, **kwargs)


# --- utilidades compartidas ------------------------------------------------


def read_json(path: Path) -> object:
    try:
        return json.loads(path.read_text(encoding="utf-8", errors="replace"))
    except (OSError, json.JSONDecodeError):
        return None


def read_json_lines(path: Path) -> list[dict]:
    rows: list[dict] = []
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return rows
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            value = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(value, dict):
            rows.append(value)
    return rows


def http_urls(host: Host, extra_ports: tuple[int, ...] = (80, 443, 8080, 8443)) -> list[str]:
    urls: list[str] = []
    for port in host.ports:
        number = port.port
        service = (port.service or "").lower()
        product = (port.product or "").lower()
        if number not in extra_ports and service not in {"http", "https", "http-alt", "http-proxy", "ssl/http"}:
            continue
        if number in {443, 8443} or service in {"https", "ssl/http"} or "ssl" in product:
            urls.append(f"https://{host.ip}:{number}")
        else:
            urls.append(f"http://{host.ip}:{number}")
    return urls


def finding(
    severity: str,
    title: str,
    host: str,
    evidence: str,
    recommendation: str,
    *,
    cves: list[str] | None = None,
    cwe: list[str] | None = None,
    attack: list[str] | None = None,
    tags: list[str] | None = None,
    source: str = "heuristic",
    confidence: str = "media",
) -> Finding:
    return Finding(
        severity=severity,
        title=title,
        host=host,
        evidence=evidence,
        recommendation=recommendation,
        cves=cves or [],
        cwe=cwe or [],
        attack=attack or [],
        tags=tags or [],
        source=source,
        confidence=confidence,
    )


def host_for(hosts: list[Host], ip: str) -> Host:
    for host in hosts:
        if host.ip == ip:
            return host
    host = Host(ip=ip)
    hosts.append(host)
    return host


def port_for(host: Host, number: int, proto: str = "tcp") -> Port | None:
    for port in host.ports:
        if port.port == number and port.proto == proto:
            return port
    return None
