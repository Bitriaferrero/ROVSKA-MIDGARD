#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Registro de herramientas de ROVSKA."""

from __future__ import annotations

from .base import Tool, ToolContext, ToolSpec
from .nmap import NmapTool
from .arp_scan import ArpScanTool
from .masscan import MasscanTool
from .http_probe import HttpProbeTool
from .whatweb import WhatWebTool
from .nikto import NiktoTool
from .nuclei import NucleiTool
from .testssl import TestSslTool
from .ssh_audit import SshAuditTool
from .smb import SmbTool
from .snmp import SnmpTool
from .dns import DnsTool
from .web_fuzz import WebFuzzTool
from .hydra import HydraTool
from .metasploit import MetasploitTool
from .searchsploit import SearchsploitTool


_TOOL_CLASSES: list[type[Tool]] = [
    NmapTool,
    ArpScanTool,
    MasscanTool,
    HttpProbeTool,
    WhatWebTool,
    NiktoTool,
    NucleiTool,
    TestSslTool,
    SshAuditTool,
    SmbTool,
    SnmpTool,
    DnsTool,
    WebFuzzTool,
    HydraTool,
    MetasploitTool,
    SearchsploitTool,
]

REGISTRY: dict[str, Tool] = {cls.spec.name: cls() for cls in _TOOL_CLASSES}


def get_tool(name: str) -> Tool | None:
    return REGISTRY.get(name)


def tool_names() -> list[str]:
    return sorted(REGISTRY)


def catalog(runner=None) -> list[dict]:
    rows = []
    for name in tool_names():
        tool = REGISTRY[name]
        spec = tool.spec
        row = {
            "name": spec.name,
            "binary": spec.binary,
            "category": spec.category,
            "description": spec.description,
            "phase": spec.phase,
            "requires_attack": spec.requires_attack,
            "profiles": list(spec.profiles),
            "attack": list(spec.attack),
        }
        if runner is not None:
            try:
                row["available"] = tool.available(runner)
            except Exception:  # noqa: BLE001
                row["available"] = False
        rows.append(row)
    return rows


__all__ = [
    "REGISTRY",
    "Tool",
    "ToolContext",
    "ToolSpec",
    "catalog",
    "get_tool",
    "tool_names",
]
