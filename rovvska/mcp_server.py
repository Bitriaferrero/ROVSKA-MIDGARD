#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Servidor MCP de ROVSKA (stdio, JSON-RPC 2.0).

Expone el arsenal y los informes a OpenCode. Ejemplo de configuración en
``opencode.jsonc``::

    {
      "mcp": {
        "rovska": {
          "type": "local",
          "command": ["python3", "-m", "rovvska.mcp_server"],
          "enabled": true,
          "environment": {"PYTHONPATH": "/home/USUARIO/ROVSKA"}
        }
      }
    }
"""

from __future__ import annotations

import json
import sys
import traceback
from typing import Any

from . import db, orchestrator, report, scanner
from .config import SETTINGS
from .scope import check_target
from .tools import REGISTRY, catalog, get_tool


PROTOCOL_VERSION = "2024-11-05"
SERVER_INFO = {"name": "rovska", "version": "1.0.0"}


TOOLS = [
    {
        "name": "rovska_scan",
        "description": "Lanza un escaneo ROVSKA (síncrono). Perfiles: discovery, quick, full, web, infra, deep, attack.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "target": {"type": "string", "description": "IP, CIDR o hostname autorizado"},
                "profile": {"type": "string", "default": "quick"},
                "authorization": {"type": "boolean", "default": False},
                "options": {"type": "object", "default": {}},
            },
            "required": ["target"],
        },
    },
    {
        "name": "rovska_scan_status",
        "description": "Resumen de un escaneo por id.",
        "inputSchema": {
            "type": "object",
            "properties": {"scan_id": {"type": "string"}},
            "required": ["scan_id"],
        },
    },
    {
        "name": "rovska_findings",
        "description": "Lista hallazgos, opcionalmente filtrados por severidad y host.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "scan_id": {"type": "string"},
                "severity": {"type": "string"},
                "host": {"type": "string"},
                "limit": {"type": "integer", "default": 100},
            },
            "required": ["scan_id"],
        },
    },
    {
        "name": "rovska_attack_matrix",
        "description": "Matriz MITRE ATT&CK agregada de un escaneo.",
        "inputSchema": {
            "type": "object",
            "properties": {"scan_id": {"type": "string"}},
            "required": ["scan_id"],
        },
    },
    {
        "name": "rovska_kill_chain",
        "description": "Cadena de ataque reconstruida paso a paso.",
        "inputSchema": {
            "type": "object",
            "properties": {"scan_id": {"type": "string"}},
            "required": ["scan_id"],
        },
    },
    {
        "name": "rovska_run_tool",
        "description": "Ejecuta una herramienta registrada. Dry-run por defecto; las ofensivas requieren ROVSKA_ALLOW_ATTACK=1.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "tool": {"type": "string"},
                "target": {"type": "string"},
                "params": {"type": "object", "default": {}},
                "dry_run": {"type": "boolean", "default": True},
                "authorization": {"type": "boolean", "default": False},
            },
            "required": ["tool", "target"],
        },
    },
    {
        "name": "rovska_tools",
        "description": "Catálogo de herramientas y disponibilidad en el runner actual.",
        "inputSchema": {"type": "object", "properties": {}},
    },
    {
        "name": "rovska_scope_check",
        "description": "Comprueba si un objetivo está dentro del alcance configurado.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "target": {"type": "string"},
                "authorization": {"type": "boolean", "default": False},
            },
            "required": ["target"],
        },
    },
    {
        "name": "rovska_report",
        "description": "Genera los informes JSON/XML/HTML/SARIF/CSV de un escaneo.",
        "inputSchema": {
            "type": "object",
            "properties": {"scan_id": {"type": "string"}},
            "required": ["scan_id"],
        },
    },
    {
        "name": "rovska_plan",
        "description": "Pide a OpenCode un plan de auditoría validado para un objetivo.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "goal": {"type": "string"},
                "target": {"type": "string"},
                "scan_id": {"type": "string"},
            },
            "required": ["goal", "target"],
        },
    },
    {
        "name": "rovska_narrate",
        "description": "Resumen ejecutivo de un escaneo (OpenCode o fallback determinista).",
        "inputSchema": {
            "type": "object",
            "properties": {"scan_id": {"type": "string"}},
            "required": ["scan_id"],
        },
    },
]


def _ok(text: str) -> dict:
    return {"content": [{"type": "text", "text": text}], "isError": False}


def _err(text: str) -> dict:
    return {"content": [{"type": "text", "text": text}], "isError": True}


def _json(value: Any) -> dict:
    return _ok(json.dumps(value, ensure_ascii=False, indent=2))


def call_tool(name: str, arguments: dict) -> dict:
    if name == "rovska_scan":
        target = str(arguments.get("target", ""))
        profile = str(arguments.get("profile", "quick"))
        authorization = bool(arguments.get("authorization"))
        options = arguments.get("options") if isinstance(arguments.get("options"), dict) else {}
        decision = check_target(target, SETTINGS, authorization)
        if not decision.allowed:
            return _err(decision.reason)
        data = scanner.run_scan(target, profile, options, authorization)
        return _json(
            {
                "scan_id": data["scan_id"],
                "target": data["target"],
                "profile": data["profile"],
                "risk": data["risk"],
                "counts": data["counts"],
                "hosts": len(data["hosts"]),
                "findings": len(data["findings"]),
                "attack_unique": data["attack"]["matrix"]["unique"],
                "reports": data["stats"].get("reports", {}),
            }
        )
    if name == "rovska_scan_status":
        data = report.build(str(arguments.get("scan_id", "")))
        return _json(
            {
                "scan_id": data["scan_id"],
                "target": data["target"],
                "status": data["status"],
                "risk": data["risk"],
                "counts": data["counts"],
                "hosts": len(data["hosts"]),
                "findings": len(data["findings"]),
            }
        )
    if name == "rovska_findings":
        data = report.build(str(arguments.get("scan_id", "")))
        severity = str(arguments.get("severity", "")).upper()
        host = str(arguments.get("host", ""))
        limit = int(arguments.get("limit", 100))
        findings = [
            f
            for f in data["findings"]
            if (not severity or f["severity"] == severity) and (not host or f["host"] == host)
        ][:limit]
        return _json(findings)
    if name == "rovska_attack_matrix":
        data = report.build(str(arguments.get("scan_id", "")))
        return _json(data["attack"]["matrix"])
    if name == "rovska_kill_chain":
        data = report.build(str(arguments.get("scan_id", "")))
        return _json(data["attack"]["kill_chain"])
    if name == "rovska_run_tool":
        tool_name = str(arguments.get("tool", ""))
        if tool_name not in REGISTRY:
            return _err(f"herramienta desconocida: {tool_name}")
        target = str(arguments.get("target", ""))
        decision = check_target(target, SETTINGS, bool(arguments.get("authorization")))
        if not decision.allowed:
            return _err(decision.reason)
        operation = scanner.run_operation(
            tool_name,
            target,
            arguments.get("params") if isinstance(arguments.get("params"), dict) else {},
            bool(arguments.get("authorization")),
            bool(arguments.get("dry_run", True)),
        )
        return _json(operation)
    if name == "rovska_tools":
        return _json(catalog())
    if name == "rovska_scope_check":
        return _json(
            check_target(
                str(arguments.get("target", "")),
                SETTINGS,
                bool(arguments.get("authorization")),
            ).to_dict()
        )
    if name == "rovska_report":
        paths = report.write_reports(str(arguments.get("scan_id", "")))
        return _json(paths)
    if name == "rovska_plan":
        scan_id = str(arguments.get("scan_id", ""))
        context = orchestrator.build_context(scan_id) if scan_id else None
        return _json(
            orchestrator.plan(
                str(arguments.get("goal", "")),
                str(arguments.get("target", "")),
                context,
            )
        )
    if name == "rovska_narrate":
        return _json(orchestrator.narrate(str(arguments.get("scan_id", ""))))
    return _err(f"herramienta MCP desconocida: {name}")


def handle(request: dict) -> dict | None:
    method = request.get("method", "")
    request_id = request.get("id")
    if method == "initialize":
        return {
            "jsonrpc": "2.0",
            "id": request_id,
            "result": {
                "protocolVersion": PROTOCOL_VERSION,
                "capabilities": {"tools": {"listChanged": False}},
                "serverInfo": SERVER_INFO,
            },
        }
    if method in {"notifications/initialized", "notifications/cancelled"}:
        return None
    if method == "ping":
        return {"jsonrpc": "2.0", "id": request_id, "result": {}}
    if method == "tools/list":
        return {"jsonrpc": "2.0", "id": request_id, "result": {"tools": TOOLS}}
    if method == "tools/call":
        params = request.get("params") or {}
        try:
            result = call_tool(str(params.get("name", "")), params.get("arguments") or {})
        except Exception as exc:  # noqa: BLE001
            result = _err(f"{exc}\n{traceback.format_exc()[-1200:]}")
        return {"jsonrpc": "2.0", "id": request_id, "result": result}
    if request_id is None:
        return None
    return {
        "jsonrpc": "2.0",
        "id": request_id,
        "error": {"code": -32601, "message": f"método no soportado: {method}"},
    }


def main() -> int:
    db.init_db()
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            request = json.loads(line)
        except json.JSONDecodeError:
            print(
                json.dumps(
                    {
                        "jsonrpc": "2.0",
                        "id": None,
                        "error": {"code": -32700, "message": "JSON inválido"},
                    }
                ),
                flush=True,
            )
            continue
        response = handle(request)
        if response is not None:
            print(json.dumps(response, ensure_ascii=False), flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
