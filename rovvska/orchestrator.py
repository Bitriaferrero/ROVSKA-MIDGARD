#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Orquestador OpenCode.

OpenCode actúa como cerebro: recibe el contexto del escaneo y propone un plan
de herramientas. ROVSKA valida el plan (herramientas registradas y objetivos
dentro de alcance) y lo ejecuta. Si OpenCode no está disponible, se usa un
plan determinista basado en el perfil.
"""

from __future__ import annotations

import json
import shutil
import subprocess
from typing import Any

from . import db, report, scanner
from .config import SETTINGS, Settings
from .scope import ScopeError, check_target
from .tools import REGISTRY, catalog


SYSTEM_RULES = """Eres el orquestador de ROVSKA, una plataforma de auditoría autorizada.
Reglas estrictas:
- Solo puedes proponer herramientas de la lista permitida.
- No inventes objetivos fuera del alcance indicado.
- Las operaciones ofensivas son dry-run salvo autorización explícita.
- Devuelve SOLO un objeto JSON válido, sin markdown ni explicaciones fuera del JSON.
"""


def opencode_available(settings: Settings | None = None) -> bool:
    settings = settings or SETTINGS
    return bool(settings.opencode_enabled and shutil.which(settings.opencode_bin))


def _run_opencode(prompt: str, settings: Settings) -> tuple[str, str]:
    argv = [
        settings.opencode_bin,
        "run",
        "--format",
        "json",
        "-m",
        settings.opencode_model,
        "--auto",
        prompt,
    ]
    try:
        proc = subprocess.run(
            argv,
            cwd=str(settings.base_dir),
            capture_output=True,
            text=True,
            errors="replace",
            timeout=settings.opencode_timeout,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired) as exc:
        return "", str(exc)
    if proc.returncode != 0:
        return proc.stdout or "", proc.stderr or f"opencode exit {proc.returncode}"
    return proc.stdout or "", ""


def _extract_text(raw: str) -> str:
    """Extrae texto de la salida JSON de OpenCode o devuelve el raw."""
    raw = (raw or "").strip()
    if not raw:
        return ""
    try:
        value = json.loads(raw)
        return _walk_text(value) or raw
    except json.JSONDecodeError:
        pass
    chunks: list[str] = []
    for line in raw.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            value = json.loads(line)
        except json.JSONDecodeError:
            chunks.append(line)
            continue
        text = _walk_text(value)
        if text:
            chunks.append(text)
    return "\n".join(chunks) if chunks else raw


def _walk_text(value: Any) -> str:
    if isinstance(value, str):
        return value
    if isinstance(value, dict):
        for key in ("text", "content", "message", "result", "output"):
            if isinstance(value.get(key), str) and value[key].strip():
                return value[key]
        for key in ("part", "data", "properties"):
            if key in value:
                text = _walk_text(value[key])
                if text:
                    return text
    if isinstance(value, list):
        parts = [_walk_text(item) for item in value]
        return "\n".join(part for part in parts if part)
    return ""


def _extract_json(text: str) -> dict | None:
    text = (text or "").strip()
    if not text:
        return None
    if text.startswith("```"):
        text = text.strip("`")
        if text.lower().startswith("json"):
            text = text[4:]
    start = text.find("{")
    end = text.rfind("}")
    if start < 0 or end <= start:
        return None
    candidate = text[start : end + 1]
    try:
        value = json.loads(candidate)
        return value if isinstance(value, dict) else None
    except json.JSONDecodeError:
        return None


def build_context(scan_id: str, limit: int = 12) -> dict:
    data = report.build(scan_id)
    hosts = []
    for host in data.get("hosts", [])[:limit]:
        hosts.append(
            {
                "ip": host.get("ip"),
                "type": host.get("type"),
                "os": host.get("os"),
                "ports": [
                    {
                        "port": p.get("port"),
                        "service": p.get("name"),
                        "product": p.get("product"),
                        "version": p.get("version"),
                    }
                    for p in host.get("ports", [])[:30]
                ],
            }
        )
    findings = [
        {
            "severity": f.get("severity"),
            "title": f.get("title"),
            "host": f.get("host"),
            "attack": f.get("attack"),
        }
        for f in data.get("findings", [])[:30]
    ]
    return {
        "target": data.get("target"),
        "profile": data.get("profile"),
        "risk": data.get("risk"),
        "counts": data.get("counts"),
        "hosts": hosts,
        "findings": findings,
        "attack": data.get("attack", {}).get("summary", {}),
    }


def plan(
    goal: str,
    target: str,
    context: dict | None = None,
    settings: Settings | None = None,
) -> dict:
    settings = settings or SETTINGS
    tools = [row for row in catalog() if not row["requires_attack"]]
    tool_lines = "\n".join(
        f"- {row['name']} ({row['category']}): {row['description']}" for row in tools
    )
    context_text = json.dumps(context or {}, ensure_ascii=False)[:12000]
    prompt = f"""{SYSTEM_RULES}

Objetivo del operador: {goal}
Alcance autorizado: {target}

Herramientas permitidas:
{tool_lines}

Contexto actual del escaneo (si existe):
{context_text}

Propón un plan de hasta 6 pasos. Formato exacto:
{{"summary":"...","steps":[{{"tool":"nmap","target":"{target}","params":{{}},"why":"...","risk":"safe"}}]}}
"""
    if not opencode_available(settings):
        return fallback_plan(goal, target, context)
    raw, error = _run_opencode(prompt, settings)
    if error:
        return {
            "source": "fallback",
            "error": error,
            "summary": "OpenCode no respondió; se usa el plan determinista.",
            **fallback_plan(goal, target, context),
        }
    text = _extract_text(raw)
    parsed = _extract_json(text)
    if not parsed or not isinstance(parsed.get("steps"), list):
        return {
            "source": "fallback",
            "error": "respuesta de OpenCode no parseable",
            "raw": text[-4000:],
            "summary": "Plan determinista por respuesta no válida del modelo.",
            **fallback_plan(goal, target, context),
        }
    return validate_plan(parsed, target, settings, source="opencode")


def validate_plan(
    plan_data: dict,
    target: str,
    settings: Settings,
    source: str = "opencode",
) -> dict:
    steps = []
    errors = []
    for step in plan_data.get("steps", [])[:10]:
        if not isinstance(step, dict):
            continue
        tool_name = str(step.get("tool", "")).strip()
        tool = REGISTRY.get(tool_name)
        if tool is None:
            errors.append(f"herramienta no permitida: {tool_name}")
            continue
        step_target = str(step.get("target") or target)
        decision = check_target(step_target, settings, authorization=False)
        if not decision.allowed:
            errors.append(f"{tool_name}: {decision.reason}")
            continue
        params = step.get("params") if isinstance(step.get("params"), dict) else {}
        steps.append(
            {
                "tool": tool_name,
                "target": step_target,
                "params": params,
                "why": str(step.get("why", ""))[:500],
                "risk": "attack" if tool.spec.requires_attack else "safe",
                "dry_run": bool(tool.spec.requires_attack and not settings.allow_attack),
            }
        )
    return {
        "source": source,
        "summary": str(plan_data.get("summary", ""))[:1000],
        "steps": steps,
        "errors": errors,
        "raw": plan_data,
    }


def fallback_plan(goal: str, target: str, context: dict | None = None) -> dict:
    context = context or {}
    profile = context.get("profile") or "deep"
    chain = scanner.PROFILES.get(profile, scanner.PROFILES["deep"])["tools"]
    steps = [
        {
            "tool": name,
            "target": target,
            "params": {},
            "why": "Paso de la cadena recomendada para el perfil actual.",
            "risk": "attack" if REGISTRY[name].spec.requires_attack else "safe",
            "dry_run": True,
        }
        for name in chain
        if name in REGISTRY
    ][:6]
    return {
        "source": "fallback",
        "summary": f"Plan determinista para «{goal}» sobre {target}.",
        "steps": steps,
        "errors": [],
    }


def execute_plan(
    plan_data: dict,
    settings: Settings | None = None,
    authorization: bool = False,
    scan_id: str | None = None,
    cancel_event=None,
) -> list[dict]:
    settings = settings or SETTINGS
    results = []
    for step in plan_data.get("steps", []):
        if cancel_event is not None and cancel_event.is_set():
            break
        tool_name = step.get("tool")
        if tool_name not in REGISTRY:
            continue
        results.append(
            scanner.run_operation(
                tool_name=tool_name,
                target=step.get("target", ""),
                params=step.get("params", {}),
                authorization=authorization,
                dry_run=bool(step.get("dry_run", True)),
                scan_id=scan_id,
                settings=settings,
            )
        )
    return results


def narrate(scan_id: str, settings: Settings | None = None) -> dict:
    settings = settings or SETTINGS
    data = report.build(scan_id)
    if not opencode_available(settings):
        return fallback_narrative(data)
    prompt = f"""{SYSTEM_RULES}

Redacta un resumen ejecutivo de esta auditoría y devuelve SOLO JSON:
{{"executive_summary":"...","key_risks":["..."],"next_steps":["..."],"confidence":"alta|media|baja"}}

Datos:
{json.dumps(build_context(scan_id), ensure_ascii=False)[:14000]}
"""
    raw, error = _run_opencode(prompt, settings)
    if error:
        result = fallback_narrative(data)
        result["error"] = error
        return result
    parsed = _extract_json(_extract_text(raw))
    if not parsed:
        result = fallback_narrative(data)
        result["error"] = "respuesta no parseable"
        return result
    return {
        "source": "opencode",
        "executive_summary": str(parsed.get("executive_summary", ""))[:4000],
        "key_risks": [str(x)[:300] for x in (parsed.get("key_risks") or [])][:10],
        "next_steps": [str(x)[:300] for x in (parsed.get("next_steps") or [])][:10],
        "confidence": str(parsed.get("confidence", "media")),
    }


def fallback_narrative(data: dict) -> dict:
    counts = data.get("counts", {})
    findings = data.get("findings", [])
    top = findings[:5]
    summary = (
        f"Se auditaron {len(data.get('hosts', []))} hosts en {data.get('target')} "
        f"con el perfil {data.get('profile')}. "
        f"Resultado: {counts.get('CRÍTICO', 0)} críticos, {counts.get('ALTO', 0)} altos, "
        f"{counts.get('MEDIO', 0)} medios y {counts.get('BAJO', 0)} bajos. "
        f"Riesgo global {data.get('risk', {}).get('label', 'sin hallazgos')}."
    )
    return {
        "source": "fallback",
        "executive_summary": summary,
        "key_risks": [f"{f.get('severity')}: {f.get('title')} ({f.get('host')})" for f in top],
        "next_steps": [
            "Priorizar los hallazgos CRÍTICO/ALTO y validar explotabilidad con el equipo responsable.",
            "Revisar la matriz ATT&CK y la cadena de ataque para cerrar vectores de acceso.",
            "Repetir el escaneo tras aplicar parches para verificar la reducción de riesgo.",
        ],
        "confidence": "media",
    }
