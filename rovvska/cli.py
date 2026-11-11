#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Interfaz de línea de comandos de ROVSKA.

Subcomandos::

    init         crea la base de datos y los directorios
    doctor       comprueba Docker, contenedor, herramientas y OpenCode
    scan         lanza un escaneo y genera informes
    operation    ejecuta una herramienta concreta
    orchestrate  pide un plan a OpenCode y opcionalmente lo ejecuta
    report       regenera o lista informes
    status       muestra escaneos y operaciones
    tools        catálogo de herramientas y disponibilidad
    serve        arranca el panel web
    mcp          servidor MCP por stdio (para OpenCode)
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

from . import __version__, db, orchestrator, report, scanner
from .config import SETTINGS
from .runner import get_runner
from .scope import ScopeError, check_target
from .tools import catalog, get_tool

# --- colores ANSI (se desactivan si no hay TTY o con NO_COLOR) --------------

_COLOR = sys.stdout.isatty() and not os.environ.get("NO_COLOR")


def _c(text: str, code: str) -> str:
    if not _COLOR:
        return text
    return f"\033[{code}m{text}\033[0m"


def bold(text: str) -> str:
    return _c(text, "1")


def dim(text: str) -> str:
    return _c(text, "2")


def red(text: str) -> str:
    return _c(text, "31")


def green(text: str) -> str:
    return _c(text, "32")


def yellow(text: str) -> str:
    return _c(text, "33")


def blue(text: str) -> str:
    return _c(text, "34")


def magenta(text: str) -> str:
    return _c(text, "35")


def cyan(text: str) -> str:
    return _c(text, "36")


SEV_COLOR = {
    "CRÍTICO": red,
    "ALTO": magenta,
    "MEDIO": yellow,
    "BAJO": cyan,
    "INFO": blue,
}

LEVEL_COLOR = {
    "cmd": dim,
    "info": lambda t: t,
    "ok": green,
    "done": green,
    "warn": yellow,
    "error": red,
    "start": bold,
}


def _print_event(message: str, level: str = "info") -> None:
    prefix = {
        "cmd": "  $",
        "info": "  ·",
        "ok": "  ✓",
        "done": "  ✓",
        "warn": "  !",
        "error": "  ✗",
        "start": "»",
    }.get(level, "  ·")
    color = LEVEL_COLOR.get(level, lambda t: t)
    print(color(f"{prefix} {message}"), flush=True)


def _load_json_arg(value: str | None) -> dict:
    if not value:
        return {}
    try:
        data = json.loads(value)
    except json.JSONDecodeError as exc:
        raise SystemExit(f"JSON inválido en --options: {exc}") from exc
    if not isinstance(data, dict):
        raise SystemExit("--options debe ser un objeto JSON")
    return data


# --- comandos ---------------------------------------------------------------


def cmd_init(args: argparse.Namespace) -> int:
    SETTINGS.ensure_dirs()
    db.init_db()
    print(bold("ROVSKA inicializado"))
    print(f"  base de datos : {SETTINGS.db_path}")
    print(f"  informes      : {SETTINGS.reports_dir}")
    print(f"  evidencias    : {SETTINGS.evidence_dir}")
    print(f"  trabajo       : {SETTINGS.work_dir}")
    return 0


def cmd_doctor(args: argparse.Namespace) -> int:
    SETTINGS.ensure_dirs()
    db.init_db()
    runner = get_runner(SETTINGS)
    print(bold("ROVSKA doctor"))
    print(f"  python        : {sys.version.split()[0]}")
    print(f"  runner        : {SETTINGS.runner}")
    print(f"  opencode      : {'sí' if orchestrator.opencode_available(SETTINGS) else 'no'} ({SETTINGS.opencode_model})")
    print(f"  allow_attack  : {'sí' if SETTINGS.allow_attack else 'no (dry-run)'}")

    if hasattr(runner, "status"):
        status = runner.status()
        state = green("en marcha") if status.get("running") else red("parado")
        print(f"  docker        : {state} {dim(str(status.get('image', '')))}")
        if status.get("error"):
            print(f"                  {yellow(status['error'])}")
    else:
        print("  docker        : no aplica (runner local)")

    try:
        pdf_ok = runner.available("weasyprint")
    except Exception:  # noqa: BLE001
        pdf_ok = False
    print(f"  pdf           : {'sí (weasyprint)' if pdf_ok else 'no (informe PDF no disponible)'}")

    print(bold("\nHerramientas"))
    rows = catalog(runner)
    width = max(len(row["name"]) for row in rows)
    for row in rows:
        flag = green("sí") if row.get("available") else red("no")
        attack = yellow(" [ataque]") if row["requires_attack"] else ""
        print(f"  {row['name'].ljust(width)}  {flag:>4}  {dim(row['binary'])}{attack}")
    missing = [row["name"] for row in rows if not row.get("available")]
    if missing:
        print(
            yellow(
                f"\n  {len(missing)} herramientas no disponibles. "
                "Arranca el contenedor: docker compose up -d"
            )
        )
    return 0


def cmd_scan(args: argparse.Namespace) -> int:
    options = _load_json_arg(args.options)
    if args.ports:
        options["nmap_ports"] = args.ports
    if args.top_ports:
        options["top_ports"] = args.top_ports
    if args.no_scripts:
        options["no_scripts"] = True
    if args.no_os:
        options["os_detection"] = False
    if args.snmp:
        options["snmp_udp"] = True
    if args.wordlist:
        options["wordlist"] = args.wordlist

    decision = check_target(args.target, SETTINGS, args.authorization)
    if not decision.allowed:
        print(red(f"[!] {decision.reason}"), file=sys.stderr)
        return 2
    print(bold(f"ROVSKA · escaneo {args.profile}"))
    print(f"  objetivo : {args.target}  ({decision.host_count} hosts)")
    print(f"  runner   : {SETTINGS.runner}")
    print(f"  alcance  : {decision.reason}\n")

    try:
        data = scanner.run_scan(
            args.target,
            args.profile,
            options,
            authorization=args.authorization,
            progress=_print_event,
        )
    except ScopeError as exc:
        print(red(f"[!] {exc}"), file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        print(yellow("\n[!] Interrumpido por el usuario."))
        return 130
    except Exception as exc:  # noqa: BLE001
        print(red(f"[!] Escaneo fallido: {exc}"), file=sys.stderr)
        return 1

    counts = data.get("counts", {})
    print()
    print(bold("Resultado"))
    for sev in ("CRÍTICO", "ALTO", "MEDIO", "BAJO", "INFO"):
        print(f"  {SEV_COLOR[sev](sev.ljust(8))} {counts.get(sev, 0)}")
    print(f"  riesgo   : {data.get('risk', {}).get('score', 0)}/100 ({data.get('risk', {}).get('label', '')})")
    print(f"  hosts    : {len(data.get('hosts', []))}")
    print(f"  scan_id  : {data.get('scan_id')}")
    paths = data.get("stats", {}).get("reports", {})
    if paths:
        print(bold("\nInformes"))
        for kind, path in paths.items():
            print(f"  {kind.ljust(5)} {path}")
    if args.json:
        print(json.dumps(data, ensure_ascii=False, indent=2))
    return 0


def cmd_operation(args: argparse.Namespace) -> int:
    params = _load_json_arg(args.params)
    tool = get_tool(args.tool)
    if tool is None:
        print(red(f"[!] herramienta desconocida: {args.tool}"), file=sys.stderr)
        return 2
    decision = check_target(args.target, SETTINGS, args.authorization)
    if not decision.allowed:
        print(red(f"[!] {decision.reason}"), file=sys.stderr)
        return 2
    dry_run = not args.execute
    if tool.spec.requires_attack and not SETTINGS.allow_attack:
        dry_run = True
        if args.execute:
            print(yellow("[!] ROVSKA_ALLOW_ATTACK=0: se fuerza dry-run."))

    print(bold(f"ROVSKA · operación {args.tool}"))
    print(f"  objetivo : {args.target}")
    print(f"  dry-run  : {'sí' if dry_run else 'NO'}\n")
    operation = scanner.run_operation(
        args.tool,
        args.target,
        params,
        authorization=args.authorization,
        dry_run=dry_run,
        scan_id=args.scan_id,
        progress=_print_event,
    )
    print()
    print(f"  id       : {operation.get('id')}")
    print(f"  estado   : {operation.get('status')}")
    if operation.get("error"):
        print(f"  error    : {operation['error']}")
    if args.json:
        print(json.dumps(operation, ensure_ascii=False, indent=2, default=str))
    return 0 if operation.get("status") == "done" else 1


def cmd_orchestrate(args: argparse.Namespace) -> int:
    decision = check_target(args.target, SETTINGS, args.authorization)
    if not decision.allowed:
        print(red(f"[!] {decision.reason}"), file=sys.stderr)
        return 2
    context = orchestrator.build_context(args.scan_id) if args.scan_id else None
    plan = orchestrator.plan(args.goal, args.target, context)
    print(bold("Plan propuesto"))
    print(f"  origen : {plan.get('source')}")
    if plan.get("error"):
        print(f"  aviso  : {yellow(str(plan['error']))}")
    print(f"  resumen: {plan.get('summary')}\n")
    for index, step in enumerate(plan.get("steps", []), 1):
        risk = yellow(step.get("risk", "safe"))
        print(
            f"  {index}. {bold(step.get('tool'))} → {step.get('target')} "
            f"[{risk}] dry_run={step.get('dry_run')}"
        )
        if step.get("why"):
            print(dim(f"     {step['why']}"))
    for error in plan.get("errors", []):
        print(yellow(f"  ! {error}"))
    if not args.execute:
        print(dim("\n  (plan solamente; usa --execute para lanzarlo)"))
        return 0
    print()
    results = orchestrator.execute_plan(
        plan, SETTINGS, authorization=args.authorization, scan_id=args.scan_id
    )
    for operation in results:
        print(f"  {operation.get('tool')}: {operation.get('status')}")
    return 0


def cmd_report(args: argparse.Namespace) -> int:
    if args.list or not args.scan_id:
        rows = sorted(SETTINGS.reports_dir.glob("informe_*"))
        if not rows:
            print(dim("No hay informes todavía."))
            return 0
        for path in rows:
            print(f"  {path.name}")
        return 0
    try:
        paths = report.write_reports(args.scan_id)
    except KeyError as exc:
        print(red(f"[!] {exc}"), file=sys.stderr)
        return 1
    print(bold("Informes regenerados"))
    for kind, path in paths.items():
        print(f"  {kind.ljust(5)} {path}")
    return 0


def cmd_status(args: argparse.Namespace) -> int:
    db.init_db()
    scans = db.query("SELECT * FROM scans ORDER BY started_at DESC LIMIT 20")
    print(bold("Últimos escaneos"))
    if not scans:
        print(dim("  sin escaneos"))
    for scan in scans:
        print(
            f"  {scan['started_at']}  {scan['profile'].ljust(10)} "
            f"{scan['target'].ljust(20)} {scan['status'].ljust(8)} {dim(scan['id'])}"
        )
    operations = db.query("SELECT * FROM operations ORDER BY started_at DESC LIMIT 10")
    print(bold("\nÚltimas operaciones"))
    if not operations:
        print(dim("  sin operaciones"))
    for op in operations:
        dry = "dry-run" if op["dry_run"] else "real"
        print(
            f"  {op['started_at']}  {op['tool'].ljust(14)} {op['status'].ljust(8)} "
            f"{dry.ljust(8)} {dim(op['target'])}"
        )
    return 0


def cmd_tools(args: argparse.Namespace) -> int:
    runner = get_runner(SETTINGS)
    rows = catalog(runner)
    if args.json:
        print(json.dumps(rows, ensure_ascii=False, indent=2))
        return 0
    width = max(len(row["name"]) for row in rows)
    for row in rows:
        flag = green("✓") if row.get("available") else red("✗")
        attack = yellow(" [ataque]") if row["requires_attack"] else ""
        print(f"  {flag} {row['name'].ljust(width)}  {dim(row['category'])}  {row['description']}{attack}")
    return 0


def cmd_serve(args: argparse.Namespace) -> int:
    from .api import serve

    return serve(host=args.host, port=args.port, open_browser=args.open)


def cmd_mcp(args: argparse.Namespace) -> int:
    from .mcp_server import main

    return main()


# --- parser -----------------------------------------------------------------


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="rovvska",
        description="ROVSKA — auditoría de red con MITRE ATT&CK, PTES, OSSTMM, OWASP y CWE.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Ejemplos:\n"
            "  python3 -m rovvska init\n"
            "  python3 -m rovvska doctor\n"
            "  python3 -m rovvska scan 192.168.1.0/24 --profile quick\n"
            "  python3 -m rovvska scan 10.0.0.10 --profile web --json\n"
            "  python3 -m rovvska operation nuclei --target 10.0.0.10\n"
            "  python3 -m rovvska serve --open\n"
        ),
    )
    parser.add_argument("--version", action="version", version=f"ROVSKA {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    p_init = sub.add_parser("init", help="crea la base de datos y los directorios")
    p_init.set_defaults(func=cmd_init)

    p_doctor = sub.add_parser("doctor", help="comprueba Docker, herramientas y OpenCode")
    p_doctor.set_defaults(func=cmd_doctor)

    p_scan = sub.add_parser("scan", help="lanza un escaneo")
    p_scan.add_argument("target", help="IP, CIDR o hostname autorizado")
    p_scan.add_argument(
        "--profile",
        "-p",
        default="quick",
        choices=sorted(scanner.PROFILES),
        help="perfil de escaneo (por defecto quick)",
    )
    p_scan.add_argument("--options", "-o", help="opciones extra en JSON")
    p_scan.add_argument("--ports", help="lista de puertos para nmap, p. ej. 22,80,443")
    p_scan.add_argument("--top-ports", type=int, help="número de puertos top para nmap")
    p_scan.add_argument("--wordlist", help="diccionario para ffuf")
    p_scan.add_argument("--no-scripts", action="store_true", help="desactiva scripts NSE")
    p_scan.add_argument(
        "--no-os",
        action="store_true",
        help="desactiva la detección de SO de nmap (-O)",
    )
    p_scan.add_argument(
        "--snmp",
        action="store_true",
        help="sonda UDP/161 para obtener sysDescr/versión exacta (SNMP)",
    )
    p_scan.add_argument(
        "--authorization",
        action="store_true",
        help="confirma autorización expresa (obligatorio para objetivos públicos)",
    )
    p_scan.add_argument("--json", action="store_true", help="imprime el informe JSON completo")
    p_scan.set_defaults(func=cmd_scan)

    p_op = sub.add_parser("operation", help="ejecuta una herramienta concreta")
    p_op.add_argument("tool", help="nombre de la herramienta (ver: tools)")
    p_op.add_argument("--target", "-t", required=True, help="IP, CIDR o hostname")
    p_op.add_argument("--params", help="parámetros de la herramienta en JSON")
    p_op.add_argument("--scan-id", help="asocia la operación a un escaneo")
    p_op.add_argument("--execute", action="store_true", help="ejecución real (no dry-run)")
    p_op.add_argument("--authorization", action="store_true", help="autorización expresa")
    p_op.add_argument("--json", action="store_true", help="salida JSON")
    p_op.set_defaults(func=cmd_operation)

    p_orch = sub.add_parser("orchestrate", help="plan con OpenCode y ejecución opcional")
    p_orch.add_argument("--goal", "-g", required=True, help="objetivo en lenguaje natural")
    p_orch.add_argument("--target", "-t", required=True, help="IP, CIDR o hostname")
    p_orch.add_argument("--scan-id", help="contexto de un escaneo previo")
    p_orch.add_argument("--execute", action="store_true", help="ejecuta el plan validado")
    p_orch.add_argument("--authorization", action="store_true", help="autorización expresa")
    p_orch.set_defaults(func=cmd_orchestrate)

    p_report = sub.add_parser("report", help="regenera o lista informes")
    p_report.add_argument("scan_id", nargs="?", help="id del escaneo")
    p_report.add_argument("--list", "-l", action="store_true", help="lista informes existentes")
    p_report.set_defaults(func=cmd_report)

    p_status = sub.add_parser("status", help="muestra escaneos y operaciones")
    p_status.set_defaults(func=cmd_status)

    p_tools = sub.add_parser("tools", help="catálogo de herramientas")
    p_tools.add_argument("--json", action="store_true", help="salida JSON")
    p_tools.set_defaults(func=cmd_tools)

    p_serve = sub.add_parser("serve", help="arranca el panel web")
    p_serve.add_argument("--host", help="interfaz de escucha (por defecto 127.0.0.1)")
    p_serve.add_argument("--port", type=int, help="puerto (por defecto 8780)")
    p_serve.add_argument("--open", action="store_true", help="abre el navegador")
    p_serve.set_defaults(func=cmd_serve)

    p_mcp = sub.add_parser("mcp", help="servidor MCP por stdio")
    p_mcp.set_defaults(func=cmd_mcp)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    SETTINGS.ensure_dirs()
    db.init_db()
    return int(args.func(args))


if __name__ == "__main__":
    raise SystemExit(main())
