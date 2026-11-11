"""Interfaz de línea de comandos y menú interactivo de MIDGARD."""

from __future__ import annotations

import argparse
import json
import os
import platform
import re
import shlex
import sys
import webbrowser
from pathlib import Path

from . import __version__, audit, config, docker, evidence, hostprobe, msf, nmap, osdetect, profiles, report, scope, snmp
from .nmap import NmapError
from .profiles import ProfileError


def _banner() -> None:
    print(f"MIDGARD {__version__} · auditoría determinista · sin IA en runtime")


def _ok(text: str) -> None:
    print(f"[ok]   {text}")


def _warn(text: str) -> None:
    print(f"[aviso] {text}")


def _err(text: str) -> None:
    print(f"[error] {text}")


def _ai_env_present() -> list[str]:
    keys = []
    for name in os.environ:
        upper = name.upper()
        if any(token in upper for token in ("OPENAI", "ANTHROPIC", "GEMINI", "MISTRAL", "GROQ", "TOGETHER")):
            keys.append(name)
    return sorted(keys)


# ---------------------------------------------------------------------------
# doctor
# ---------------------------------------------------------------------------


def cmd_doctor(args) -> int:
    _banner()
    core_ok = True

    _ok(f"python {platform.python_version()} en {platform.system()}")

    available, detail = docker.docker_available()
    if available:
        _ok(f"docker {detail}")
    else:
        _err(f"docker: {detail}")
        core_ok = False

    image = config.docker_image()
    info = docker.image_info(image) if available else {}
    if info.get("id"):
        _ok(f"imagen {image} ({info['id'][:19]}…)")
    else:
        _err(f"imagen {image}: {info.get('error', 'no disponible')}")
        core_ok = False

    name = config.docker_container()
    if docker.container_running(name):
        _ok(f"contenedor {name} en ejecución")
    else:
        _warn(f"contenedor {name} no está en ejecución (MIDGARD usa contenedores efímeros)")

    if available and info.get("id"):
        nmap_result = docker.run_quick(["/usr/bin/nmap", "--version"], timeout=60)
        version = nmap.nmap_version_from_text(nmap_result.stdout + nmap_result.stderr)
        if nmap_result.ok and version:
            _ok(f"nmap {version}")
        else:
            _err("nmap no responde dentro de la imagen")
            core_ok = False

        if not args.skip_msf:
            msf_result = docker.run_quick(["/usr/bin/msfconsole", "--version"], timeout=120)
            if msf_result.ok:
                first = (msf_result.stdout or msf_result.stderr).strip().splitlines()
                _ok(f"msfconsole {first[0] if first else 'presente'}")
            else:
                _warn("msfconsole no responde (los planes .rc se generan igualmente)")

    directory = config.evidence_dir()
    try:
        directory.mkdir(parents=True, exist_ok=True)
        probe = directory / ".write-test"
        probe.write_text("ok", encoding="utf-8")
        probe.unlink()
        _ok(f"evidencias en {directory}")
    except OSError as exc:
        _err(f"no se puede escribir en {directory}: {exc}")
        core_ok = False

    _ok("capacidades de contenedor: NET_RAW, NET_ADMIN")
    _ok("IA en runtime: no")
    _ok("telemetría: no")
    _ok("actualizaciones remotas: no")

    ai_keys = _ai_env_present()
    if ai_keys:
        _warn(
            "hay variables de IA en el entorno, pero MIDGARD no las lee: "
            + ", ".join(ai_keys)
        )
    else:
        _ok("sin variables de IA en el entorno")

    result = audit.audit()
    if result["ok"]:
        _ok(f"código sin imports de red/IA ({result['files_scanned']} ficheros)")
    else:
        _err(f"auditoría del código con {len(result['findings'])} hallazgo(s)")
        core_ok = False

    return 0 if core_ok else 1


# ---------------------------------------------------------------------------
# perfiles
# ---------------------------------------------------------------------------


def cmd_profiles(args) -> int:
    _banner()
    try:
        items = profiles.load_all()
    except ProfileError as exc:
        _err(str(exc))
        return 1
    for profile in items.values():
        print(f"\n  {profile.id:<10} {profile.label}")
        print(f"             {profile.description}")
        if profile.ports_tcp:
            print(f"             TCP: {profile.ports_tcp}")
        if profile.ports_udp:
            print(f"             UDP: {profile.ports_udp}")
        if profile.scripts:
            print(f"             NSE: {', '.join(profile.scripts)}")
    print("\n  Usa: midgard scan <IP|CIDR> --profile <id>")
    return 0


# ---------------------------------------------------------------------------
# scan
# ---------------------------------------------------------------------------


def _prepare_scan(args):
    net = scope.validate(args.target, authorized=getattr(args, "authorized", False))
    profile = profiles.get(args.profile)
    ports = (args.ports or "").strip() or None
    scripts = nmap.validate_scripts(args.scripts) if (args.scripts or "").strip() else None
    nmap_args = nmap.build_nmap_args(
        scope.describe(net),
        profile,
        ports=ports,
        scripts=scripts,
        os_detection=False if args.no_os else None,
        no_ping=args.no_ping,
        udp=True if args.udp else None,
    )
    return net, profile, nmap_args


def _safe_container_name(run_id: str) -> str:
    name = "midgard-" + re.sub(r"[^A-Za-z0-9_.-]+", "-", run_id)
    return name[:120].strip("-") or "midgard-run"


def cmd_scan(args) -> int:
    _banner()
    try:
        net, profile, nmap_args = _prepare_scan(args)
    except (scope.ScopeError, ProfileError, NmapError) as exc:
        _err(str(exc))
        return 2

    target = scope.describe(net)
    snmp_community = "public"
    if getattr(args, "snmp", False):
        try:
            snmp_community = snmp.validate_community(getattr(args, "snmp_community", "public"))
        except snmp.SnmpError as exc:
            _err(str(exc))
            return 2
    image = config.docker_image()
    preview_name = "midgard-preview"
    preview = docker.build_docker_argv(
        image,
        ["/usr/bin/nmap"] + nmap_args,
        name=preview_name,
    )

    print(f"  objetivo : {target}")
    print(f"  perfil   : {profile.id} ({profile.label})")
    print(f"  imagen   : {image}")
    print(f"  comando  : {shlex.join(preview)}")
    print()

    if args.dry_run:
        _ok("dry-run: no se ha ejecutado nada")
        return 0

    if not args.yes:
        if not sys.stdin.isatty():
            _err("sin terminal interactiva; añade --yes para ejecutar")
            return 2
        answer = input("¿Ejecutar este escaneo? [s/N] ").strip().lower()
        if answer not in {"s", "si", "sí", "y", "yes"}:
            print("Cancelado.")
            return 0

    run_dir = evidence.new_run(target, profile.id)
    container_name = _safe_container_name(run_dir.name)
    timeout = int(args.timeout or profile.timeout)

    (run_dir / "command.txt").write_text(
        "\n".join(
            [
                f"# MIDGARD {__version__}",
                f"# target: {target}",
                f"# profile: {profile.id}",
                f"# date: {evidence.now_iso()}",
                "# argv:",
                shlex.join(preview),
                "",
            ]
        ),
        encoding="utf-8",
    )

    version_result = docker.run_quick(["/usr/bin/nmap", "--version"], timeout=60)
    nmap_version = nmap.nmap_version_from_text(version_result.stdout + version_result.stderr)

    print(f"  ejecutando nmap (límite {timeout}s)…", flush=True)

    def _on_stderr(line: str) -> None:
        stripped = line.rstrip()
        if stripped:
            print(f"  {stripped}", flush=True)

    result = docker.run_container(
        image,
        ["/usr/bin/nmap"] + nmap_args,
        name=container_name,
        timeout=timeout,
        on_stderr=_on_stderr if args.verbose else None,
    )

    status = "ok"
    if result.timed_out:
        status = "timeout"
    elif result.returncode != 0:
        status = "error"

    xml_text = result.stdout or ""
    (run_dir / "nmap.xml").write_text(xml_text, encoding="utf-8")
    (run_dir / "nmap.stderr.txt").write_text(result.stderr or "", encoding="utf-8")

    meta = {
        "target": target,
        "profile": profile.id,
        "run_id": run_dir.name,
        "created_at": evidence.now_iso(),
        "operator": config.operator(),
        "status": status,
        "nmap_version": nmap_version,
        "docker_image": image,
        "image_id": (docker.image_info(image) or {}).get("id", ""),
        "argv": nmap_args,
        "returncode": result.returncode,
        "duration_seconds": round(result.duration, 2),
        "timed_out": result.timed_out,
    }

    if not xml_text.strip():
        meta["error"] = "nmap no devolvió XML"
        evidence.write_manifest(run_dir, meta)
        _err("nmap no devolvió XML. Revisa nmap.stderr.txt")
        print(f"  evidencia: {run_dir}")
        return 1

    try:
        hosts = nmap.parse_xml(xml_text)
    except NmapError as exc:
        meta["error"] = str(exc)
        evidence.write_manifest(run_dir, meta)
        _err(f"no se pudo parsear el XML: {exc}")
        print(f"  evidencia: {run_dir}")
        return 1

    snmp_data = {}
    if getattr(args, "snmp", False):
        print("  sonda SNMPv2c (sysDescr)…", flush=True)
        snmp_data = snmp.probe_hosts(hosts, snmp_community)
        evidence.write_json(run_dir / "snmp.json", snmp_data)
        meta["snmp"] = {
            "enabled": True,
            "community": snmp_data["community"],
            "targets": snmp_data["targets"],
            "responded": snmp_data["responded"],
        }
        if not snmp_data["targets"]:
            _warn("no hay hosts con UDP/161 ni routers MikroTik que sondear")
        elif not snmp_data["responded"]:
            _warn("SNMP no respondió en ningún host (UDP/161 cerrado o comunidad distinta)")

    if profile.os and not getattr(args, "no_os", False):
        print("  sonda TTL para afinar el SO…", flush=True)
        probed = hostprobe.probe_ttl(hosts)
        if probed:
            print(f"  TTL obtenido en {probed}/{len(hosts)} hosts", flush=True)

    osdetect.detect_all(hosts)
    open_ports = sum(len(host.open_ports) for host in hosts)

    meta["finished_at"] = evidence.now_iso()
    meta["counts"] = {"hosts": len(hosts), "open_ports": open_ports}

    report.print_summary(hosts)
    report.write_json(run_dir, hosts, meta)
    report.write_csv(run_dir, hosts)
    report.write_html(run_dir, hosts, meta)
    evidence.write_manifest(run_dir, meta)

    print()
    _ok(f"evidencia: {run_dir}")
    _ok(f"informe:   {run_dir / 'report.html'}")
    _ok(f"manifiesto:{run_dir / 'manifest.json'}")
    if status != "ok":
        _warn(f"el escaneo terminó con estado {status}")
        return 1
    return 0


# ---------------------------------------------------------------------------
# listado / consulta / informe
# ---------------------------------------------------------------------------


def cmd_ls(args) -> int:
    _banner()
    runs = evidence.list_runs()
    if not runs:
        print("  No hay ejecuciones todavía.")
        return 0
    print(f"\n  {'RUN':<46} {'OBJETIVO':<18} {'PERFIL':<10} {'HOSTS':>5}  ESTADO")
    for run in runs:
        print(
            f"  {run['run_id']:<46} {run['target']:<18} {run['profile']:<10} "
            f"{run['hosts']:>5}  {run['status']}"
        )
    return 0


def _load_run(run_id: str):
    run_dir = evidence.run_path(run_id)
    path = run_dir / "hosts.json"
    if not path.is_file():
        raise FileNotFoundError(f"{run_id} no tiene hosts.json")
    payload = json.loads(path.read_text(encoding="utf-8"))
    hosts = [nmap.Host.from_dict(item) for item in payload.get("hosts", [])]
    return run_dir, payload.get("meta", {}), hosts


def cmd_show(args) -> int:
    _banner()
    try:
        _, meta, hosts = _load_run(args.run_id)
    except (FileNotFoundError, ValueError, json.JSONDecodeError) as exc:
        _err(str(exc))
        return 1

    print(f"  objetivo: {meta.get('target', '?')} · perfil: {meta.get('profile', '?')}")
    print(f"  estado:   {meta.get('status', '?')} · {meta.get('created_at', '')}\n")
    report.print_summary(hosts)

    if args.details:
        for host in hosts:
            os_info = host.os or {}
            print(f"\n  {host.ip} · {os_info.get('name', '?')} {os_info.get('version', '')}")
            for candidate in os_info.get("candidates", []):
                print(
                    f"    - {candidate.get('name')} {candidate.get('version', '')} "
                    f"[{candidate.get('score')}] {', '.join(candidate.get('sources', []))}"
                )
            for port in host.open_ports:
                print(f"    {port.port}/{port.proto} {port.label}")
    return 0


def cmd_report(args) -> int:
    _banner()
    try:
        run_dir, meta, hosts = _load_run(args.run_id)
    except (FileNotFoundError, ValueError, json.JSONDecodeError) as exc:
        _err(str(exc))
        return 1

    path = run_dir / "report.html"
    if args.regenerate or not path.is_file():
        path = report.write_html(run_dir, hosts, meta)
        _ok(f"informe regenerado: {path}")
    else:
        _ok(f"informe: {path}")

    if args.open:
        webbrowser.open(path.resolve().as_uri())
    return 0


def cmd_msf(args) -> int:
    _banner()
    if args.action not in {"plan", "run"}:
        _err("acción no soportada")
        return 2
    try:
        run_dir, meta, hosts = _load_run(args.run_id)
    except (FileNotFoundError, ValueError, json.JSONDecodeError) as exc:
        _err(str(exc))
        return 1

    try:
        path = msf.write_plan(run_dir, hosts)
    except msf.RCSafetyError as exc:
        _err(f"plan rechazado: {exc}")
        return 2
    evidence.refresh_manifest(run_dir)
    grouped = msf.collect(hosts)

    if args.action == "plan":
        _ok(f"plan generado: {path}")
        if not grouped:
            _warn("no hay puertos que mapear a módulos auxiliary")
        else:
            print(f"  módulos: {len(grouped)}")
            for module, ips in grouped.items():
                print(f"    {module} -> {', '.join(ips)}")
        print("\n  Para ejecutarlo manualmente (revisa antes el alcance):")
        print(f"  {msf.docker_command(run_dir)}")
        print("\n  MIDGARD no lo ejecuta solo y no incluye exploits.")
        return 0

    # action == "run"
    _ok(f"plan validado (solo auxiliary): {path}")
    if not grouped:
        _warn("no hay módulos auxiliary que ejecutar")
        return 1
    if not config.allow_msf():
        _err(
            "ejecución de Metasploit desactivada. "
            "Exporta MIDGARD_ALLOW_MSF=1 y repite el comando."
        )
        return 2

    target = str(meta.get("target", ""))
    try:
        net = scope.validate(target, authorized=getattr(args, "authorized", False))
    except scope.ScopeError as exc:
        _err(f"alcance no válido para ejecutar: {exc}")
        return 2

    timeout = int(getattr(args, "timeout", 0) or 900)
    preview = docker.build_docker_argv(
        config.docker_image(),
        ["/usr/bin/msfconsole", "-q", "-n", "--no-readline", "-r", "/out/msf_plan.rc"],
        name="midgard-msf-preview",
        extra=["-v", f"{run_dir.resolve()}:/out:ro"],
    )
    print(f"  objetivo : {scope.describe(net)}")
    print(f"  módulos  : {len(grouped)}")
    for module, ips in grouped.items():
        print(f"    {module} -> {', '.join(ips)}")
    print(f"  comando  : {shlex.join(preview)}")
    print()

    if getattr(args, "dry_run", False):
        _ok("dry-run: plan validado, no se ejecutó Metasploit")
        return 0

    if not getattr(args, "yes", False):
        if not sys.stdin.isatty():
            _err("sin terminal interactiva; añade --yes para ejecutar")
            return 2
        answer = input("¿Ejecutar Metasploit con este plan? [s/N] ").strip().lower()
        if answer not in {"s", "si", "sí", "y", "yes"}:
            print("Cancelado.")
            return 0

    print(f"  ejecutando msfconsole (timeout {timeout}s)…", flush=True)
    started = evidence.now_iso()
    try:
        result = msf.run_plan(run_dir, timeout=timeout)
    except msf.RCSafetyError as exc:
        _err(f"plan rechazado: {exc}")
        return 2

    (run_dir / "msf_run.log").write_text(result.stdout or "", encoding="utf-8")
    (run_dir / "msf_run.stderr.txt").write_text(result.stderr or "", encoding="utf-8")
    status = "timeout" if result.timed_out else ("ok" if result.ok else "error")
    summary = {
        "run_id": run_dir.name,
        "target": scope.describe(net),
        "started_at": started,
        "finished_at": evidence.now_iso(),
        "status": status,
        "returncode": result.returncode,
        "duration_seconds": round(result.duration, 2),
        "timed_out": result.timed_out,
        "modules": grouped,
        "argv": result.argv,
        "resource": "msf_plan.rc (montado en /out:ro)",
        "ai_runtime": False,
    }
    evidence.write_json(run_dir / "msf_run.json", summary)
    evidence.refresh_manifest(run_dir)

    _ok(f"log: {run_dir / 'msf_run.log'}")
    _ok(f"resultado: {run_dir / 'msf_run.json'}")
    if status != "ok":
        _warn(f"Metasploit terminó con estado {status}")
        return 1
    return 0


# ---------------------------------------------------------------------------
# verify
# ---------------------------------------------------------------------------


def cmd_verify(args) -> int:
    _banner()
    result = audit.audit()
    if result["ok"]:
        _ok(f"sin imports de red/IA en {result['files_scanned']} ficheros del paquete")
    else:
        for finding in result["findings"]:
            _err(f"{finding['file']}:{finding['line']} {finding['kind']} {finding['value']}")
        return 1

    ai_keys = _ai_env_present()
    if ai_keys:
        _warn("variables de IA presentes (MIDGARD no las usa): " + ", ".join(ai_keys))
    else:
        _ok("sin variables de IA en el entorno")

    _ok("manifiestos declaran ai_runtime=false y telemetry=false")
    _ok("el único tráfico previsto es hacia el objetivo del escaneo")
    return 0


# ---------------------------------------------------------------------------
# menú
# ---------------------------------------------------------------------------


def _ask(prompt: str, default: str = "") -> str:
    suffix = f" [{default}]" if default else ""
    try:
        value = input(f"{prompt}{suffix}: ").strip()
    except EOFError:
        return default
    return value or default


def _menu_scan() -> int:
    target = _ask("Objetivo (IP o CIDR)")
    if not target:
        print("Cancelado.")
        return 0

    items = profiles.load_all()
    print("\n  Perfiles:")
    for index, profile in enumerate(items.values(), start=1):
        print(f"    {index}) {profile.id:<10} {profile.label} — {profile.description}")
    choice = _ask("Perfil", "quick")
    if choice.isdigit():
        ordered = list(items.values())
        index = int(choice) - 1
        if not 0 <= index < len(ordered):
            _err("perfil fuera de rango")
            return 2
        profile_id = ordered[index].id
    else:
        profile_id = choice

    ports = _ask("Puertos (vacío = los del perfil)")
    scripts = _ask("Scripts NSE separados por coma (vacío = los del perfil)")
    os_enabled = not _ask("¿Desactivar detección de SO? [s/N]", "n").lower().startswith("s")
    no_ping = _ask("¿Omitir descubrimiento de host (-Pn)? [s/N]", "n").lower().startswith("s")
    snmp_enabled = _ask("¿Sonda SNMP para versión exacta? [s/N]", "n").lower().startswith("s")
    snmp_community = _ask("Comunidad SNMP", "public") if snmp_enabled else "public"
    dry_run = _ask("¿Solo mostrar el comando (dry-run)? [s/N]", "n").lower().startswith("s")

    args = argparse.Namespace(
        target=target,
        profile=profile_id,
        ports=ports,
        scripts=scripts,
        no_os=not os_enabled,
        no_ping=no_ping,
        udp=False,
        snmp=snmp_enabled,
        snmp_community=snmp_community,
        timeout=0,
        dry_run=dry_run,
        yes=False,
        authorized=False,
        verbose=False,
    )
    return cmd_scan(args)


def cmd_menu(args) -> int:
    while True:
        _banner()
        print(
            "\n  1) Escanear\n"
            "  2) Ver ejecuciones\n"
            "  3) Ver un informe\n"
            "  4) Plan Metasploit\n"
            "  5) Doctor\n"
            "  6) Verificar offline\n"
            "  7) Ejecutar Metasploit (solo auxiliary)\n"
            "  0) Salir\n"
        )
        choice = _ask("Opción", "0")
        if choice in {"0", "q", "salir"}:
            return 0
        if choice == "1":
            _menu_scan()
        elif choice == "2":
            cmd_ls(args)
        elif choice == "3":
            runs = evidence.list_runs()
            if not runs:
                print("  No hay ejecuciones.")
                continue
            run_id = _ask("Run (vacío = la última)", runs[0]["run_id"])
            cmd_show(argparse.Namespace(run_id=run_id, details=True))
        elif choice == "4":
            runs = evidence.list_runs()
            if not runs:
                print("  No hay ejecuciones.")
                continue
            run_id = _ask("Run (vacío = la última)", runs[0]["run_id"])
            cmd_msf(argparse.Namespace(action="plan", run_id=run_id))
        elif choice == "5":
            cmd_doctor(argparse.Namespace(skip_msf=False))
        elif choice == "6":
            cmd_verify(argparse.Namespace())
        elif choice == "7":
            runs = evidence.list_runs()
            if not runs:
                print("  No hay ejecuciones.")
                continue
            run_id = _ask("Run (vacío = la última)", runs[0]["run_id"])
            print("  Requiere MIDGARD_ALLOW_MSF=1; solo módulos auxiliary.")
            cmd_msf(
                argparse.Namespace(
                    action="run",
                    run_id=run_id,
                    yes=False,
                    dry_run=False,
                    timeout=900,
                    authorized=False,
                )
            )
        else:
            print("  Opción no válida.")


# ---------------------------------------------------------------------------
# parser
# ---------------------------------------------------------------------------


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="midgard",
        description="Auditoría determinista sin IA en runtime.",
    )
    parser.add_argument("--version", action="version", version=f"MIDGARD {__version__}")
    sub = parser.add_subparsers(dest="command")

    p_doctor = sub.add_parser("doctor", help="comprueba Docker, imagen, nmap y offline")
    p_doctor.add_argument("--skip-msf", action="store_true")
    p_doctor.set_defaults(func=cmd_doctor)

    p_profiles = sub.add_parser("profiles", help="lista los perfiles de escaneo")
    p_profiles.set_defaults(func=cmd_profiles)

    p_scan = sub.add_parser("scan", help="ejecuta un escaneo con evidencia")
    p_scan.add_argument("target", help="IP o CIDR (p. ej. 192.168.1.0/24)")
    p_scan.add_argument("-p", "--profile", default="quick")
    p_scan.add_argument("--ports", help="puertos personalizados, p. ej. 22,80,443")
    p_scan.add_argument("--scripts", help="scripts NSE permitidos, separados por coma")
    p_scan.add_argument("--no-os", action="store_true", help="no ejecutar -O")
    p_scan.add_argument("--no-ping", action="store_true", help="añadir -Pn")
    p_scan.add_argument("--udp", action="store_true", help="añadir sondeo UDP")
    p_scan.add_argument(
        "--snmp",
        action="store_true",
        help="sonda SNMPv2c (sysDescr) para la versión exacta",
    )
    p_scan.add_argument(
        "--snmp-community",
        default="public",
        help="comunidad SNMP para --snmp (por defecto public)",
    )
    p_scan.add_argument("--timeout", type=int, default=0, help="segundos (0 = perfil)")
    p_scan.add_argument("--dry-run", action="store_true", help="solo mostrar el comando")
    p_scan.add_argument("-y", "--yes", action="store_true", help="no pedir confirmación")
    p_scan.add_argument("--authorized", action="store_true", help="objetivo público autorizado")
    p_scan.add_argument("--verbose", action="store_true", help="mostrar salida de nmap en vivo")
    p_scan.set_defaults(func=cmd_scan)

    p_ls = sub.add_parser("ls", help="lista ejecuciones")
    p_ls.set_defaults(func=cmd_ls)

    p_show = sub.add_parser("show", help="resumen de una ejecución")
    p_show.add_argument("run_id")
    p_show.add_argument("--details", action="store_true")
    p_show.set_defaults(func=cmd_show)

    p_report = sub.add_parser("report", help="abre o regenera el informe HTML")
    p_report.add_argument("run_id")
    p_report.add_argument("--open", action="store_true")
    p_report.add_argument("--regenerate", action="store_true")
    p_report.set_defaults(func=cmd_report)

    p_msf = sub.add_parser("msf", help="plan/ejecución de Metasploit (solo auxiliary)")
    p_msf.add_argument("action", choices=["plan", "run"])
    p_msf.add_argument("run_id")
    p_msf.add_argument("--yes", "-y", action="store_true", help="no pedir confirmación")
    p_msf.add_argument("--dry-run", action="store_true", help="valida el RC sin ejecutar")
    p_msf.add_argument("--timeout", type=int, default=900, help="segundos para msfconsole")
    p_msf.add_argument("--authorized", action="store_true", help="objetivo público autorizado")
    p_msf.set_defaults(func=cmd_msf)

    p_verify = sub.add_parser("verify", help="comprueba que el runtime es offline")
    p_verify.set_defaults(func=cmd_verify)

    p_menu = sub.add_parser("menu", help="menú interactivo")
    p_menu.set_defaults(func=cmd_menu)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if not getattr(args, "command", None):
        try:
            return cmd_menu(argparse.Namespace())
        except KeyboardInterrupt:
            print("\nCancelado.")
            return 130
    try:
        return args.func(args)
    except KeyboardInterrupt:
        print("\nCancelado.")
        return 130
    except (scope.ScopeError, profiles.ProfileError, nmap.NmapError) as exc:
        _err(str(exc))
        return 2
