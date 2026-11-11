#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Adaptador de Nmap: descubrimiento, puertos, versiones y scripts NSE."""

from __future__ import annotations

import ipaddress
import os
import xml.etree.ElementTree as ET
from pathlib import Path

from ..models import Host, Port
from .base import Tool, ToolContext, ToolResult, ToolSpec


SAFE_SCRIPTS = [
    "banner",
    "http-title",
    "http-headers",
    "ssl-cert",
    "ssh-hostkey",
    "rpcinfo",
]
INFRA_SCRIPTS = [
    "smb-os-discovery",
    "smb-security-mode",
    "smb2-security-mode",
    "smb2-time",
    "dns-recursion",
    "dns-service-discovery",
]
WEB_SCRIPTS = [
    "http-methods",
    "http-security-headers",
    "http-server-header",
    "http-enum",
]

CURATED_PORTS = (
    "22,23,25,53,80,111,135,139,161,389,443,445,512,513,514,587,631,636,"
    "873,902,993,995,1080,1433,1521,2049,2375,2376,3000,3128,3306,3389,"
    "4008,4369,5000,5432,5601,5672,5900,5985,5986,6379,6443,7001,8000,"
    "8006,8080,8081,8082,8112,8443,8888,9000,9042,9080,9090,9100,9117,"
    "9200,9221,9300,9443,10000,10250,11211,15672,27017,50000"
)


class NmapTool(Tool):
    spec = ToolSpec(
        name="nmap",
        binary="nmap",
        category="network",
        description="Descubrimiento de hosts, puertos, versiones y scripts NSE seguros.",
        phase="recon",
        profiles=("discovery", "quick", "full", "web", "infra", "deep", "attack"),
        attack=("T1595", "T1046"),
    )

    def run(self, ctx: ToolContext) -> ToolResult:
        if not self.available(ctx.runner):
            return self.missing(ctx)

        options = ctx.options or {}
        nmap_profile = options.get("nmap_profile", "quick")
        os_detection = bool(options.get("os_detection", True))
        result = ToolResult(tool=self.name)

        if nmap_profile == "discovery":
            self._discovery(ctx, result)
            return result

        # Sin hosts activos no se escanea el rango completo con -Pn: eso
        # marcaría las 256 direcciones como "up" y agotaría el tiempo.
        if not self._scan_targets(ctx):
            result.skipped = True
            result.meta["reason"] = "sin hosts activos"
            ctx.warn("nmap: el descubrimiento no encontró hosts activos; se omite el escaneo de puertos")
            return result

        explicit_ports = str(options.get("nmap_ports", "")).strip()
        top_ports = int(options.get("top_ports", 1000))
        scripts = list(SAFE_SCRIPTS)
        if nmap_profile in {"infra", "deep", "attack"}:
            scripts += INFRA_SCRIPTS
        if nmap_profile in {"web", "deep"}:
            scripts += WEB_SCRIPTS
        if options.get("no_scripts"):
            scripts = []

        if explicit_ports:
            self._scan(ctx, result, ["-p", explicit_ports], "ports", scripts, os_detection=os_detection)
        elif nmap_profile == "full":
            self._scan(ctx, result, ["-p-"], "full", scripts, os_detection=os_detection)
        else:
            self._scan(
                ctx,
                result,
                ["--top-ports", str(top_ports)],
                "top",
                scripts,
                os_detection=os_detection,
            )
            # Los puertos de gestión/LAN no suelen estar en el top-1000.
            # La detección de SO ya se hizo en la pasada anterior.
            self._scan(
                ctx,
                result,
                ["-p", CURATED_PORTS],
                "curated",
                scripts,
                os_detection=False,
            )

        # Sondeo UDP/161 opcional para obtener sysDescr (p. ej. versión RouterOS).
        if options.get("snmp_udp"):
            self._scan(
                ctx,
                result,
                ["-p", "161"],
                "snmp",
                [],
                os_detection=False,
                udp=True,
            )

        return result

    # -- pasadas -------------------------------------------------------

    def _scan_targets(self, ctx: ToolContext, *, discover: bool = True) -> list[str]:
        """Limita nmap a los hosts activos del objetivo.

        Sin esto, un perfil sobre ``192.168.1.0/24`` con ``-Pn`` marca los 256
        hosts como activos y lanza detección de versión/SO contra todos, lo que
        agota el timeout y deja el XML sin escribir. ``arp_scan`` ya ha
        descubierto los hosts reales en la LAN local; reutilizamos su lista.

        Si ``arp_scan`` no encontró nada (objetivo enrutado o fuera de la LAN
        local) se hace un descubrimiento con ``nmap -sn`` y se escanean solo
        los hosts que responden. Así una subred enrutada no produce hosts
        fantasma ni pierde puertos/CVE por timeout. La lista se calcula una
        sola vez por ejecución y se cachea en el contexto.
        """
        cached = getattr(ctx, "_nmap_scan_targets", None)
        if cached is not None:
            return list(cached)

        target = str(ctx.target or "").strip()
        discovered: list[str] = []
        for host in ctx.hosts or []:
            ip = str(getattr(host, "ip", "") or "").strip()
            if ip and ip not in discovered:
                discovered.append(ip)
        try:
            network = ipaddress.ip_network(target, strict=False)
        except ValueError:
            network = None

        if discovered:
            inside: list[str] = []
            for ip in discovered:
                try:
                    if network is not None and ipaddress.ip_address(ip) in network:
                        inside.append(ip)
                except ValueError:
                    continue
            targets = inside or ([target] if target else [])
        elif network is not None and discover and network.num_addresses > 1:
            targets = self._ping_sweep(ctx, network)
        else:
            targets = [target] if target else []

        setattr(ctx, "_nmap_scan_targets", targets)
        return list(targets)

    def _ping_sweep(self, ctx: ToolContext, network) -> list[str]:
        """Descubre hosts vivos con nmap -sn cuando ARP no puede (subred enrutada)."""
        out = ctx.path("nmap_ping.xml")
        argv = [
            "nmap",
            "-sn",
            "-n",
            "-PE",
            "-PS22,80,443,445,8006,8080,8443,3000",
            "-PA80,443,8006",
            "-T4",
            "--max-retries",
            "2",
            "--host-timeout",
            "90s",
            "-oX",
            out.name,
            str(network),
        ]
        cmd = ctx.run(argv, timeout=min(ctx.timeout, 600))
        if not out.exists():
            # Si el descubrimiento no se pudo ejecutar, se conserva el
            # comportamiento anterior en vez de quedarse sin escaneo.
            return [str(network)] if cmd.returncode != 0 else []
        try:
            root = ET.parse(out).getroot()
        except ET.ParseError:
            return [str(network)]
        live: list[str] = []
        for host_el in root.findall("host"):
            status = host_el.find("status")
            if status is not None and status.get("state") != "up":
                continue
            for address in host_el.findall("address"):
                if address.get("addrtype") in {"ipv4", "ipv6"}:
                    ip = address.get("addr", "")
                    if ip:
                        live.append(ip)
                    break
        ctx.info(f"nmap: descubrimiento en {network} → {len(live)} hosts activos")
        return live

    def _discovery(self, ctx: ToolContext, result: ToolResult) -> None:
        out = ctx.path("nmap_discovery.xml")
        argv = [
            "nmap",
            "-sn",
            "-n",
            "-PE",
            "-PS22,80,443,445",
            "-PA80,443",
            "-T4",
            "--max-retries",
            "2",
            "--host-timeout",
            "90s",
            "-oX",
            out.name,
            *self._scan_targets(ctx, discover=False),
        ]
        cmd = ctx.run(argv, timeout=min(ctx.timeout, 600))
        self._parse(ctx, out, result, cmd.returncode, cmd.output)

    def _scan(
        self,
        ctx: ToolContext,
        result: ToolResult,
        port_args: list[str],
        label: str,
        scripts: list[str],
        *,
        os_detection: bool = True,
        udp: bool = False,
    ) -> None:
        out = ctx.path(f"nmap_{label}.xml")
        if udp:
            scan_type = "-sU"
        else:
            scan_type = "-sS" if ctx.runner.name == "docker" else "-sT"
        argv = [
            "nmap",
            scan_type,
            "-Pn",
            "-n",
            "-T4",
            "--max-retries",
            "2",
            "--host-timeout",
            "10m",
        ]
        if not udp:
            argv += ["--min-rate", "100", "--max-rate", "1000"]
        argv += [
            *port_args,
            "-sV",
            "--version-light",
            "--version-intensity",
            "2" if udp else "5",
        ]
        if scripts and not udp:
            argv += ["--script", ",".join(scripts), "--script-timeout", "45s"]
        # `-O` necesita root dentro del contenedor (o root local). En local sin
        # privilegios se omite para no romper el escaneo.
        privileged = ctx.runner.name == "docker" or getattr(os, "geteuid", lambda: -1)() == 0
        if os_detection and not udp and privileged:
            argv += ["-O", "--osscan-guess"]
        argv += ["-oX", out.name, *self._scan_targets(ctx)]
        cmd = ctx.run(argv, timeout=ctx.timeout)
        self._parse(ctx, out, result, cmd.returncode, cmd.output)

    # -- parser --------------------------------------------------------

    def _parse(
        self,
        ctx: ToolContext,
        xml_path: Path,
        result: ToolResult,
        returncode: int,
        output: str,
    ) -> None:
        if not xml_path.exists():
            if returncode != 0:
                result.ok = False
                result.error = (output or "nmap no generó XML")[-2000:]
            return
        try:
            root = ET.parse(xml_path).getroot()
        except ET.ParseError as exc:
            result.ok = False
            result.error = f"XML de nmap inválido: {exc}"
            return

        for host_el in root.findall("host"):
            status = host_el.find("status")
            if status is not None and status.get("state") != "up":
                continue
            host = Host(ip="")
            for address in host_el.findall("address"):
                addrtype = address.get("addrtype", "")
                if addrtype in {"ipv4", "ipv6"} and not host.ip:
                    host.ip = address.get("addr", "")
                elif addrtype == "mac":
                    host.mac = address.get("addr", "")
                    host.vendor = address.get("vendor", "")
            if not host.ip:
                continue

            hostnames_el = host_el.find("hostnames")
            if hostnames_el is not None:
                host.hostnames = [
                    hn.get("name", "")
                    for hn in hostnames_el.findall("hostname")
                    if hn.get("name")
                ]

            os_el = host_el.find("os")
            if os_el is not None:
                best = None
                best_acc = -1
                for match in os_el.findall("osmatch"):
                    try:
                        accuracy = int(match.get("accuracy", "0"))
                    except ValueError:
                        accuracy = 0
                    if accuracy > best_acc:
                        best, best_acc = match, accuracy
                if best is not None:
                    host.os = best.get("name", "")

            for port_el in host_el.findall("ports/port"):
                state_el = port_el.find("state")
                state = state_el.get("state", "") if state_el is not None else ""
                if state not in {"open", "open|filtered"}:
                    continue
                try:
                    number = int(port_el.get("portid", "0"))
                except ValueError:
                    continue
                service_el = port_el.find("service")
                port = Port(port=number, proto=port_el.get("protocol", "tcp"), state="open")
                if service_el is not None:
                    port.service = service_el.get("name", "")
                    port.product = service_el.get("product", "")
                    port.version = service_el.get("version", "")
                    port.extrainfo = service_el.get("extrainfo", "")
                for script_el in port_el.findall("script"):
                    script_id = script_el.get("id", "")
                    if script_id:
                        port.scripts[script_id] = script_el.get("output", "")
                host.add_port(port)

            hostscripts = host_el.find("hostscript")
            if hostscripts is not None:
                for script_el in hostscripts.findall("script"):
                    script_id = script_el.get("id", "")
                    if script_id:
                        host.hostscripts[script_id] = script_el.get("output", "")

            result.hosts.append(host)

        # Fusiona hosts repetidos entre pasadas (top + curated).
        merged: dict[str, Host] = {}
        for host in result.hosts:
            if host.ip in merged:
                target = merged[host.ip]
                for port in host.ports:
                    target.add_port(port)
                target.hostscripts.update(host.hostscripts)
                target.hostnames = sorted(set(target.hostnames + host.hostnames))
                target.os = target.os or host.os
                target.mac = target.mac or host.mac
                target.vendor = target.vendor or host.vendor
            else:
                merged[host.ip] = host
        result.hosts = list(merged.values())
