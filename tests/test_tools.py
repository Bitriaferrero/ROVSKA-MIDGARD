#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Tests de adaptadores con salidas simuladas de las herramientas."""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from rovvska.config import Settings
from rovvska.models import Host, Port
from rovvska.runner import CommandResult
from rovvska.tools.base import ToolContext
from rovvska.tools.metasploit import MetasploitTool
from rovvska.tools.masscan import MasscanTool
from rovvska.tools.nmap import NmapTool
from rovvska.tools.smb import SmbTool
from rovvska.tools.snmp import SnmpTool
from rovvska.tools.testssl import TestSslTool


class FakeRunner:
    """Runner de prueba: devuelve una salida fija y escribe ficheros si hace falta."""

    name = "fake"

    def __init__(self, stdout: str = "", files: dict[str, str] | None = None, name: str = "fake"):
        self.stdout = stdout
        self.files = files or {}
        self.name = name
        self.calls: list[list[str]] = []

    def available(self, binary: str) -> bool:  # noqa: ARG002
        return True

    def workdir(self, operation_id: str) -> Path:
        raise NotImplementedError

    def map_cwd(self, host_cwd: Path) -> str:
        return str(host_cwd)

    def run(self, argv, timeout=None, cwd=None, env=None, input_text=None, cancel_event=None) -> CommandResult:  # noqa: ARG002
        self.calls.append(list(argv))
        if cwd and self.files:
            for name, content in self.files.items():
                (Path(cwd) / name).write_text(content, encoding="utf-8")
        return CommandResult(argv=list(argv), returncode=0, stdout=self.stdout)


def _ctx(runner: FakeRunner, hosts: list[Host], options: dict | None = None, target: str | None = None) -> ToolContext:
    tmp = tempfile.mkdtemp(prefix="rovska-tool-")
    return ToolContext(
        runner=runner,
        target=target or (hosts[0].ip if hosts else "10.0.0.0/24"),
        workdir=Path(tmp),
        options=options or {},
        settings=Settings(),
        hosts=hosts,
    )


class SmbTests(unittest.TestCase):
    def test_enum4linux_ng_nested_json(self) -> None:
        payload = {
            "sessions": {"sessions": [{"session": "null", "auth": True}], "errors": []},
            "shares": {"shares": [{"name": "datos", "access": "READ,WRITE"}], "errors": []},
            "users": {"users": {"Administrador": {}, "guest": {}}, "errors": []},
            "smb_signing": {"required": False},
        }
        runner = FakeRunner(files={"enum4linux_10.0.0.5.json": json.dumps(payload)})
        host = Host(ip="10.0.0.5", ports=[Port(port=445, service="microsoft-ds")])
        result = SmbTool().run(_ctx(runner, [host]))

        titles = {finding.title for finding in result.findings}
        self.assertIn("SMB permite sesión nula o anónima", titles)
        self.assertIn("Recursos SMB accesibles", titles)
        self.assertIn("Enumeración de usuarios SMB", titles)
        self.assertIn("SMB sin firma obligatoria", titles)


class SnmpTests(unittest.TestCase):
    def test_numeric_oids_without_mibs(self) -> None:
        stdout = (
            "iso.3.6.1.2.1.1.1.0 = STRING: Linux router 5.10\n"
            "iso.3.6.1.2.1.1.5.0 = STRING: router.interno\n"
        )
        runner = FakeRunner(stdout=stdout)
        host = Host(ip="10.0.0.6", ports=[Port(port=161, proto="udp", service="snmp")])
        result = SnmpTool().run(_ctx(runner, [host]))

        titles = {finding.title for finding in result.findings}
        self.assertIn("SNMP con comunidad pública", titles)
        values = result.meta["snmp"]["10.0.0.6"]
        self.assertEqual(values["sysDescr"], "Linux router 5.10")
        self.assertEqual(values["sysName"], "router.interno")


class NmapTests(unittest.TestCase):
    XML = """<?xml version="1.0"?>
<nmaprun>
  <host>
    <status state="up"/>
    <address addr="10.0.0.5" addrtype="ipv4"/>
    <ports>
      <port protocol="tcp" portid="22">
        <state state="open"/>
        <service name="ssh" product="OpenSSH" version="8.2p1"/>
      </port>
    </ports>
    <os><osmatch name="Linux 5.0 - 5.4" accuracy="95"/></os>
  </host>
</nmaprun>
"""

    def _scan(self, options: dict) -> FakeRunner:
        runner = FakeRunner(files={"nmap_ports.xml": self.XML}, name="docker")
        result = NmapTool().run(_ctx(runner, [Host(ip="10.0.0.5")], options))
        self.assertTrue(result.ok)
        return runner

    def test_docker_scan_requests_os_detection(self) -> None:
        runner = self._scan({"nmap_ports": "22,80"})
        self.assertEqual(len(runner.calls), 1)
        argv = runner.calls[0]
        self.assertIn("-O", argv)
        self.assertIn("--osscan-guess", argv)

    def test_os_detection_can_be_disabled(self) -> None:
        runner = self._scan({"nmap_ports": "22,80", "os_detection": False})
        argv = runner.calls[0]
        self.assertNotIn("-O", argv)
        self.assertNotIn("--osscan-guess", argv)

    def test_scan_limited_to_discovered_hosts(self) -> None:
        """Con un /24 y hosts ya descubiertos no se escanean los 256 con -Pn."""
        runner = FakeRunner(files={"nmap_ports.xml": self.XML}, name="docker")
        ctx = _ctx(
            runner,
            [Host(ip="10.0.0.5"), Host(ip="10.0.0.9"), Host(ip="10.0.1.5")],
            {"nmap_ports": "22,80"},
            target="10.0.0.0/24",
        )
        result = NmapTool().run(ctx)
        self.assertTrue(result.ok)
        argv = runner.calls[0]
        self.assertIn("10.0.0.5", argv)
        self.assertIn("10.0.0.9", argv)
        self.assertNotIn("10.0.1.5", argv)
        self.assertNotIn("10.0.0.0/24", argv)

    def test_scan_keeps_target_without_discovery(self) -> None:
        runner = FakeRunner(files={"nmap_ports.xml": self.XML}, name="docker")
        ctx = _ctx(
            runner,
            [Host(ip="10.0.0.5")],
            {"nmap_ports": "22,80"},
            target="10.0.0.0/24",
        )
        # Sin hosts previos, nmap debe recibir el objetivo original.
        ctx.hosts = []
        result = NmapTool().run(ctx)
        self.assertTrue(result.ok)
        self.assertIn("10.0.0.0/24", runner.calls[0])

    def test_optional_snmp_probe_is_udp_161(self) -> None:
        runner = FakeRunner(
            files={"nmap_ports.xml": self.XML, "nmap_snmp.xml": self.XML},
            name="docker",
        )
        NmapTool().run(
            _ctx(runner, [Host(ip="10.0.0.5")], {"nmap_ports": "22", "snmp_udp": True})
        )
        snmp_argv = runner.calls[-1]
        self.assertIn("-sU", snmp_argv)
        self.assertEqual(snmp_argv[snmp_argv.index("-p") + 1], "161")
        self.assertNotIn("-O", snmp_argv)


class MasscanTests(unittest.TestCase):
    def test_empty_output_is_not_an_error(self) -> None:
        runner = FakeRunner(files={"masscan.json": ""})
        result = MasscanTool().run(
            _ctx(runner, [Host(ip="192.168.88.252")], {"use_masscan": True})
        )
        self.assertTrue(result.ok)
        self.assertEqual(result.hosts, [])


class TestSslTests(unittest.TestCase):
    def test_filters_cipher_noise_and_keeps_actionable_rows(self) -> None:
        payload = [
            {"id": "cipher-tls1_2_xc028", "severity": "LOW", "finding": "TLSv1.2 xc028 ..."},
            {"id": "cipherlist_OBSOLETED", "severity": "LOW", "finding": "offered"},
            {"id": "cert_chain_of_trust", "severity": "CRITICAL", "finding": "failed (self signed)."},
            {"id": "cert_subjectAltName", "severity": "HIGH", "finding": "No SAN, browsers are complaining"},
            {"id": "HSTS", "severity": "LOW", "finding": "not offered"},
            {"id": "security_headers", "severity": "MEDIUM", "finding": "--"},
            {"id": "overall_grade", "severity": "CRITICAL", "finding": "T"},
        ]
        runner = FakeRunner(
            files={"testssl_https___127_0_0_1_8443.json": json.dumps(payload)}
        )
        host = Host(ip="127.0.0.1", ports=[Port(port=8443, service="https")])
        result = TestSslTool().run(_ctx(runner, [host]))

        titles = [finding.title for finding in result.findings]
        self.assertIn("Certificado TLS no confiable", titles)
        self.assertIn("Certificado TLS sin SAN", titles)
        self.assertIn("HSTS no configurado", titles)
        self.assertIn("Calificación TLS global: T", titles)
        self.assertIn("Cifrados TLS obsoletos ofrecidos", titles)
        self.assertFalse(any("xc028" in title for title in titles))
        self.assertFalse(any("security_headers" in title for title in titles))


class MetasploitTests(unittest.TestCase):
    def test_auxiliary_check_uses_run(self) -> None:
        host = Host(ip="10.0.0.7")
        result = MetasploitTool().run(
            _ctx(
                FakeRunner(),
                [host],
                {"module": "auxiliary/scanner/ssh/ssh_version", "action": "check"},
            )
        )
        script = result.meta["planned"]["script"]
        self.assertIn("run", script.splitlines())
        self.assertNotIn("check", script.splitlines())

    def test_exploit_module_uses_check(self) -> None:
        host = Host(ip="10.0.0.8")
        result = MetasploitTool().run(
            _ctx(
                FakeRunner(),
                [host],
                {"module": "exploit/linux/http/example", "action": "check"},
            )
        )
        script = result.meta["planned"]["script"]
        self.assertIn("check", script.splitlines())


class RunnerCancellationTests(unittest.TestCase):
    def test_local_runner_stops_a_cancelled_command(self) -> None:
        import sys
        import threading
        import time

        from rovvska.runner import LocalRunner

        runner = LocalRunner(Settings())
        cancel = threading.Event()
        threading.Timer(0.3, cancel.set).start()
        started = time.monotonic()
        result = runner.run(
            [sys.executable, "-c", "import time; time.sleep(30)"],
            timeout=30,
            cancel_event=cancel,
        )
        self.assertTrue(result.cancelled)
        self.assertEqual(result.returncode, 130)
        self.assertIn("cancelado", result.stderr)
        self.assertLess(time.monotonic() - started, 10)

    def test_tool_context_raises_cancelled(self) -> None:
        import threading

        from rovvska.runner import Cancelled

        class CancelledRunner(FakeRunner):
            def run(self, argv, timeout=None, cwd=None, env=None, input_text=None, cancel_event=None):  # noqa: ARG002
                return CommandResult(
                    argv=list(argv), returncode=130, stderr="cancelado", cancelled=True
                )

        ctx = _ctx(CancelledRunner(), [Host(ip="10.0.0.9")])
        ctx.cancel_event = threading.Event()
        with self.assertRaises(Cancelled):
            ctx.run(["true"])


if __name__ == "__main__":
    unittest.main()
