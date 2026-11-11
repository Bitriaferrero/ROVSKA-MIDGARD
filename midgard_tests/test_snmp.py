"""Tests de la sonda SNMPv2c determinista."""

from __future__ import annotations

import unittest

from midgard import docker, nmap, snmp


def _host(ip: str, ports: list[nmap.Port], vendor: str = "") -> nmap.Host:
    return nmap.Host(ip=ip, vendor=vendor, ports=ports)


class SnmpArgTests(unittest.TestCase):
    def test_community_validation(self) -> None:
        self.assertEqual(snmp.validate_community(" public "), "public")
        for value in ("", "public;rm", "con espacio", "a" * 65):
            with self.assertRaises(snmp.SnmpError):
                snmp.validate_community(value)

    def test_build_get_argv_is_argv_only(self) -> None:
        argv = snmp.build_get_argv("192.168.88.1", "public")
        self.assertEqual(argv[0], "/usr/bin/snmpget")
        self.assertIn("-Oqv", argv)
        self.assertEqual(argv[-2:], ["192.168.88.1", snmp.SYS_DESCR_OID])
        self.assertNotIn(";", " ".join(argv))

    def test_parse_sysdescr_plain_and_labeled(self) -> None:
        self.assertEqual(
            snmp.parse_sysdescr('"RouterOS RB750Gr3 6.49.23 (stable)"\n'),
            "RouterOS RB750Gr3 6.49.23 (stable)",
        )
        self.assertEqual(
            snmp.parse_sysdescr("SNMPv2-MIB::sysDescr.0 = STRING: Linux router 5.10\n"),
            "Linux router 5.10",
        )
        self.assertEqual(snmp.parse_sysdescr("Timeout: No Response from 192.168.88.1\n"), "")


class SnmpProbeTests(unittest.TestCase):
    def test_probe_attaches_sysdescr_to_host(self) -> None:
        host = _host("192.168.88.1", [nmap.Port(port=161, proto="udp", state="open")])
        calls: list[list[str]] = []

        def fake(argv, timeout=8):
            calls.append(list(argv))
            return docker.CommandResult(
                argv=list(argv),
                returncode=0,
                stdout="RouterOS RB750Gr3 6.49.23 (stable)\n",
            )

        result = snmp.probe_hosts([host], "public", runner=fake)
        self.assertEqual(result["targets"], 1)
        self.assertEqual(result["responded"], 1)
        self.assertEqual(host.scripts["snmp-sysdescr"], "RouterOS RB750Gr3 6.49.23 (stable)")
        self.assertEqual(len(calls), 1)

    def test_private_community_is_redacted_in_evidence(self) -> None:
        host = _host("192.168.88.1", [nmap.Port(port=161, proto="udp", state="open")])

        def fake(argv, timeout=8):
            return docker.CommandResult(argv=list(argv), returncode=0, stdout="RouterOS 7.1\n")

        result = snmp.probe_hosts([host], "mi-comunidad", runner=fake)
        self.assertEqual(result["community"], "<redactada>")
        self.assertNotIn("mi-comunidad", str(result))
        self.assertEqual(result["responded"], 1)

    def test_fallback_to_mikrotik_when_udp_161_not_scanned(self) -> None:
        host = _host(
            "192.168.88.1",
            [nmap.Port(port=8291, proto="tcp", state="open", service="http")],
            vendor="Routerboard.com",
        )

        def fake(argv, timeout=8):
            return docker.CommandResult(argv=list(argv), returncode=0, stdout="RouterOS 7.15.3\n")

        result = snmp.probe_hosts([host], "public", runner=fake)
        self.assertEqual(result["targets"], 1)
        self.assertEqual(host.scripts["snmp-sysdescr"], "RouterOS 7.15.3")


if __name__ == "__main__":
    unittest.main()
