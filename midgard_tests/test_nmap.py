"""Tests de construcción de argumentos y parseo de Nmap."""

from __future__ import annotations

import unittest
from pathlib import Path

from midgard import nmap, profiles


FIXTURE = Path(__file__).parent / "fixtures" / "lan_mixed.xml"


class NmapArgsTests(unittest.TestCase):
    def setUp(self):
        self.quick = profiles.get("quick")
        self.discovery = profiles.get("discovery")

    def test_quick_has_os_and_version(self):
        args = nmap.build_nmap_args("192.168.88.0/24", self.quick)
        for flag in ("-sS", "-sV", "-O", "--osscan-guess"):
            self.assertIn(flag, args)
        self.assertEqual(args[-1], "192.168.88.0/24")
        self.assertIn("--top-ports", args)

    def test_discovery_has_no_os(self):
        args = nmap.build_nmap_args("192.168.88.0/24", self.discovery)
        self.assertIn("-sn", args)
        self.assertNotIn("-O", args)
        self.assertNotIn("-sV", args)

    def test_custom_requires_ports(self):
        custom = profiles.get("custom")
        with self.assertRaises(nmap.NmapError):
            nmap.build_nmap_args("192.168.88.1", custom)

    def test_custom_with_ports(self):
        custom = profiles.get("custom")
        args = nmap.build_nmap_args("192.168.88.1", custom, ports="22,80")
        self.assertIn("22,80", args)

    def test_invalid_ports_rejected(self):
        with self.assertRaises(nmap.NmapError):
            nmap.build_nmap_args("192.168.88.1", self.quick, ports="22; rm -rf /")

    def test_invalid_script_rejected(self):
        with self.assertRaises(nmap.NmapError):
            nmap.validate_scripts("http-title,evil-script")
        with self.assertRaises(nmap.NmapError):
            nmap.validate_scripts("http-title;rm")

    def test_no_update_script(self):
        args = nmap.build_nmap_args("192.168.88.1", self.quick)
        self.assertNotIn("--script-updatedb", args)

    def test_udp_without_ports_is_rejected(self):
        with self.assertRaises(nmap.NmapError):
            nmap.build_nmap_args("192.168.88.1", self.quick, udp=True)

    def test_router_profile_has_udp(self):
        router = profiles.get("router")
        args = nmap.build_nmap_args("192.168.88.1", router)
        self.assertIn("-sU", args)
        self.assertIn("U:161", " ".join(args))


class NmapParseTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.hosts = nmap.parse_xml(FIXTURE.read_text(encoding="utf-8"))

    def test_host_count(self):
        self.assertEqual(len(self.hosts), 7)

    def test_mac_and_vendor(self):
        host = next(h for h in self.hosts if h.ip == "192.168.88.1")
        self.assertEqual(host.vendor, "Routerboard.com")
        self.assertTrue(host.mac)

    def test_ports_and_scripts(self):
        host = next(h for h in self.hosts if h.ip == "192.168.88.11")
        ports = {p.port for p in host.open_ports}
        self.assertEqual(ports, {135, 445, 3389})
        smb = next(p for p in host.ports if p.port == 445)
        self.assertIn("22631", smb.scripts["smb-os-discovery"])

    def test_os_matches(self):
        host = next(h for h in self.hosts if h.ip == "192.168.88.1")
        self.assertTrue(host.os_matches)
        self.assertIn("RouterOS", host.os_matches[0].name)

    def test_empty_xml_rejected(self):
        with self.assertRaises(nmap.NmapError):
            nmap.parse_xml("")

    def test_invalid_xml_rejected(self):
        with self.assertRaises(nmap.NmapError):
            nmap.parse_xml("<nmaprun>")


if __name__ == "__main__":
    unittest.main()
