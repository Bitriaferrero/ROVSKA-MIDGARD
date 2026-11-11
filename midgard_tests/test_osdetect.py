"""Tests de enriquecimiento de sistema operativo."""

from __future__ import annotations

import unittest
from pathlib import Path

from midgard import nmap, osdetect


FIXTURE = Path(__file__).parent / "fixtures" / "lan_mixed.xml"


class OsDetectTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.hosts = osdetect.detect_all(
            nmap.parse_xml(FIXTURE.read_text(encoding="utf-8"))
        )
        cls.by_ip = {host.ip: host for host in cls.hosts}

    def test_ubuntu_1604_from_ssh_banner(self):
        os_info = self.by_ip["192.168.88.10"].os
        self.assertEqual(os_info["name"], "Ubuntu")
        self.assertEqual(os_info["version"], "16.04")
        self.assertEqual(os_info["confidence"], "alta")
        self.assertIn("banner SSH", os_info["sources"])

    def test_windows_11_23h2_from_smb_build(self):
        os_info = self.by_ip["192.168.88.11"].os
        self.assertEqual(os_info["name"], "Windows 11")
        self.assertEqual(os_info["version"], "23H2")
        self.assertEqual(os_info["device"], "Servidor / PC")

    def test_debian_11_from_http_and_ssh(self):
        os_info = self.by_ip["192.168.88.12"].os
        self.assertEqual(os_info["name"], "Debian")
        self.assertIn(os_info["version"], {"11", "10"})
        self.assertIn(os_info["confidence"], {"alta", "media"})

    def test_macos_from_nmap_match(self):
        os_info = self.by_ip["192.168.88.13"].os
        self.assertEqual(os_info["name"], "macOS")
        self.assertTrue(os_info["version"].startswith("12"))

    def test_samsung_vendor_gives_android(self):
        os_info = self.by_ip["192.168.88.14"].os
        self.assertEqual(os_info["name"], "Android (Samsung)")
        self.assertEqual(os_info["confidence"], "baja")
        self.assertEqual(os_info["device"], "Móvil / tablet")

    def test_mikrotik_with_version(self):
        os_info = self.by_ip["192.168.88.1"].os
        self.assertEqual(os_info["name"], "MikroTik RouterOS")
        self.assertEqual(os_info["version"], "6.49.23")
        self.assertEqual(os_info["device"], "Router")

    def test_unknown_host(self):
        os_info = self.by_ip["192.168.88.20"].os
        self.assertEqual(os_info["name"], "SO desconocido")
        self.assertEqual(os_info["score"], 0)
        self.assertEqual(os_info["candidates"], [])

    def test_mikrotik_exact_version_from_snmp_sysdescr(self):
        host = nmap.Host(
            ip="192.168.88.1",
            vendor="Routerboard.com",
            ports=[nmap.Port(port=161, proto="udp", state="open", service="snmp")],
            scripts={"snmp-sysdescr": "RouterOS RB750Gr3 6.49.23 (stable)"},
        )
        os_info = osdetect.detect(host)
        self.assertEqual(os_info["name"], "MikroTik RouterOS")
        self.assertEqual(os_info["version"], "6.49.23")
        self.assertEqual(os_info["confidence"], "alta")

    def test_mikrotik_version_from_ftp_product(self):
        host = nmap.Host(
            ip="192.168.88.1",
            vendor="Routerboard.com",
            ports=[
                nmap.Port(
                    port=21,
                    proto="tcp",
                    state="open",
                    service="ftp",
                    product="MikroTik router ftpd",
                    version="6.49.23",
                )
            ],
        )
        os_info = osdetect.detect(host)
        self.assertEqual(os_info["name"], "MikroTik RouterOS")
        self.assertEqual(os_info["version"], "6.49.23")
        self.assertEqual(os_info["confidence"], "alta")

    def test_service_banner_beats_nmap_os_version(self):
        # El `osmatch` de nmap aproxima la rama ("6.19"); el FTP publica la
        # versión exacta ("6.49.23"). El banner del servicio manda.
        host = nmap.Host(
            ip="192.168.88.1",
            vendor="Routerboard.com",
            ports=[
                nmap.Port(
                    port=21,
                    proto="tcp",
                    state="open",
                    service="ftp",
                    product="MikroTik router ftpd",
                    version="6.49.23",
                )
            ],
            os_matches=[
                nmap.OSMatch(name="MikroTik RouterOS 6.19", accuracy=96)
            ],
        )
        os_info = osdetect.detect(host)
        self.assertEqual(os_info["name"], "MikroTik RouterOS")
        self.assertEqual(os_info["version"], "6.49.23")
        self.assertEqual(os_info["sources"], ["producto/servicio"])

    def test_ttl_128_points_to_windows(self):
        os_info = osdetect.detect(nmap.Host(ip="192.168.88.30", ttl=128))
        self.assertEqual(os_info["name"], "Windows (TTL 128)")
        self.assertEqual(os_info["confidence"], "baja")
        self.assertEqual(os_info["device"], "PC / servidor Windows")

    def test_ttl_64_points_to_linux_when_nmap_is_silent(self):
        os_info = osdetect.detect(nmap.Host(ip="192.168.88.31", ttl=64))
        self.assertEqual(os_info["name"], "Linux / Unix (TTL 64)")
        self.assertEqual(os_info["confidence"], "baja")

    def test_vendor_hint_when_nmap_has_no_os(self):
        os_info = osdetect.detect(
            nmap.Host(ip="192.168.88.32", vendor="LCFC(Hefei) Electronics Technology")
        )
        self.assertEqual(os_info["name"], "PC Lenovo (LCFC)")
        self.assertEqual(os_info["sources"], ["fabricante MAC"])

    def test_mikrotik_beats_generic_linux_kernel(self):
        host = nmap.Host(
            ip="192.168.88.1",
            vendor="Routerboard.com",
            ports=[
                nmap.Port(
                    port=22,
                    proto="tcp",
                    state="open",
                    service="ssh",
                    product="MikroTik RouterOS sshd",
                )
            ],
            os_matches=[nmap.OSMatch(name="Linux 2.6.32 - 3.13", accuracy=100)],
        )
        os_info = osdetect.detect(host)
        self.assertEqual(os_info["name"], "MikroTik RouterOS")
        self.assertIn("producto/servicio", os_info["sources"])

    def test_ubuntu_interim_from_ssh_banner(self):
        host = nmap.Host(
            ip="192.168.88.40",
            ports=[
                nmap.Port(
                    port=22,
                    proto="tcp",
                    state="open",
                    service="ssh",
                    product="OpenSSH",
                    version="9.9p1",
                    extrainfo="Ubuntu-3ubuntu1",
                )
            ],
        )
        os_info = osdetect.detect(host)
        self.assertEqual(os_info["name"], "Ubuntu")
        self.assertEqual(os_info["version"], "25.04/25.10 (interim)")

    def test_proxmox_node_from_port_8006(self):
        host = nmap.Host(
            ip="192.168.88.41",
            ports=[
                nmap.Port(port=8006, proto="tcp", state="open", service="https"),
            ],
            os_matches=[nmap.OSMatch(name="Linux 5.0 - 5.4", accuracy=98)],
        )
        os_info = osdetect.detect(host)
        self.assertEqual(os_info["device"], "Nodo Proxmox")
        self.assertIn("Proxmox VE", os_info["name"])

    def test_guest_proxmox_from_mac_prefix(self):
        host = nmap.Host(
            ip="192.168.88.42",
            mac="BC:24:11:AA:BB:CC",
            ports=[
                nmap.Port(port=22, proto="tcp", state="open", service="ssh"),
            ],
            os_matches=[nmap.OSMatch(name="Linux 5.0 - 5.4", accuracy=98)],
        )
        os_info = osdetect.detect(host)
        self.assertEqual(os_info["device"], "Guest Proxmox (LXC/VM)")

    def test_vm_from_mac_prefix(self):
        host = nmap.Host(
            ip="192.168.88.43",
            mac="52:54:00:12:34:56",
            ports=[
                nmap.Port(port=22, proto="tcp", state="open", service="ssh"),
            ],
            os_matches=[nmap.OSMatch(name="Linux 5.0 - 5.4", accuracy=98)],
        )
        os_info = osdetect.detect(host)
        self.assertEqual(os_info["device"], "Máquina virtual (QEMU/KVM)")
        self.assertIn("VM QEMU/KVM", os_info["name"])


if __name__ == "__main__":
    unittest.main()
