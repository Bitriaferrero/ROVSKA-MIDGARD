#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Tests del motor de análisis y del enriquecimiento de marcos."""

from __future__ import annotations

import unittest

from rovvska import analyzer, attack, frameworks, scanner
from rovvska.models import Finding, Host, Port, counts_by_severity, merge_findings


class AnalyzerTests(unittest.TestCase):
    def test_exposed_redis_is_critical(self) -> None:
        host = Host(ip="10.0.0.5", ports=[Port(port=6379, service="redis")])
        result = analyzer.analyze([host], [], [])
        titles = [finding.title for finding in result["findings"]]
        self.assertIn("Redis expuesto", titles)
        finding = next(f for f in result["findings"] if f.title == "Redis expuesto")
        self.assertEqual(finding.severity, "CRÍTICO")
        self.assertIn("T1190", finding.attack)
        self.assertIn("frameworks", finding.to_dict())
        self.assertTrue(finding.frameworks["ptes"]["phase"])
        self.assertGreater(host.extra["risk"], 0)

    def test_legacy_ftp_backdoor(self) -> None:
        host = Host(
            ip="10.0.0.6",
            ports=[Port(port=21, service="ftp", product="vsftpd", version="2.3.4")],
        )
        result = analyzer.analyze([host], [], [])
        finding = next(f for f in result["findings"] if "vsftpd" in f.title)
        self.assertEqual(finding.severity, "CRÍTICO")
        self.assertIn("CVE-2011-2523", finding.cves)

    def test_missing_http_headers(self) -> None:
        host = Host(ip="10.0.0.7", ports=[Port(port=80, service="http")])
        host.ports[0].scripts["http-headers"] = "Server: nginx/1.18.0\n"
        result = analyzer.analyze([host], [], [])
        titles = [f.title for f in result["findings"]]
        self.assertIn("Cabeceras de seguridad HTTP ausentes", titles)

    def test_positive_checks(self) -> None:
        host = Host(ip="10.0.0.8", ports=[Port(port=22, service="ssh")])
        result = analyzer.analyze([host], [], [])
        self.assertTrue(result["good_checks"])

    def test_merge_findings_keeps_highest_severity(self) -> None:
        low = Finding(severity="BAJO", title="Duplicado", host="10.0.0.9", cves=["CVE-1"])
        high = Finding(severity="ALTO", title="Duplicado", host="10.0.0.9", cves=["CVE-2"])
        merged = merge_findings([low, high])
        self.assertEqual(len(merged), 1)
        self.assertEqual(merged[0].severity, "ALTO")
        self.assertIn("CVE-1", merged[0].cves)

    def test_refine_os_from_ssh_banner(self) -> None:
        host = Host(
            ip="10.0.0.11",
            os="Linux 5.0 - 5.4",
            ports=[
                Port(
                    port=22,
                    service="ssh",
                    product="OpenSSH",
                    version="8.2p1",
                    extrainfo="Ubuntu-1ubuntu0.1",
                )
            ],
        )
        analyzer.refine_os(host)
        self.assertEqual(host.os, "Ubuntu 20.04")

    def test_refine_os_keeps_mikrotik_over_generic_linux(self) -> None:
        host = Host(
            ip="10.0.0.12",
            os="Linux 5.0 - 5.4",
            ports=[Port(port=22, service="ssh", product="ROSSH", version="6.49.23")],
        )
        analyzer.refine_os(host)
        self.assertEqual(host.os, "MikroTik RouterOS 6.49.23")

    def test_refine_os_mikrotik_version_from_ftp_product(self) -> None:
        host = Host(
            ip="10.0.0.14",
            vendor="Routerboard.com",
            ports=[
                Port(
                    port=21,
                    service="ftp",
                    product="MikroTik router ftpd",
                    version="6.49.23",
                )
            ],
        )
        analyzer.refine_os(host)
        self.assertEqual(host.os, "MikroTik RouterOS 6.49.23")

    def test_refine_os_prefers_service_version_over_nmap_guess(self) -> None:
        # nmap puede aproximar la rama ("6.19") mientras el FTP publica la
        # versión exacta; el banner del servicio debe mandar.
        host = Host(
            ip="10.0.0.17",
            os="MikroTik RouterOS 6.19",
            vendor="Routerboard.com",
            ports=[
                Port(
                    port=21,
                    service="ftp",
                    product="MikroTik router ftpd",
                    version="6.49.23",
                )
            ],
        )
        analyzer.refine_os(host)
        self.assertEqual(host.os, "MikroTik RouterOS 6.49.23")

    def test_refine_os_uses_ttl_when_nmap_is_silent(self) -> None:
        host = Host(ip="10.0.0.15", extra={"ttl": 128})
        analyzer.refine_os(host)
        self.assertEqual(host.os, "Windows (TTL 128)")

    def test_refine_os_uses_vendor_when_nmap_is_silent(self) -> None:
        host = Host(ip="10.0.0.16", vendor="LCFC(Hefei) Electronics Technology")
        analyzer.refine_os(host)
        self.assertEqual(host.os, "PC Lenovo (LCFC)")

    def test_refine_os_ubuntu_interim(self) -> None:
        host = Host(
            ip="10.0.0.20",
            os="Linux 6.0 - 6.8",
            ports=[
                Port(
                    port=22,
                    service="ssh",
                    product="OpenSSH",
                    version="9.9p1",
                    extrainfo="Ubuntu-3ubuntu1",
                )
            ],
        )
        analyzer.refine_os(host)
        self.assertEqual(host.os, "Ubuntu 25.04/25.10 (interim)")

    def test_refine_os_debian_12(self) -> None:
        host = Host(
            ip="10.0.0.21",
            os="Linux 5.0 - 6.2",
            ports=[
                Port(
                    port=22,
                    service="ssh",
                    product="OpenSSH",
                    version="9.2p1",
                    extrainfo="Debian-12",
                )
            ],
        )
        analyzer.refine_os(host)
        self.assertEqual(host.os, "Debian 12")

    def test_classify_proxmox_guest_keeps_distro(self) -> None:
        host = Host(
            ip="10.0.0.22",
            mac="BC:24:11:AA:BB:CC",
            os="Ubuntu 24.04",
            ports=[Port(port=22, service="ssh")],
        )
        analyzer.classify_host(host)
        self.assertEqual(host.type, "Guest Proxmox (LXC/VM)")
        self.assertEqual(host.os, "Ubuntu 24.04")

    def test_classify_vm_by_mac_prefix(self) -> None:
        host = Host(
            ip="10.0.0.23",
            mac="52:54:00:12:34:56",
            os="Linux 5.0 - 6.2",
            ports=[Port(port=22, service="ssh")],
        )
        analyzer.classify_host(host)
        self.assertEqual(host.type, "Máquina virtual (QEMU/KVM)")
        self.assertEqual(host.os, "Linux 5.0 - 6.2 (VM QEMU/KVM)")

    def test_classify_proxmox_node_os(self) -> None:
        host = Host(
            ip="10.0.0.24",
            os="Linux 5.0 - 6.2",
            ports=[Port(port=8006, service="https")],
        )
        analyzer.classify_host(host)
        self.assertEqual(host.type, "Nodo Proxmox")
        self.assertIn("Proxmox VE", host.os)

    def test_scanner_applies_snmp_sysdescr_to_host(self) -> None:
        host = Host(ip="10.0.0.13", os="Linux 5.0 - 5.4")
        scanner._apply_snmp_meta(
            {host.ip: host},
            {"snmp": {host.ip: {"sysDescr": "RouterOS RB750Gr3 6.49.23 (stable)"}}},
        )
        self.assertEqual(host.os, "MikroTik RouterOS 6.49.23")

    def test_os_from_sysdescr(self) -> None:
        self.assertEqual(
            analyzer.os_from_sysdescr("RouterOS RB750Gr3 6.49.23 (stable)"),
            "MikroTik RouterOS 6.49.23",
        )
        self.assertEqual(
            analyzer.os_from_sysdescr("Linux router 5.10.0-28-amd64 #1 SMP"),
            "Linux 5.10.0-28-amd64",
        )
        self.assertEqual(analyzer.os_from_sysdescr(""), "")

    def test_counts_by_severity(self) -> None:
        counts = counts_by_severity(
            [Finding(severity="ALTO", title="a"), Finding(severity="ALTO", title="b")]
        )
        self.assertEqual(counts["ALTO"], 2)
        self.assertEqual(counts["CRÍTICO"], 0)


class AttackTests(unittest.TestCase):
    def test_matrix_and_kill_chain(self) -> None:
        findings = [
            Finding(
                severity="CRÍTICO",
                title="Redis expuesto",
                host="10.0.0.5",
                tags=["database", "redis"],
                source="heuristic",
            ),
            Finding(
                severity="ALTO",
                title="Credenciales válidas encontradas",
                host="10.0.0.5",
                tags=["credentials", "brute-force"],
                source="hydra",
            ),
        ]
        matrix = attack.build_matrix(findings)
        self.assertEqual(len(matrix["tactics"]), len(attack.TACTICS))
        self.assertGreater(matrix["unique"], 0)
        chain = attack.build_kill_chain([Host(ip="10.0.0.5")], findings)
        self.assertEqual(len(chain["stages"]), 7)
        self.assertGreaterEqual(chain["observed"], 1)

    def test_technique_mapping(self) -> None:
        finding = Finding(
            severity="ALTO",
            title="SMB expuesto",
            host="10.0.0.10",
            tags=["smb"],
        )
        ids = attack.techniques_for_finding(finding)
        self.assertIn("T1021.002", ids)

    def test_coverage(self) -> None:
        data = attack.coverage(["nmap", "nuclei"])
        self.assertGreater(data["total_covered"], 0)
        self.assertIn("nmap", data["tools"])


class FrameworkTests(unittest.TestCase):
    def test_enrichment(self) -> None:
        finding = Finding(
            severity="MEDIO",
            title="Cabeceras de seguridad HTTP ausentes",
            host="10.0.0.7",
            tags=["web", "misconfig"],
            source="http_probe",
        )
        data = frameworks.enrich(finding)
        self.assertEqual(data["ptes"]["phase"], "vulnerability-analysis")
        self.assertEqual(data["osstmm"]["module"], "NET-APP")
        self.assertIn("A05", data["owasp"]["top10"])
        self.assertTrue(data["cwe"])

    def test_summary(self) -> None:
        findings = [
            Finding(severity="ALTO", title="SMB expuesto", tags=["smb"]),
            Finding(severity="MEDIO", title="Cabeceras web", tags=["web"]),
        ]
        summary = frameworks.summary(findings)
        self.assertEqual(len(summary["ptes"]), len(frameworks.PTES_PHASES))
        self.assertTrue(summary["owasp"]["top10"])
        self.assertTrue(summary["cwe"])


if __name__ == "__main__":
    unittest.main()
