#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Tests de persistencia y generación de informes."""

from __future__ import annotations

import atexit
import json
import os
import shutil
import tempfile
import unittest
import xml.etree.ElementTree as ET
from pathlib import Path

# Los tests nunca deben tocar data/ del usuario: base de datos temporal.
_TEST_DATA = tempfile.mkdtemp(prefix="rovska-tests-")
os.environ["ROVSKA_DATA_DIR"] = _TEST_DATA
atexit.register(shutil.rmtree, _TEST_DATA, ignore_errors=True)

from rovvska import config

config.reset_settings()

from rovvska import compare, db, importer, report


SCAN_ID = "scan_test_report"


def _reset() -> None:
    db.init_db()
    with db.tx() as conn:
        for table in ("findings", "good_checks", "ports", "hosts", "tool_runs", "operations", "scans"):
            conn.execute(f"DELETE FROM {table}")


def _seed() -> None:
    now = db.utc_now()
    with db.tx() as conn:
        conn.execute(
            "INSERT INTO scans (id, target, profile, mode, status, started_at, finished_at, options_json, stats_json) "
            "VALUES (?,?,?,?,?,?,?,?,?)",
            (
                SCAN_ID,
                "10.0.0.0/24",
                "quick",
                "top-ports-1000",
                "done",
                now,
                now,
                "{}",
                json.dumps(
                    {
                        "proxmox": {"cluster": "pve", "quorate": "1"},
                        "scope": {"allowed": True, "reason": "dentro de alcance"},
                    }
                ),
            ),
        )
        conn.execute(
            "INSERT INTO hosts (scan_id, ip, mac, vendor, hostnames_json, os, type, risk, extra_json) "
            "VALUES (?,?,?,?,?,?,?,?,?)",
            (
                SCAN_ID,
                "10.0.0.5",
                "bc:24:11:00:00:01",
                "Proxmox",
                json.dumps(["pve.local"]),
                "Proxmox VE 8.2",
                "Nodo Proxmox",
                45,
                json.dumps({"risk": 45}),
            ),
        )
        conn.execute(
            "INSERT INTO ports (scan_id, ip, port, proto, state, service, product, version, extrainfo, scripts_json) "
            "VALUES (?,?,?,?,?,?,?,?,?,?)",
            (
                SCAN_ID,
                "10.0.0.5",
                8006,
                "tcp",
                "open",
                "http",
                "Proxmox",
                "8.2",
                "",
                json.dumps({"http-title": "Proxmox VE"}),
            ),
        )
        conn.execute(
            "INSERT INTO findings (id, scan_id, ip, severity, title, evidence, recommendation, cves_json, "
            "cwe_json, attack_json, frameworks_json, source, confidence, tags_json, created_at) "
            "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (
                "f_test_1",
                SCAN_ID,
                "10.0.0.5",
                "ALTO",
                "Interfaz Proxmox expuesta",
                "10.0.0.5:8006 abierto",
                "Restringir a la LAN de gestión",
                "[]",
                json.dumps(["CWE-668"]),
                json.dumps(["T1190"]),
                json.dumps(
                    {
                        "ptes": {"phase": "vulnerability-analysis", "name": "Vulnerability Analysis"},
                        "osstmm": {"channel": "Data Networks", "module": "NET-SEC", "name": "Seguridad de redes de datos"},
                        "owasp": {"top10": ["A05"], "top10_names": [], "wstg": ["WSTG-CONF"]},
                        "cwe": ["CWE-668"],
                    }
                ),
                "heuristic",
                "alta",
                json.dumps(["exposure", "proxmox"]),
                now,
            ),
        )
        conn.execute(
            "INSERT INTO findings (id, scan_id, ip, severity, title, evidence, recommendation, cves_json, "
            "cwe_json, attack_json, frameworks_json, source, confidence, tags_json, created_at) "
            "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (
                "f_test_2",
                SCAN_ID,
                "10.0.0.5",
                "BAJO",
                "Servicio obsoleto expuesto",
                "10.0.0.5:8006 ejecuta una versión antigua",
                "Actualizar el servicio",
                "[]",
                json.dumps(["CWE-1104"]),
                json.dumps([]),
                json.dumps({}),
                "heuristic",
                "media",
                json.dumps(["obsolete"]),
                now,
            ),
        )
        conn.execute(
            "INSERT INTO good_checks (scan_id, text) VALUES (?,?)",
            (SCAN_ID, "No se detectó SMB expuesto."),
        )


def _seed_second() -> None:
    now = db.utc_now()
    with db.tx() as conn:
        conn.execute(
            "INSERT INTO scans (id, target, profile, mode, status, started_at, finished_at, options_json, stats_json) "
            "VALUES (?,?,?,?,?,?,?,?,?)",
            (
                "scan_test_second",
                "10.0.0.0/24",
                "quick",
                "top-ports-1000",
                "done",
                now,
                now,
                "{}",
                json.dumps({"scope": {"allowed": True, "reason": "dentro de alcance"}}),
            ),
        )
        for ip, host_type, risk in (
            ("10.0.0.5", "Nodo Proxmox", 6),
            ("10.0.0.9", "Servidor / servicio", 15),
        ):
            conn.execute(
                "INSERT INTO hosts (scan_id, ip, mac, vendor, hostnames_json, os, type, risk, extra_json) "
                "VALUES (?,?,?,?,?,?,?,?,?)",
                (
                    "scan_test_second",
                    ip,
                    "",
                    "",
                    "[]",
                    "Linux",
                    host_type,
                    risk,
                    json.dumps({"risk": risk, "risk_meta": {"score": risk, "label": "Bajo", "cls": "low"}}),
                ),
            )
        conn.execute(
            "INSERT INTO ports (scan_id, ip, port, proto, state, service, product, version, extrainfo, scripts_json) "
            "VALUES (?,?,?,?,?,?,?,?,?,?)",
            ("scan_test_second", "10.0.0.5", 8006, "tcp", "open", "http", "Proxmox", "8.2", "", "{}"),
        )
        conn.execute(
            "INSERT INTO ports (scan_id, ip, port, proto, state, service, product, version, extrainfo, scripts_json) "
            "VALUES (?,?,?,?,?,?,?,?,?,?)",
            ("scan_test_second", "10.0.0.9", 443, "tcp", "open", "https", "nginx", "1.24", "", "{}"),
        )
        rows = [
            (
                "f2_1",
                "10.0.0.5",
                "MEDIO",
                "Interfaz Proxmox expuesta",
                "10.0.0.5:8006 abierto",
                "Restringir a la LAN de gestión",
                [],
                ["CWE-668"],
                ["T1190"],
            ),
            (
                "f2_2",
                "10.0.0.9",
                "ALTO",
                "TLS débil",
                "10.0.0.9:443 acepta TLS 1.0",
                "Deshabilitar TLS 1.0/1.1",
                [],
                ["CWE-327"],
                ["T1595.002"],
            ),
        ]
        for ident, ip, severity, title, evidence, recommendation, cves, cwes, techniques in rows:
            conn.execute(
                "INSERT INTO findings (id, scan_id, ip, severity, title, evidence, recommendation, cves_json, "
                "cwe_json, attack_json, frameworks_json, source, confidence, tags_json, created_at) "
                "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (
                    ident,
                    "scan_test_second",
                    ip,
                    severity,
                    title,
                    evidence,
                    recommendation,
                    json.dumps(cves),
                    json.dumps(cwes),
                    json.dumps(techniques),
                    json.dumps({}),
                    "heuristic",
                    "alta",
                    json.dumps([]),
                    now,
                ),
            )
        conn.execute(
            "INSERT INTO good_checks (scan_id, text) VALUES (?,?)",
            ("scan_test_second", "TLS moderno en el resto de hosts."),
        )


class ReportTests(unittest.TestCase):
    def setUp(self) -> None:
        # Barrera de seguridad: si esto falla, el test borraría datos reales.
        self.assertTrue(str(db.SETTINGS.db_path).startswith(_TEST_DATA))
        _reset()
        _seed()

    def test_build_report_compatibility(self) -> None:
        data = report.build(SCAN_ID)
        for key in (
            "target",
            "scanned_at",
            "mode",
            "hosts",
            "findings",
            "good_checks",
            "proxmox",
            "counts",
            "attack",
            "frameworks",
            "operations",
            "limitations",
        ):
            self.assertIn(key, data)
        self.assertEqual(data["target"], "10.0.0.0/24")
        self.assertEqual(len(data["hosts"]), 1)
        self.assertEqual(data["counts"]["ALTO"], 1)
        self.assertGreater(data["attack"]["matrix"]["unique"], 0)
        self.assertEqual(len(data["attack"]["kill_chain"]["stages"]), 7)

    def test_write_all_formats(self) -> None:
        paths = report.write_reports(SCAN_ID, include_pdf=False)
        self.assertEqual(set(paths), {"json", "xml", "html", "sarif", "csv"})
        for path in paths.values():
            self.assertTrue(Path(path).is_file(), path)
            self.assertGreater(Path(path).stat().st_size, 100, path)

        payload = json.loads(Path(paths["json"]).read_text(encoding="utf-8"))
        self.assertEqual(payload["schema_version"], "2.0")
        self.assertFalse(payload["stats"]["pdf"]["ok"])

        root = ET.fromstring(Path(paths["xml"]).read_text(encoding="utf-8"))
        self.assertEqual(root.tag, "rovska-report")
        self.assertIsNotNone(root.find("findings/finding"))

        sarif = json.loads(Path(paths["sarif"]).read_text(encoding="utf-8"))
        self.assertEqual(sarif["version"], "2.1.0")
        self.assertTrue(sarif["runs"][0]["results"])

        csv_text = Path(paths["csv"]).read_text(encoding="utf-8")
        self.assertIn("severidad", csv_text.splitlines()[0])

        html = Path(paths["html"]).read_text(encoding="utf-8")
        self.assertIn("Cadena de ataque reconstruida", html)
        self.assertIn("ATT&amp;CK", html)

    def test_pdf_html_has_cover_and_paged_css(self) -> None:
        html = report.render_html(report.build(SCAN_ID), for_pdf=True)
        self.assertIn('class="cover"', html)
        self.assertIn("Resumen ejecutivo", html)
        self.assertIn("@page cover", html)
        self.assertIn("counter(page)", html)
        self.assertIn("Hallazgos prioritarios", html)
        self.assertIn("Control del documento", html)

    def test_report_paths_are_safe(self) -> None:
        paths = report.write_reports(SCAN_ID, include_pdf=False)
        for path in paths.values():
            self.assertIn("informe_", Path(path).name)
            self.assertNotIn("..", Path(path).name)

    def test_compare_scans(self) -> None:
        _seed_second()
        data = compare.compare_scans(SCAN_ID, "scan_test_second")
        self.assertEqual(data["delta"]["findings"], 0)  # 2 hallazgos en ambos
        self.assertEqual(data["delta"]["risk"], 4)  # 17 -> 21
        self.assertEqual([item["title"] for item in data["findings"]["added"]], ["TLS débil"])
        self.assertEqual(
            [item["title"] for item in data["findings"]["removed"]], ["Servicio obsoleto expuesto"]
        )
        self.assertEqual(len(data["findings"]["changed"]), 1)
        self.assertEqual(data["findings"]["changed"][0]["before"], "ALTO")
        self.assertEqual(data["findings"]["changed"][0]["after"], "MEDIO")
        self.assertEqual([host["ip"] for host in data["hosts"]["added"]], ["10.0.0.9"])
        self.assertEqual([port["port"] for port in data["ports"]["added"]], [443])

    def test_import_json_creates_scan(self) -> None:
        original = report.write_reports(SCAN_ID, include_pdf=False)
        original_payload = json.loads(Path(original["json"]).read_text(encoding="utf-8"))
        payload = json.dumps(original_payload, ensure_ascii=False)
        result = importer.import_text(
            payload, filename="informe.json", include_pdf=False
        )
        self.assertTrue(result["ok"])
        self.assertTrue(result["scan_id"].startswith("scan_"))
        self.assertEqual(result["hosts"], 1)
        self.assertEqual(result["findings"], 2)
        self.assertEqual(result["format"], "json")
        imported = report.build(result["scan_id"])
        self.assertEqual(imported["target"], "10.0.0.0/24")
        self.assertEqual(imported["stats"]["imported"], True)
        self.assertEqual(len(imported["findings"]), 2)
        # Importar el informe de un escaneo no debe sobrescribir su evidencia.
        self.assertNotEqual(result["reports"]["json"], original["json"])
        kept = json.loads(Path(original["json"]).read_text(encoding="utf-8"))
        self.assertEqual(kept["scan_id"], SCAN_ID)
        self.assertIn("_", Path(result["reports"]["json"]).stem[len(Path(original["json"]).stem):])

    def test_import_xml_creates_scan(self) -> None:
        payload = report.render_xml(report.build(SCAN_ID))
        result = importer.import_text(payload, filename="informe.xml", include_pdf=False)
        self.assertTrue(result["ok"])
        self.assertEqual(result["format"], "xml")
        imported = report.build(result["scan_id"])
        self.assertEqual(len(imported["findings"]), 2)
        self.assertEqual(imported["hosts"][0]["ip"], "10.0.0.5")

    def test_import_rejects_invalid_content(self) -> None:
        with self.assertRaises(ValueError):
            importer.import_text("", filename="vacio.json", include_pdf=False)
        with self.assertRaises(ValueError):
            importer.import_text("{no json", filename="roto.json", include_pdf=False)


if __name__ == "__main__":
    unittest.main()
