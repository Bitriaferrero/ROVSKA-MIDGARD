"""Tests de evidencias, informes y plan de Metasploit."""

from __future__ import annotations

import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from midgard import audit, evidence, msf, nmap, osdetect, report


FIXTURE = Path(__file__).parent / "fixtures" / "lan_mixed.xml"
META = {
    "target": "192.168.88.0/24",
    "profile": "quick",
    "run_id": "test-run",
    "created_at": "2026-01-01T00:00:00+00:00",
    "status": "ok",
}


class ReportTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.run_dir = Path(self.tmp.name) / "run"
        self.run_dir.mkdir()
        self.hosts = osdetect.detect_all(
            nmap.parse_xml(FIXTURE.read_text(encoding="utf-8"))
        )

    def tearDown(self):
        self.tmp.cleanup()

    def test_artifacts_and_manifest(self):
        report.write_json(self.run_dir, self.hosts, META)
        report.write_csv(self.run_dir, self.hosts)
        report.write_html(self.run_dir, self.hosts, META)
        manifest = evidence.write_manifest(self.run_dir, META)

        for name in ("hosts.json", "hosts.csv", "report.html", "manifest.json"):
            self.assertTrue((self.run_dir / name).is_file(), name)

        self.assertFalse(manifest["ai_runtime"])
        self.assertFalse(manifest["telemetry"])
        self.assertIn("hosts.json", manifest["artifacts"])
        expected = evidence.sha256_file(self.run_dir / "hosts.json")
        self.assertEqual(manifest["artifacts"]["hosts.json"]["sha256"], expected)

    def test_html_contains_os(self):
        path = report.write_html(self.run_dir, self.hosts, META)
        page = path.read_text(encoding="utf-8")
        self.assertIn("Ubuntu", page)
        self.assertIn("Windows 11", page)
        self.assertIn("MikroTik RouterOS", page)
        self.assertIn("hash", page.lower())

    def test_hosts_roundtrip(self):
        report.write_json(self.run_dir, self.hosts, META)
        payload = json.loads((self.run_dir / "hosts.json").read_text(encoding="utf-8"))
        restored = [nmap.Host.from_dict(item) for item in payload["hosts"]]
        self.assertEqual(len(restored), len(self.hosts))
        self.assertEqual(restored[0].ip, self.hosts[0].ip)
        self.assertEqual(restored[0].os["name"], self.hosts[0].os["name"])

    def test_refresh_manifest_picks_up_new_artifact(self):
        report.write_json(self.run_dir, self.hosts, META)
        evidence.write_manifest(self.run_dir, META)
        (self.run_dir / "msf_plan.rc").write_text("exit -y\n", encoding="utf-8")
        manifest = evidence.refresh_manifest(self.run_dir)
        self.assertIn("msf_plan.rc", manifest["artifacts"])
        expected = evidence.sha256_file(self.run_dir / "msf_plan.rc")
        self.assertEqual(manifest["artifacts"]["msf_plan.rc"]["sha256"], expected)


class MsfPlanTests(unittest.TestCase):
    def test_plan_only_uses_auxiliary(self):
        hosts = osdetect.detect_all(
            nmap.parse_xml(FIXTURE.read_text(encoding="utf-8"))
        )
        rc = msf.build_rc(hosts, "run-123")
        self.assertIn("auxiliary/scanner/ssh/ssh_version", rc)
        self.assertIn("auxiliary/scanner/smb/smb_version", rc)
        self.assertNotIn("exploit/", rc)
        self.assertNotIn("payload", rc.lower())
        self.assertIn("exit -y", rc)


class EvidenceTests(unittest.TestCase):
    def test_run_ids_are_unique(self):
        with tempfile.TemporaryDirectory() as tmp:
            with mock.patch.dict(os.environ, {"MIDGARD_EVIDENCE": tmp}):
                first = evidence.new_run("192.168.1.0/24", "quick")
                second = evidence.new_run("192.168.1.0/24", "quick")
                self.assertNotEqual(first, second)
                self.assertTrue(first.is_dir())
                self.assertTrue(second.is_dir())


class AuditTests(unittest.TestCase):
    def test_runtime_is_offline(self):
        result = audit.audit()
        self.assertTrue(result["ok"], result["findings"])
        self.assertGreater(result["files_scanned"], 5)


if __name__ == "__main__":
    unittest.main()
