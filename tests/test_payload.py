#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Tests de la lista unificada de IPs (ROVSKA + MIDGARD).

Regla que se comprueba:
  - un barrido de subred abre un contexto nuevo y limpia la lista;
  - un escaneo de una IP suelta se suma al contexto vigente;
  - un barrido en curso limpia la lista desde el primer momento;
  - la evidencia de MIDGARD alimenta la misma lista que ROVSKA.
"""

from __future__ import annotations

import atexit
import json
import os
import shutil
import tempfile
import unittest
from pathlib import Path
from unittest import mock

# Nunca tocar data/ del usuario.
if "ROVSKA_DATA_DIR" not in os.environ:
    _TEST_DATA = tempfile.mkdtemp(prefix="rovska-payload-")
    os.environ["ROVSKA_DATA_DIR"] = _TEST_DATA
    atexit.register(shutil.rmtree, _TEST_DATA, ignore_errors=True)
    from rovvska import config

    config.reset_settings()

from rovvska import api, db


TABLES = (
    "events",
    "findings",
    "good_checks",
    "ports",
    "hosts",
    "tool_runs",
    "operations",
    "scans",
    "task_dismissals",
)


def _reset() -> None:
    db.init_db()
    with db.tx() as conn:
        for table in TABLES:
            conn.execute(f"DELETE FROM {table}")


def _add_scan(
    scan_id: str,
    target: str,
    started_at: str,
    profile: str = "full",
    status: str = "done",
) -> None:
    with db.tx() as conn:
        conn.execute(
            "INSERT INTO scans (id, target, profile, mode, status, started_at, finished_at, "
            "options_json, stats_json) VALUES (?,?,?,?,?,?,?,?,?)",
            (scan_id, target, profile, profile, status, started_at, started_at, "{}", "{}"),
        )


def _add_host(scan_id: str, ip: str, os_name: str = "", type_name: str = "") -> None:
    with db.tx() as conn:
        conn.execute(
            "INSERT INTO hosts (scan_id, ip, mac, vendor, hostnames_json, os, type, risk, extra_json) "
            "VALUES (?,?,?,?,?,?,?,?,?)",
            (scan_id, ip, "", "", "[]", os_name, type_name, 0, "{}"),
        )


class PayloadContextTests(unittest.TestCase):
    def setUp(self) -> None:
        _reset()
        self.evidence = Path(tempfile.mkdtemp(prefix="rovska-evidence-empty-"))
        self.addCleanup(shutil.rmtree, self.evidence, ignore_errors=True)

    def _payload(self) -> dict:
        with mock.patch.object(api.JOBS, "list", return_value=[]), mock.patch.object(
            api.integrations, "list_jobs", return_value=[]
        ), mock.patch.object(api.integrations, "EVIDENCE_DIR", self.evidence):
            return api.build_payload()

    def test_subnet_sweep_replaces_previous_context(self) -> None:
        _add_scan("scan_a", "10.0.0.0/24", "2026-01-01 10:00:00")
        _add_host("scan_a", "10.0.0.5", "Debian 12")
        _add_scan("scan_b", "192.168.1.0/24", "2026-01-01 11:00:00")
        _add_host("scan_b", "192.168.1.10", "Ubuntu 22.04")

        payload = self._payload()
        ips = {host["ip"] for host in payload["hosts"]}
        self.assertEqual(ips, {"192.168.1.10"})
        self.assertEqual(payload["global"]["target"], "192.168.1.0/24")

    def test_single_ip_scan_joins_current_context(self) -> None:
        _add_scan("scan_a", "10.0.0.0/24", "2026-01-01 10:00:00")
        _add_host("scan_a", "10.0.0.5", "Debian 12")
        _add_scan("scan_b", "10.0.0.77", "2026-01-01 10:05:00", profile="quick")
        _add_host("scan_b", "10.0.0.77", "Ubuntu 24.04")

        payload = self._payload()
        ips = {host["ip"] for host in payload["hosts"]}
        self.assertEqual(ips, {"10.0.0.5", "10.0.0.77"})

    def test_cancelled_sweep_keeps_previous_context(self) -> None:
        _add_scan("scan_a", "10.0.0.0/24", "2026-01-01 10:00:00")
        _add_host("scan_a", "10.0.0.5", "Debian 12")
        _add_scan("scan_b", "192.168.9.0/24", "2026-01-01 11:00:00", status="cancelled")

        payload = self._payload()
        self.assertEqual({host["ip"] for host in payload["hosts"]}, {"10.0.0.5"})
        self.assertEqual(payload["global"]["target"], "10.0.0.0/24")
        self.assertEqual(payload["global"]["status"], "done")

    def test_payload_incluye_estado_proxmox(self) -> None:
        _add_scan("scan_a", "10.0.0.0/24", "2026-01-01 10:00:00")
        _add_host("scan_a", "10.0.0.5", "Debian 12")
        payload = self._payload()
        self.assertIn("proxmox", payload)
        self.assertFalse(payload["proxmox"]["configured"])
        self.assertEqual(payload["proxmox"]["nodes"], [])

    def test_running_sweep_clears_the_list_immediately(self) -> None:
        _add_scan("scan_a", "10.0.0.0/24", "2026-01-01 10:00:00")
        _add_host("scan_a", "10.0.0.5", "Debian 12")
        running = [
            {
                "id": "scan_running",
                "kind": "scan",
                "status": "running",
                "target": "192.168.88.0/24",
                "started_at": "2026-01-01 12:00:00",
            }
        ]
        with mock.patch.object(api.JOBS, "list", return_value=running), mock.patch.object(
            api.integrations, "list_jobs", return_value=[]
        ), mock.patch.object(api.integrations, "EVIDENCE_DIR", self.evidence):
            payload = api.build_payload()

        self.assertEqual(payload["hosts"], [])
        self.assertTrue(payload["global"]["active_sweep"])
        self.assertEqual(payload["global"]["target"], "192.168.88.0/24")


class MidgardPayloadTests(unittest.TestCase):
    def setUp(self) -> None:
        _reset()
        self.evidence = Path(tempfile.mkdtemp(prefix="rovska-evidence-"))
        self.addCleanup(shutil.rmtree, self.evidence, ignore_errors=True)

    def _write_run(self, name: str, target: str, hosts: list[dict], status: str = "ok") -> None:
        run = self.evidence / name
        run.mkdir(parents=True, exist_ok=True)
        manifest = {
            "target": target,
            "profile": "full",
            "status": status,
            "created_at": "2026-02-01T10:10:00+01:00",
        }
        (run / "manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
        (run / "hosts.json").write_text(
            json.dumps({"meta": manifest, "hosts": hosts}), encoding="utf-8"
        )

    def _payload(self, jobs: list[dict] | None = None) -> dict:
        with mock.patch.object(api.JOBS, "list", return_value=[]), mock.patch.object(
            api.integrations, "list_jobs", return_value=jobs or []
        ), mock.patch.object(api.integrations, "EVIDENCE_DIR", self.evidence):
            return api.build_payload()

    def test_midgard_sweep_feeds_the_panel_and_replaces_rovska(self) -> None:
        _add_scan("scan_old", "10.0.0.0/24", "2026-01-01 10:00:00")
        _add_host("scan_old", "10.0.0.5", "Debian 12")
        self._write_run(
            "20260201-100000-full-192_168_88_0_24",
            "192.168.88.0/24",
            [
                {
                    "ip": "192.168.88.40",
                    "mac": "BC:24:11:AA:BB:CC",
                    "vendor": "",
                    "hostnames": ["web.lan"],
                    "os": {
                        "name": "Ubuntu",
                        "version": "22.04",
                        "device": "Host",
                        "confidence": "alta",
                        "score": 97,
                        "sources": ["banner SSH"],
                    },
                    "ports": [
                        {
                            "port": 22,
                            "proto": "tcp",
                            "state": "open",
                            "service": "ssh",
                            "product": "OpenSSH",
                            "version": "8.9p1",
                            "extrainfo": "Ubuntu-3ubuntu0.1",
                        },
                        {
                            "port": 9999,
                            "proto": "tcp",
                            "state": "filtered",
                            "service": "desconocido",
                        },
                    ],
                }
            ],
        )

        payload = self._payload()
        ips = {host["ip"] for host in payload["hosts"]}
        self.assertEqual(ips, {"192.168.88.40"})
        host = payload["hosts"][0]
        self.assertEqual(host["type"], "Guest Proxmox (LXC/VM)")
        self.assertEqual(host["os"], "Ubuntu 22.04")
        self.assertEqual(len(host["ports"]), 1)
        self.assertEqual(host["ports"][0]["port"], 22)
        self.assertEqual(payload["global"]["source"], "midgard")
        self.assertEqual(payload["global"]["target"], "192.168.88.0/24")

    def test_single_ip_scan_after_midgard_sweep_is_merged(self) -> None:
        self._write_run(
            "20260201-100000-full-192_168_88_0_24",
            "192.168.88.0/24",
            [
                {
                    "ip": "192.168.88.40",
                    "os": {"name": "Debian", "version": "12", "device": "Host"},
                    "ports": [],
                }
            ],
        )
        _add_scan("scan_late", "192.168.88.254", "2026-02-01 10:20:00", profile="quick")
        _add_host("scan_late", "192.168.88.254", "Windows 11")

        payload = self._payload()
        ips = {host["ip"] for host in payload["hosts"]}
        self.assertEqual(ips, {"192.168.88.40", "192.168.88.254"})

    def test_running_midgard_sweep_clears_the_list_immediately(self) -> None:
        _add_scan("scan_old", "10.0.0.0/24", "2026-01-01 10:00:00")
        _add_host("scan_old", "10.0.0.5", "Debian 12")
        jobs = [
            {
                "id": "midgard-running",
                "kind": "midgard",
                "label": "full · 192.168.88.0/24",
                "target": "192.168.88.0/24",
                "status": "running",
                "live": True,
                "started_at": "2026-02-01 11:00:00",
            }
        ]

        payload = self._payload(jobs)
        self.assertEqual(payload["hosts"], [])
        self.assertTrue(payload["global"]["active_sweep"])
        self.assertEqual(payload["global"]["source"], "midgard")


if __name__ == "__main__":
    unittest.main()
