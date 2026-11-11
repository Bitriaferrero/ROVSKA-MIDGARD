#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Tests de la adopción de trabajos persistidos (MIDGARD/NETMAP).

Cuando el panel se reinicia mientras un proceso sigue vivo, el lector de la
tubería desaparece y el JSON del trabajo puede quedarse en ``running``. Estos
tests comprueban que el estado final se recupera del log o de la evidencia, y
que un trabajo realmente desaparecido se marca como interrumpido.
"""

from __future__ import annotations

import atexit
import json
import os
import shutil
import tempfile
import unittest
from collections import deque
from pathlib import Path
from unittest import mock

# Nunca tocar data/ del usuario.
if "ROVSKA_DATA_DIR" not in os.environ:
    _TEST_DATA = tempfile.mkdtemp(prefix="rovska-integrations-")
    os.environ["ROVSKA_DATA_DIR"] = _TEST_DATA
    atexit.register(shutil.rmtree, _TEST_DATA, ignore_errors=True)
    from rovvska import config

    config.reset_settings()

from rovvska import integrations


class AdoptPersistedTests(unittest.TestCase):
    def setUp(self) -> None:
        self.work = Path(tempfile.mkdtemp(prefix="rovska-work-"))
        self.evidence = Path(tempfile.mkdtemp(prefix="rovska-evidence-"))
        self.addCleanup(shutil.rmtree, self.work, ignore_errors=True)
        self.addCleanup(shutil.rmtree, self.evidence, ignore_errors=True)
        patcher_work = mock.patch.object(integrations, "WORK_DIR", self.work)
        patcher_evidence = mock.patch.object(integrations, "EVIDENCE_DIR", self.evidence)
        patcher_work.start()
        patcher_evidence.start()
        self.addCleanup(patcher_work.stop)
        self.addCleanup(patcher_evidence.stop)

    def _job(self, **overrides) -> dict:
        data = {
            "id": "midgard-20261108-050000-abcdef",
            "kind": "midgard",
            "target": "192.168.88.0/24",
            "status": "running",
            "started_at": "2026-11-08 05:00:00",
            "finished_at": "",
            "exit_code": None,
            "pid": 0,
        }
        data.update(overrides)
        return data

    def _write_log(self, job_id: str, lines: list[str]) -> None:
        (self.work / f"{job_id}.log").write_text("\n".join(lines) + "\n", encoding="utf-8")

    def _write_evidence(self, name: str, target: str, status: str = "ok") -> None:
        run = self.evidence / name
        run.mkdir(parents=True, exist_ok=True)
        (run / "manifest.json").write_text(
            json.dumps(
                {
                    "target": target,
                    "profile": "full",
                    "status": status,
                    "created_at": "2026-11-08T05:50:00+01:00",
                }
            ),
            encoding="utf-8",
        )

    def test_log_marks_a_finished_midgard_job_ok(self) -> None:
        job = self._job()
        self._write_log(
            job["id"],
            [
                "  ejecutando nmap (límite 7200s)…",
                "[ok]   evidencia: /tmp/run",
                "[ok]   informe:   /tmp/run/report.html",
                "[ok]   manifiesto:/tmp/run/manifest.json",
            ],
        )

        data = integrations._adopt_persisted(job)
        self.assertFalse(data["live"])
        self.assertEqual(data["status"], "ok")
        self.assertEqual(data["exit_code"], 0)
        self.assertTrue(data["finished_at"])

    def test_log_marks_a_netmap_job_ok(self) -> None:
        job = self._job(id="netmap-20261108-050000-abcdef", kind="netmap", target="wlan0")
        self._write_log(
            job["id"],
            [
                "[+] 5 dispositivos por ARP",
                "OK: 5 hosts -> /home/rorshach/ROVSKA-MIDGARD/netmap/map/index.html",
            ],
        )

        data = integrations._adopt_persisted(job)
        self.assertEqual(data["status"], "ok")

    def test_evidence_recovers_a_job_without_log_tail(self) -> None:
        job = self._job()
        self._write_log(job["id"], ["  ejecutando nmap (límite 7200s)…"])
        self._write_evidence("20261108-050000-full-192_168_88_0_24", "192.168.88.0/24")

        data = integrations._adopt_persisted(job)
        self.assertEqual(data["status"], "ok")
        self.assertEqual(data["exit_code"], 0)
        self.assertTrue(data["finished_at"])

    def test_evidence_without_manifest_does_not_claim_success(self) -> None:
        job = self._job()
        self._write_log(job["id"], ["  ejecutando nmap (límite 7200s)…"])
        (self.evidence / "20261108-050000-full-192_168_88_0_24").mkdir()

        data = integrations._adopt_persisted(job)
        self.assertEqual(data["status"], "interrupted")

    def test_missing_process_without_trace_is_interrupted(self) -> None:
        job = self._job()
        data = integrations._adopt_persisted(job)
        self.assertEqual(data["status"], "interrupted")
        self.assertFalse(data["live"])
        self.assertTrue(data["error"])

    def test_live_process_is_kept_running(self) -> None:
        job = self._job(pid=os.getpid())
        with mock.patch.object(integrations, "_pid_alive", return_value=True):
            data = integrations._adopt_persisted(job)
        self.assertTrue(data["live"])
        self.assertEqual(data["status"], "running")


class CancelJobTests(unittest.TestCase):
    def setUp(self) -> None:
        self.work = Path(tempfile.mkdtemp(prefix="rovska-cancel-"))
        self.evidence = Path(tempfile.mkdtemp(prefix="rovska-cancel-evidence-"))
        self.addCleanup(shutil.rmtree, self.work, ignore_errors=True)
        self.addCleanup(shutil.rmtree, self.evidence, ignore_errors=True)
        patcher_work = mock.patch.object(integrations, "WORK_DIR", self.work)
        patcher_evidence = mock.patch.object(integrations, "EVIDENCE_DIR", self.evidence)
        patcher_work.start()
        patcher_evidence.start()
        self.addCleanup(patcher_work.stop)
        self.addCleanup(patcher_evidence.stop)
        self._saved_jobs = dict(integrations._JOBS)
        with integrations._LOCK:
            integrations._JOBS.clear()
        self.addCleanup(self._restore_jobs)

    def _restore_jobs(self) -> None:
        with integrations._LOCK:
            integrations._JOBS.clear()
            integrations._JOBS.update(self._saved_jobs)

    def _add_running(self, job_id: str = "midgard-live") -> dict:
        job = {
            "id": job_id,
            "kind": "midgard",
            "label": "full · 192.168.88.0/24",
            "target": "192.168.88.0/24",
            "status": "running",
            "started_at": "2026-11-09 10:00:00",
            "finished_at": "",
            "exit_code": None,
            "pid": 12345,
            "log": deque(["MIDGARD 0.1.0", "ejecutando nmap…"], maxlen=2000),
        }
        with integrations._LOCK:
            integrations._JOBS[job_id] = job
        return job

    def test_cancel_running_job_marks_it_cancelled(self) -> None:
        self._add_running()
        with mock.patch.object(integrations, "_terminate") as terminate:
            data = integrations.cancel_job("midgard-live")

        terminate.assert_called_once()
        self.assertEqual(data["status"], "cancelled")
        self.assertTrue(data["cancelled"])
        self.assertEqual(data["exit_code"], 130)
        self.assertTrue(data["finished_at"])
        self.assertFalse(data["live"])

    def test_cancel_finished_job_changes_nothing(self) -> None:
        job = self._add_running()
        with integrations._LOCK:
            job["status"] = "ok"
            job["finished_at"] = "2026-11-09 10:30:00"
            job["exit_code"] = 0

        with mock.patch.object(integrations, "_terminate") as terminate:
            data = integrations.cancel_job("midgard-live")

        terminate.assert_not_called()
        self.assertEqual(data["status"], "ok")
        self.assertFalse(data["cancelled"])

    def test_cancel_writes_cancelled_manifest_for_partial_evidence(self) -> None:
        job = self._add_running()
        run = self.evidence / "20261109-100000-full-192_168_88_0_24"
        run.mkdir(parents=True)
        (run / "command.txt").write_text("# MIDGARD\n", encoding="utf-8")

        with mock.patch.object(integrations, "_terminate"):
            integrations.cancel_job(job["id"])

        manifest = json.loads((run / "manifest.json").read_text(encoding="utf-8"))
        self.assertEqual(manifest["status"], "cancelled")
        self.assertEqual(manifest["run_id"], run.name)
        self.assertEqual(manifest["returncode"], 130)
        self.assertEqual(manifest["target"], "192.168.88.0/24")
        self.assertEqual(manifest["profile"], "full")

    def test_cancel_keeps_a_finished_manifest_untouched(self) -> None:
        job = self._add_running()
        run = self.evidence / "20261109-100000-full-192_168_88_0_24"
        run.mkdir(parents=True)
        original = {"status": "ok", "target": "192.168.88.0/24"}
        (run / "manifest.json").write_text(json.dumps(original), encoding="utf-8")

        with mock.patch.object(integrations, "_terminate"):
            integrations.cancel_job(job["id"])

        manifest = json.loads((run / "manifest.json").read_text(encoding="utf-8"))
        self.assertEqual(manifest, original)

    def test_cancel_unknown_job_returns_none(self) -> None:
        self.assertIsNone(integrations.cancel_job("midgard-no-existe"))


if __name__ == "__main__":
    unittest.main()
