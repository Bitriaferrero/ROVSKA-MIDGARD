#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Tests de la vista de tareas (/api/tasks)."""

from __future__ import annotations

import atexit
import os
import shutil
import tempfile
import threading
import time
import unittest
from collections import deque

# Los tests nunca deben tocar data/ del usuario: base de datos temporal.
# Si otro módulo de test ya configuró una, se reutiliza para no cambiar la
# configuración global a mitad de la ejecución (unittest descubre en orden).
if "ROVSKA_DATA_DIR" not in os.environ:
    _TEST_DATA = tempfile.mkdtemp(prefix="rovska-tasks-")
    os.environ["ROVSKA_DATA_DIR"] = _TEST_DATA
    atexit.register(shutil.rmtree, _TEST_DATA, ignore_errors=True)
    from rovvska import config

    config.reset_settings()

from rovvska import api, db, integrations, scanner
from rovvska.config import SETTINGS
from rovvska.jobs import JOBS, Job


def _reset() -> None:
    db.init_db()
    with db.tx() as conn:
        for table in ("events", "findings", "good_checks", "ports", "hosts", "tool_runs", "operations", "scans", "task_dismissals"):
            conn.execute(f"DELETE FROM {table}")


def _add_scan(scan_id: str, status: str, profile: str = "quick", target: str = "10.0.0.0/24") -> None:
    now = db.utc_now()
    with db.tx() as conn:
        conn.execute(
            "INSERT INTO scans (id, target, profile, mode, status, started_at, finished_at, options_json, stats_json) "
            "VALUES (?,?,?,?,?,?,?,?,?)",
            (
                scan_id,
                target,
                profile,
                "top-ports-1000",
                status,
                now,
                "" if status in {"queued", "running"} else now,
                "{}",
                "{}",
            ),
        )


def _add_operation(operation_id: str, status: str, tool: str = "nmap", scan_id: str = "") -> None:
    now = db.utc_now()
    with db.tx() as conn:
        conn.execute(
            "INSERT INTO operations (id, scan_id, kind, tool, target, params_json, dry_run, status, "
            "started_at, finished_at, result_json) VALUES (?,?,?,?,?,?,?,?,?,?,?)",
            (
                operation_id,
                scan_id,
                "tool",
                tool,
                "10.0.0.5",
                "{}",
                1,
                status,
                now,
                "" if status in {"queued", "running"} else now,
                "{}",
            ),
        )


class TaskPayloadTests(unittest.TestCase):
    def setUp(self) -> None:
        _reset()
        self._saved_jobs = dict(JOBS._jobs)
        with JOBS._lock:
            JOBS._jobs.clear()

    def tearDown(self) -> None:
        with JOBS._lock:
            JOBS._jobs.clear()
            JOBS._jobs.update(self._saved_jobs)

    def test_active_scan_without_job_is_interrupted(self) -> None:
        _add_scan("scan_live", "running")
        payload = api.tasks_payload()
        task = next(item for item in payload["tasks"] if item["id"] == "scan_live")
        self.assertEqual(task["status"], "interrupted")
        self.assertEqual(task["status_label"], "Interrumpido")
        self.assertFalse(task["active"])
        self.assertTrue(task["can_cancel"])
        self.assertEqual(task["type"], "scan")
        self.assertEqual(task["target"], "10.0.0.0/24")
        self.assertEqual(payload["counts"]["interrupted"], 1)

    def test_running_operation_with_job_and_event(self) -> None:
        _add_operation("op_live", "running")
        with db.tx() as conn:
            conn.execute(
                "INSERT INTO events (ts, level, operation_id, scan_id, message) VALUES (?,?,?,?,?)",
                (db.utc_now(), "cmd", "op_live", "", "nmap: $ nmap -sV 10.0.0.5"),
            )
        with JOBS._lock:
            JOBS._jobs["op_live"] = Job(
                id="op_live", kind="operation", status="running", target="10.0.0.5"
            )
        payload = api.tasks_payload()
        task = next(item for item in payload["tasks"] if item["id"] == "op_live")
        self.assertEqual(task["status"], "running")
        self.assertEqual(task["status_label"], "Activo")
        self.assertTrue(task["active"])
        self.assertTrue(task["can_cancel"])
        self.assertEqual(task["cancel_kind"], "operation")
        self.assertIn("nmap -sV", task["current"])
        self.assertEqual(payload["counts"]["active"], 1)

    def test_done_scan_and_import(self) -> None:
        _add_scan("scan_done", "done")
        _add_scan("scan_import", "done", profile="import", target="informe externo")
        with db.tx() as conn:
            conn.execute(
                "INSERT INTO events (ts, level, operation_id, scan_id, message) VALUES (?,?,?,?,?)",
                (db.utc_now(), "done", "", "scan_done", "Escaneo completado: 1 hosts, 2 hallazgos"),
            )
        payload = api.tasks_payload()
        by_id = {item["id"]: item for item in payload["tasks"]}
        self.assertEqual(by_id["scan_done"]["status"], "done")
        self.assertEqual(by_id["scan_done"]["type"], "scan")
        self.assertFalse(by_id["scan_done"]["can_cancel"])
        self.assertIn("Escaneo completado", by_id["scan_done"]["current"])
        self.assertEqual(by_id["scan_import"]["type"], "import")
        self.assertEqual(payload["counts"]["done"], 2)

    def test_job_without_db_entry_is_visible_but_not_cancelable(self) -> None:
        with JOBS._lock:
            JOBS._jobs["orch_1"] = Job(
                id="orch_1", kind="orchestration", status="running", target="10.0.0.7"
            )
        payload = api.tasks_payload()
        task = next(item for item in payload["tasks"] if item["id"] == "orch_1")
        self.assertEqual(task["type"], "orchestration")
        self.assertEqual(task["target"], "10.0.0.7")
        self.assertTrue(task["active"])
        self.assertFalse(task["can_cancel"])
        self.assertFalse(task["log_available"])

    def test_active_tasks_sort_before_history(self) -> None:
        _add_scan("scan_done", "done")
        _add_scan("scan_live", "running")
        ids = [item["id"] for item in api.tasks_payload()["tasks"]]
        self.assertLess(ids.index("scan_live"), ids.index("scan_done"))


class IntegrationTaskTests(unittest.TestCase):
    def setUp(self) -> None:
        _reset()
        self._saved_jobs = dict(integrations._JOBS)
        with integrations._LOCK:
            integrations._JOBS.clear()

    def tearDown(self) -> None:
        with integrations._LOCK:
            integrations._JOBS.clear()
            integrations._JOBS.update(self._saved_jobs)

    def _add_job(self, job_id: str, kind: str, status: str = "running") -> None:
        with integrations._LOCK:
            integrations._JOBS[job_id] = {
                "id": job_id,
                "kind": kind,
                "label": "full · 192.168.88.0/24",
                "target": "192.168.88.0/24",
                "status": status,
                "started_at": time.strftime("%Y-%m-%d %H:%M:%S"),
                "finished_at": "" if status == "running" else time.strftime("%Y-%m-%d %H:%M:%S"),
                "exit_code": None if status == "running" else 0,
                "command": ["python3", "-m", "midgard"],
                "log": deque(["MIDGARD 0.1.0", "ejecutando nmap…"], maxlen=2000),
            }

    def test_running_midgard_job_is_visible_and_active(self) -> None:
        self._add_job("midgard-live", "midgard")
        payload = api.tasks_payload()
        task = next(item for item in payload["tasks"] if item["id"] == "midgard-live")
        self.assertEqual(task["type"], "midgard")
        self.assertEqual(task["target"], "192.168.88.0/24")
        self.assertEqual(task["status"], "running")
        self.assertTrue(task["active"])
        self.assertTrue(task["log_available"])
        self.assertTrue(task["can_cancel"])
        self.assertEqual(task["cancel_kind"], "midgard")
        self.assertEqual(task["current"], "ejecutando nmap…")
        self.assertEqual(payload["counts"]["active"], 1)

    def test_running_netmap_job_is_visible_and_active(self) -> None:
        self._add_job("netmap-live", "netmap")
        payload = api.tasks_payload()
        task = next(item for item in payload["tasks"] if item["id"] == "netmap-live")
        self.assertEqual(task["type"], "netmap")
        self.assertEqual(task["status"], "running")
        self.assertTrue(task["active"])
        self.assertTrue(task["can_cancel"])
        self.assertEqual(task["cancel_kind"], "netmap")

    def test_finished_integration_job_maps_ok_to_done(self) -> None:
        self._add_job("midgard-done", "midgard", status="ok")
        payload = api.tasks_payload()
        task = next(item for item in payload["tasks"] if item["id"] == "midgard-done")
        self.assertEqual(task["status"], "done")
        self.assertFalse(task["active"])
        self.assertFalse(task["can_cancel"])

    def test_persisted_running_job_without_process_is_interrupted(self) -> None:
        self.assertEqual(
            api._integration_task_status({"status": "running", "live": False}),
            "interrupted",
        )


class TaskClearTests(unittest.TestCase):
    def setUp(self) -> None:
        _reset()
        self._saved_jobs = dict(JOBS._jobs)
        with JOBS._lock:
            JOBS._jobs.clear()

    def tearDown(self) -> None:
        with JOBS._lock:
            JOBS._jobs.clear()
            JOBS._jobs.update(self._saved_jobs)

    def test_clear_hides_finished_but_keeps_active(self) -> None:
        _add_scan("scan_done", "done")
        _add_scan("scan_live", "running")
        with JOBS._lock:
            JOBS._jobs["scan_live"] = Job(
                id="scan_live", kind="scan", status="running", target="10.0.0.0/24"
            )

        result = api._clear_tasks()

        self.assertEqual(result["cleared"], 1)
        self.assertEqual(result["kept_active"], 1)
        payload = api.tasks_payload()
        ids = {task["id"] for task in payload["tasks"]}
        self.assertIn("scan_live", ids)
        self.assertNotIn("scan_done", ids)
        self.assertEqual(payload["counts"]["active"], 1)
        self.assertEqual(payload["counts"]["total"], 1)

    def test_clear_does_not_delete_history_or_evidence(self) -> None:
        _add_scan("scan_keep", "done")
        db.record_event("evento conservado", "info")

        api._clear_tasks()

        self.assertIsNotNone(db.query_one("SELECT id FROM scans WHERE id=?", ("scan_keep",)))
        self.assertGreaterEqual(db.query_one("SELECT COUNT(*) AS n FROM events")["n"], 1)

    def test_clear_without_finished_tasks_is_noop(self) -> None:
        _add_scan("scan_live", "running")
        with JOBS._lock:
            JOBS._jobs["scan_live"] = Job(
                id="scan_live", kind="scan", status="running", target="10.0.0.0/24"
            )

        result = api._clear_tasks()

        self.assertEqual(result["cleared"], 0)
        self.assertEqual(result["kept_active"], 1)


class ReportDeletionTests(unittest.TestCase):
    def setUp(self) -> None:
        _reset()

    def test_delete_only_generated_reports(self) -> None:
        reports = SETTINGS.reports_dir
        imports = reports / "imports"
        imports.mkdir(parents=True, exist_ok=True)
        generated = reports / "informe_test.json"
        imported = imports / "informe_importado.json"
        other = reports / "nota.txt"
        generated.write_text("{}", encoding="utf-8")
        imported.write_text("{}", encoding="utf-8")
        other.write_text("no es un informe", encoding="utf-8")

        result = api._delete_reports()

        self.assertTrue(result["ok"])
        self.assertGreaterEqual(result["deleted"], 1)
        self.assertIn(generated.name, result["names"])
        self.assertFalse(generated.exists())
        self.assertTrue(imported.exists())
        self.assertTrue(other.exists())
        self.assertGreaterEqual(result["reports_count"], 0)

        imported.unlink(missing_ok=True)
        other.unlink(missing_ok=True)

    def test_delete_purges_scan_history_and_keeps_audit(self) -> None:
        reports = SETTINGS.reports_dir
        imports = reports / "imports"
        imports.mkdir(parents=True, exist_ok=True)
        generated = reports / "informe_hist.json"
        imported = imports / "informe_hist_importado.json"
        generated.write_text("{}", encoding="utf-8")
        imported.write_text("{}", encoding="utf-8")

        _add_scan("scan_hist", "done", target="10.0.0.0/24")
        now = db.utc_now()
        with db.tx() as conn:
            conn.execute(
                "INSERT INTO hosts (scan_id, ip, os, type, risk) VALUES (?,?,?,?,?)",
                ("scan_hist", "10.0.0.5", "Linux", "server", 10),
            )
            conn.execute(
                "INSERT INTO ports (scan_id, ip, port, proto, service) VALUES (?,?,?,?,?)",
                ("scan_hist", "10.0.0.5", 22, "tcp", "ssh"),
            )
            conn.execute(
                "INSERT INTO findings (id, scan_id, ip, severity, title, created_at) "
                "VALUES (?,?,?,?,?,?)",
                ("finding_hist", "scan_hist", "10.0.0.5", "MEDIO", "SSH abierto", now),
            )
            conn.execute(
                "INSERT INTO good_checks (scan_id, text) VALUES (?,?)",
                ("scan_hist", "sin servicios expuestos"),
            )
            conn.execute(
                "INSERT INTO tool_runs (id, scan_id, tool, started_at) VALUES (?,?,?,?)",
                ("run_hist", "scan_hist", "nmap", now),
            )
        db.save_annotation("10.0.0.5", "server", "nas")
        db.record_event("evento previo", "info")

        result = api._delete_reports()

        self.assertTrue(result["ok"])
        self.assertFalse(generated.exists())
        self.assertTrue(imported.exists())
        self.assertEqual(result["history"]["scans"], 1)
        self.assertEqual(result["history"]["hosts"], 1)
        self.assertEqual(result["history"]["ports"], 1)
        self.assertEqual(result["history"]["findings"], 1)
        self.assertEqual(result["history"]["good_checks"], 1)
        self.assertEqual(result["history"]["tool_runs"], 1)
        for table in ("scans", "hosts", "ports", "findings", "good_checks", "tool_runs"):
            self.assertEqual(db.query_one(f"SELECT COUNT(*) AS n FROM {table}")["n"], 0)
        self.assertEqual(db.load_annotations()["10.0.0.5"]["name"], "nas")
        self.assertGreaterEqual(db.query_one("SELECT COUNT(*) AS n FROM events")["n"], 1)

        imported.unlink(missing_ok=True)

    def test_refuses_to_purge_history_while_scan_is_active(self) -> None:
        _add_scan("scan_active", "running")
        with self.assertRaises(ValueError):
            api._purge_scan_history()


class JobMetadataTests(unittest.TestCase):
    def test_job_exposes_target_and_started_at(self) -> None:
        job = Job(id="j1", kind="scan", target="192.168.1.0/24")
        row = job.to_dict()
        self.assertEqual(row["target"], "192.168.1.0/24")
        self.assertTrue(row["started_at"])
        self.assertEqual(row["status"], "queued")


class CancellationTests(unittest.TestCase):
    def setUp(self) -> None:
        _reset()
        self._saved_jobs = dict(JOBS._jobs)
        with JOBS._lock:
            JOBS._jobs.clear()

    def tearDown(self) -> None:
        with JOBS._lock:
            JOBS._jobs.clear()
            JOBS._jobs.update(self._saved_jobs)

    def test_scan_cancel_is_not_reported_as_error(self) -> None:
        event = threading.Event()
        event.set()
        with self.assertRaises(RuntimeError):
            scanner.run_scan(
                "127.0.0.1", "quick", scan_id="scan_cancel", cancel_event=event
            )
        row = db.query_one("SELECT status, error FROM scans WHERE id=?", ("scan_cancel",))
        self.assertIsNotNone(row)
        self.assertEqual(row["status"], "cancelled")
        self.assertIsNone(row["error"])
        operation = db.query_one(
            "SELECT status FROM operations WHERE scan_id=?", ("scan_cancel",)
        )
        self.assertEqual(operation["status"], "cancelled")

    def test_job_manager_marks_cancelled_after_exception(self) -> None:
        started = threading.Event()

        def work(cancel_event=None):
            started.set()
            cancel_event.wait(2)
            raise RuntimeError("cancelado por el usuario")

        job = JOBS.submit("job_cancel", "test", work, target="127.0.0.1")
        self.assertTrue(started.wait(2))
        self.assertTrue(JOBS.cancel("job_cancel"))
        deadline = time.time() + 3
        while job.status != "cancelled" and time.time() < deadline:
            time.sleep(0.01)
        self.assertEqual(job.status, "cancelled")
        self.assertEqual(job.error, "")


if __name__ == "__main__":
    unittest.main()
