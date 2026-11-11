#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Cola de trabajos en segundo plano para escaneos y operaciones."""

from __future__ import annotations

import threading
import traceback
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from typing import Callable

from . import db


@dataclass
class Job:
    id: str
    kind: str
    status: str = "queued"
    error: str = ""
    target: str = ""
    started_at: str = field(default_factory=db.utc_now)
    cancel_event: threading.Event = field(default_factory=threading.Event)

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "kind": self.kind,
            "status": self.status,
            "error": self.error,
            "target": self.target,
            "started_at": self.started_at,
            "cancelled": self.cancel_event.is_set(),
        }


class JobManager:
    def __init__(self, max_workers: int = 4):
        self._executor = ThreadPoolExecutor(max_workers=max_workers, thread_name_prefix="rovska")
        self._jobs: dict[str, Job] = {}
        self._lock = threading.Lock()

    def submit(
        self, job_id: str, kind: str, fn: Callable, *args, target: str = "", **kwargs
    ) -> Job:
        with self._lock:
            existing = self._jobs.get(job_id)
            if existing and existing.status in {"queued", "running"}:
                return existing
            job = Job(id=job_id, kind=kind, target=target)
            self._jobs[job_id] = job
        self._executor.submit(self._run, job, fn, args, kwargs)
        return job

    def _run(self, job: Job, fn: Callable, args: tuple, kwargs: dict) -> None:
        job.status = "running"
        try:
            fn(*args, cancel_event=job.cancel_event, **kwargs)
            job.status = "cancelled" if job.cancel_event.is_set() else "done"
        except Exception as exc:  # noqa: BLE001
            if job.cancel_event.is_set():
                job.status = "cancelled"
                return
            job.status = "error"
            job.error = str(exc)
            db.record_event(
                f"Trabajo {job.id} fallido: {exc}\n{traceback.format_exc()[-1200:]}",
                "error",
            )

    def cancel(self, job_id: str) -> bool:
        with self._lock:
            job = self._jobs.get(job_id)
        if not job:
            return False
        job.cancel_event.set()
        job.status = "cancelling"
        return True

    def get(self, job_id: str) -> Job | None:
        with self._lock:
            return self._jobs.get(job_id)

    def list(self) -> list[dict]:
        with self._lock:
            return [job.to_dict() for job in self._jobs.values()]

    def shutdown(self) -> None:
        self._executor.shutdown(wait=False, cancel_futures=True)


JOBS = JobManager()
