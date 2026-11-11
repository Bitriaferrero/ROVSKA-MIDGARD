#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Ejecución de comandos en local o dentro del contenedor Kali.

El backend nunca usa ``shell=True``: todas las herramientas se invocan con
listas de argumentos. Así se evita la inyección de comandos desde el panel.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

from .config import Settings


MAX_CAPTURE = 2_000_000  # 2 MB por salida; el resto se trunca.


class Cancelled(RuntimeError):
    """El operador canceló la ejecución en curso."""


@dataclass
class CommandResult:
    argv: list[str]
    returncode: int
    stdout: str = ""
    stderr: str = ""
    duration: float = 0.0
    timed_out: bool = False
    cancelled: bool = False

    @property
    def ok(self) -> bool:
        return self.returncode == 0 and not self.timed_out

    @property
    def output(self) -> str:
        return (self.stdout + ("\n" + self.stderr if self.stderr else "")).strip()

    def to_dict(self) -> dict:
        return {
            "argv": list(self.argv),
            "returncode": self.returncode,
            "stdout": self.stdout,
            "stderr": self.stderr,
            "duration": round(self.duration, 2),
            "timed_out": self.timed_out,
        }


class Runner:
    """Interfaz común de ejecución."""

    name = "base"

    def __init__(self, settings: Settings):
        self.settings = settings
        self._available: dict[str, bool] = {}

    # -- rutas ---------------------------------------------------------
    def workdir(self, operation_id: str) -> Path:
        path = self.settings.work_dir / operation_id
        path.mkdir(parents=True, exist_ok=True)
        return path

    def map_cwd(self, host_cwd: Path) -> str:
        return str(host_cwd)

    def read_text(self, host_path: Path) -> str:
        try:
            return host_path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return ""

    # -- ejecución -----------------------------------------------------
    def available(self, binary: str) -> bool:
        raise NotImplementedError

    def run(
        self,
        argv: list[str],
        timeout: int | None = None,
        cwd: Path | None = None,
        env: dict[str, str] | None = None,
        input_text: str | None = None,
        cancel_event=None,
    ) -> CommandResult:
        raise NotImplementedError

    def _execute(
        self,
        argv: list[str],
        timeout: int,
        cwd: Path | None,
        env: dict[str, str] | None,
        input_text: str | None,
        cancel_event=None,
        kill_hook: Callable[[], None] | None = None,
    ) -> CommandResult:
        started = time.monotonic()
        merged_env = os.environ.copy()
        if env:
            merged_env.update(env)
        try:
            proc = subprocess.Popen(  # noqa: S603 - argv sin shell
                argv,
                cwd=str(cwd) if cwd else None,
                env=merged_env,
                stdin=subprocess.PIPE if input_text is not None else subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                errors="replace",
            )
        except FileNotFoundError as exc:
            return CommandResult(
                argv=argv, returncode=127, stderr=str(exc),
                duration=time.monotonic() - started,
            )
        except OSError as exc:
            return CommandResult(
                argv=argv, returncode=126, stderr=str(exc),
                duration=time.monotonic() - started,
            )

        pending_input = input_text
        stdout = stderr = ""
        timed_out = cancelled = False
        while True:
            try:
                stdout, stderr = proc.communicate(input=pending_input, timeout=0.5)
                break
            except subprocess.TimeoutExpired:
                pending_input = None
                if cancel_event is not None and cancel_event.is_set():
                    cancelled = True
                elif time.monotonic() - started > timeout:
                    timed_out = True
                if not (cancelled or timed_out):
                    continue
                # La cancelación debe alcanzar también al proceso dentro del
                # contenedor: el hook lo mata por su PID antes del cliente.
                if kill_hook is not None:
                    try:
                        kill_hook()
                    except Exception:  # noqa: BLE001 - nunca ocultar el cancel
                        pass
                proc.terminate()
                try:
                    stdout, stderr = proc.communicate(timeout=5)
                except subprocess.TimeoutExpired:
                    proc.kill()
                    stdout, stderr = proc.communicate()
                break
            except OSError as exc:
                stderr = (stderr or "") + str(exc)
                break

        stdout = (stdout or "")[:MAX_CAPTURE]
        stderr = (stderr or "")[:MAX_CAPTURE]
        code = proc.returncode
        if cancelled:
            code = 130
            stderr += "\ncancelado por el usuario"
        elif timed_out:
            code = 124
            stderr += f"\ntimeout tras {timeout}s"
        return CommandResult(
            argv=argv,
            returncode=code,
            stdout=stdout,
            stderr=stderr,
            duration=time.monotonic() - started,
            timed_out=timed_out,
            cancelled=cancelled,
        )


class LocalRunner(Runner):
    """Ejecuta en el host. Solo útil para nmap/nuclei ya instalados."""

    name = "local"

    def available(self, binary: str) -> bool:
        if binary not in self._available:
            self._available[binary] = shutil.which(binary) is not None
        return self._available[binary]

    def run(
        self, argv, timeout=None, cwd=None, env=None, input_text=None, cancel_event=None
    ) -> CommandResult:
        return self._execute(
            argv,
            timeout or self.settings.tool_timeout,
            cwd,
            env,
            input_text,
            cancel_event=cancel_event,
        )


class DockerRunner(Runner):
    """Ejecuta dentro del contenedor Kali con el volumen ``./data:/data``."""

    name = "docker"

    def __init__(self, settings: Settings):
        super().__init__(settings)
        self._container_ok: bool | None = None
        self._container_checked_at = 0.0
        self._available_at: dict[str, float] = {}

    def _docker(self, *args: str, timeout: int = 20) -> CommandResult:
        return self._execute(["docker", *args], timeout, None, None, None)

    def container_running(self) -> bool:
        # Se revalida cada pocos segundos: el contenedor puede arrancar después
        # que el servidor y el panel debe reflejarlo sin reiniciar.
        now = time.monotonic()
        if self._container_ok is None or now - self._container_checked_at > 5:
            result = self._docker(
                "inspect", "-f", "{{.State.Running}}", self.settings.container
            )
            self._container_ok = result.ok and result.stdout.strip() == "true"
            self._container_checked_at = now
        return bool(self._container_ok)

    def available(self, binary: str) -> bool:
        now = time.monotonic()
        cached = self._available.get(binary)
        if cached is not None and now - self._available_at.get(binary, 0.0) < 30:
            return cached
        if not self.container_running():
            self._available[binary] = False
            self._available_at[binary] = now
            return False
        result = self._docker(
            "exec", self.settings.container, "sh", "-lc", f"command -v {shlex_quote(binary)}",
            timeout=15,
        )
        self._available[binary] = result.ok and bool(result.stdout.strip())
        self._available_at[binary] = now
        return self._available[binary]

    def map_cwd(self, host_cwd: Path) -> str:
        try:
            relative = host_cwd.resolve().relative_to(self.settings.data_dir.resolve())
            return "/data/" + relative.as_posix()
        except ValueError:
            return "/data"

    def _kill_container_process(self, host_pid_path: Path) -> Callable[[], None]:
        """Devuelve un hook que mata el proceso real dentro del contenedor."""

        def _kill() -> None:
            try:
                pid = int(host_pid_path.read_text(encoding="utf-8").strip())
            except (OSError, ValueError):
                return
            self._docker(
                "exec", self.settings.container, "kill", "-TERM", str(pid), timeout=10
            )
            time.sleep(0.5)
            self._docker(
                "exec", self.settings.container, "kill", "-KILL", str(pid), timeout=10
            )

        return _kill

    def run(
        self, argv, timeout=None, cwd=None, env=None, input_text=None, cancel_event=None
    ) -> CommandResult:
        if not self.container_running():
            return CommandResult(
                argv=argv,
                returncode=125,
                stderr=(
                    f"el contenedor '{self.settings.container}' no está en marcha. "
                    "Ejecuta: docker compose up -d"
                ),
            )
        container_cwd = self.map_cwd(cwd or self.settings.data_dir)
        command = [
            "docker",
            "exec",
            "-i",
            "-w",
            container_cwd,
            self.settings.container,
        ]
        pid_file = (cwd / ".command.pid") if cwd is not None else None
        if pid_file is not None:
            # El wrapper guarda el PID real dentro del contenedor para poder
            # matarlo al cancelar; `exec` conserva ese mismo PID.
            command += [
                "sh",
                "-c",
                'echo $$ > "$1"; shift; exec "$@"',
                "sh",
                f"{container_cwd}/.command.pid",
            ]
        command += list(argv)
        try:
            return self._execute(
                command,
                timeout or self.settings.tool_timeout,
                None,
                env,
                input_text,
                cancel_event=cancel_event,
                kill_hook=self._kill_container_process(pid_file) if pid_file else None,
            )
        finally:
            if pid_file is not None:
                try:
                    pid_file.unlink()
                except OSError:
                    pass

    def read_text(self, host_path: Path) -> str:
        # El volumen está montado: se lee directamente del host.
        return super().read_text(host_path)

    def status(self) -> dict:
        if not shutil.which("docker"):
            return {"docker": False, "running": False, "error": "docker no está en PATH"}
        result = self._docker(
            "inspect",
            "-f",
            "{{.State.Running}}|{{.Config.Image}}|{{.State.StartedAt}}",
            self.settings.container,
        )
        if not result.ok:
            return {
                "docker": True,
                "running": False,
                "error": result.stderr.strip() or "contenedor no encontrado",
            }
        parts = result.stdout.strip().split("|")
        return {
            "docker": True,
            "running": parts[0] == "true",
            "image": parts[1] if len(parts) > 1 else "",
            "started_at": parts[2] if len(parts) > 2 else "",
        }


def shlex_quote(value: str) -> str:
    """Cita un único binario para ``sh -lc``; solo letras/números/._-."""
    safe = "".join(c for c in value if c.isalnum() or c in "._-")
    return safe or "true"


def get_runner(settings: Settings) -> Runner:
    if settings.runner == "docker":
        return DockerRunner(settings)
    return LocalRunner(settings)
