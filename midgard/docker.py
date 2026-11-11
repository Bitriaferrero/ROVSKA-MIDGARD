"""Ejecución de herramientas dentro de la imagen Kali de ROVSKA.

Nunca se usa `shell=True` en el host: cada comando se construye como una
lista de argumentos. El contenedor es efímero, usa la red del host (para
poder ver MAC y hacer fingerprint de SO en la LAN) y recibe solo las
capacidades NET_RAW/NET_ADMIN.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import threading
import time
from dataclasses import dataclass, field
from typing import Callable

from . import config


@dataclass
class CommandResult:
    argv: list[str]
    returncode: int
    stdout: str = ""
    stderr: str = ""
    duration: float = 0.0
    timed_out: bool = False

    @property
    def ok(self) -> bool:
        return self.returncode == 0 and not self.timed_out

    def to_dict(self) -> dict:
        return {
            "argv": list(self.argv),
            "returncode": self.returncode,
            "duration": round(self.duration, 2),
            "timed_out": self.timed_out,
            "stderr_tail": self.stderr[-4000:],
        }


def docker_bin() -> str:
    return os.environ.get("MIDGARD_DOCKER", "docker")


def docker_available() -> tuple[bool, str]:
    binary = docker_bin()
    if not shutil.which(binary):
        return False, f"{binary} no está en PATH"
    try:
        proc = subprocess.run(
            [binary, "version", "--format", "{{.Server.Version}}"],
            capture_output=True,
            text=True,
            timeout=15,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        return False, f"no se pudo ejecutar docker: {exc}"
    if proc.returncode != 0:
        return False, (proc.stderr or proc.stdout).strip()[:300]
    return True, proc.stdout.strip()


def image_info(image: str) -> dict:
    binary = docker_bin()
    try:
        proc = subprocess.run(
            [binary, "image", "inspect", image, "--format", "{{.Id}}|{{.Created}}|{{.Size}}"],
            capture_output=True,
            text=True,
            timeout=20,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        return {"error": str(exc)}
    if proc.returncode != 0:
        return {"error": (proc.stderr or proc.stdout).strip()[:300]}
    parts = proc.stdout.strip().split("|")
    return {
        "id": parts[0] if parts else "",
        "created": parts[1] if len(parts) > 1 else "",
        "size": parts[2] if len(parts) > 2 else "",
    }


def container_running(name: str) -> bool:
    binary = docker_bin()
    try:
        proc = subprocess.run(
            [binary, "inspect", "-f", "{{.State.Running}}", name],
            capture_output=True,
            text=True,
            timeout=15,
        )
    except (OSError, subprocess.TimeoutExpired):
        return False
    return proc.returncode == 0 and proc.stdout.strip() == "true"


def build_docker_argv(
    image: str,
    argv: list[str],
    *,
    name: str,
    network_host: bool = True,
    extra: list[str] | None = None,
) -> list[str]:
    """Construye `docker run` sin pasar por un shell."""
    if not argv:
        raise ValueError("argv vacío")
    cmd = [
        docker_bin(),
        "run",
        "--rm",
        "--name",
        name,
        "--label",
        "midgard=1",
        "--cap-add",
        "NET_RAW",
        "--cap-add",
        "NET_ADMIN",
    ]
    if network_host:
        cmd += ["--network", "host"]
    if extra:
        cmd += list(extra)
    cmd += ["--entrypoint", argv[0], image]
    cmd += list(argv[1:])
    return cmd


def run_container(
    image: str,
    argv: list[str],
    *,
    name: str,
    timeout: float,
    on_stderr: Callable[[str], None] | None = None,
    network_host: bool = True,
    extra: list[str] | None = None,
    input_text: str | None = None,
) -> CommandResult:
    """Lanza un contenedor efímero y captura stdout/stderr.

    `argv[0]` se usa como entrypoint (por ejemplo `/usr/bin/nmap`).
    `input_text` se envía por stdin (Metasploit lee ahí el resource script).
    """
    cmd = build_docker_argv(
        image,
        argv,
        name=name,
        network_host=network_host,
        extra=extra,
    )
    started = time.monotonic()
    out_chunks: list[str] = []
    err_chunks: list[str] = []

    try:
        proc = subprocess.Popen(
            cmd,
            stdin=subprocess.PIPE if input_text is not None else subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            errors="replace",
            bufsize=1,
        )
    except OSError as exc:
        return CommandResult(argv=cmd, returncode=127, stderr=str(exc))

    if input_text is not None and proc.stdin is not None:
        try:
            proc.stdin.write(input_text)
            proc.stdin.close()
        except (OSError, ValueError):
            pass

    def _read(stream, sink: list[str], callback: Callable[[str], None] | None = None) -> None:
        try:
            for line in stream:
                sink.append(line)
                if callback:
                    callback(line)
        finally:
            try:
                stream.close()
            except Exception:
                pass

    t_out = threading.Thread(target=_read, args=(proc.stdout, out_chunks), daemon=True)
    t_err = threading.Thread(target=_read, args=(proc.stderr, err_chunks, on_stderr), daemon=True)
    t_out.start()
    t_err.start()

    timed_out = False
    try:
        proc.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        timed_out = True
        subprocess.run(
            [docker_bin(), "rm", "-f", name],
            capture_output=True,
            text=True,
            timeout=30,
        )
        proc.kill()
        try:
            proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            pass

    t_out.join(timeout=5)
    t_err.join(timeout=5)
    duration = time.monotonic() - started

    return CommandResult(
        argv=cmd,
        returncode=proc.returncode if proc.returncode is not None else -1,
        stdout="".join(out_chunks),
        stderr="".join(err_chunks),
        duration=duration,
        timed_out=timed_out,
    )


def run_quick(container_argv: list[str], timeout: float = 60) -> CommandResult:
    """Ejecuta un comando corto de diagnóstico en la imagen (sin nombre fijo)."""
    image = config.docker_image()
    name = f"midgard-probe-{os.getpid()}-{int(time.time())}"
    return run_container(image, container_argv, name=name, timeout=timeout)


def nmap_binary() -> list[str]:
    return ["nmap", "--version"]


def msf_binary() -> list[str]:
    return ["msfconsole", "--version"]
