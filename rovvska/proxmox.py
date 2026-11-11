#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Inventario Proxmox por API de solo lectura.

El panel nunca habla con Proxmox desde el navegador: las credenciales viven en
``data/proxmox.json`` (permisos 600) o en variables de entorno y solo se usan
en el servidor. Todas las peticiones a la API son ``GET``; el token debe tener
el rol ``PVEAuditor`` (o equivalente de solo lectura).

La integración es opcional y tolerante a fallos: si la API no responde, el
escaneo y la lista siguen funcionando y el panel muestra un aviso.
"""

from __future__ import annotations

import copy
import ipaddress
import json
import os
import ssl
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime
from pathlib import Path

from .config import SETTINGS

CONFIG_PATH = Path(SETTINGS.data_dir) / "proxmox.json"

CACHE_TTL = 45.0
CACHE_ERROR_TTL = 30.0
MAX_IPS_PER_GUEST = 8

_DEFAULT_CONFIG: dict = {
    "endpoint": "",
    "token_id": "",
    "token_secret": "",
    "verify_tls": True,
    "timeout": 8,
    "enabled": False,
    "include_in_scans": True,
}

_CONFIG_KEYS = tuple(_DEFAULT_CONFIG)

_LOCK = threading.Lock()
_FETCH_LOCK = threading.Lock()
_CACHE: dict = {
    "key": "",
    "at": 0.0,
    "data": None,
    "error_at": 0.0,
    "error": "",
}


class ProxmoxError(RuntimeError):
    """Error legible de configuración o de la API de Proxmox."""


# ---------------------------------------------------------------------------
# Configuración
# ---------------------------------------------------------------------------


def _now() -> str:
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def _as_bool(value, default: bool = False) -> bool:
    if isinstance(value, bool):
        return value
    if value is None:
        return default
    return str(value).strip().lower() in {"1", "true", "yes", "on", "si", "sí"}


def _env_bool(name: str) -> bool | None:
    raw = os.environ.get(name)
    return None if raw is None else _as_bool(raw)


def _env_text(name: str) -> str | None:
    raw = os.environ.get(name)
    return None if raw is None else raw.strip()


def _normalize_endpoint(value: str) -> str:
    text = str(value or "").strip()
    if not text:
        return ""
    if "://" not in text:
        text = f"https://{text}"
    parsed = urllib.parse.urlparse(text)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        raise ValueError("el endpoint debe ser una URL http(s), por ejemplo https://192.168.88.10:8006")
    return text.rstrip("/")


def _normalize(raw: dict, source: str = "") -> dict:
    """Devuelve una configuración completa y con tipos correctos."""
    data = dict(_DEFAULT_CONFIG)
    for key in _CONFIG_KEYS:
        if key in raw and raw[key] is not None:
            data[key] = raw[key]

    data["endpoint"] = _normalize_endpoint(data.get("endpoint", ""))
    data["token_id"] = str(data.get("token_id") or "").strip()
    data["token_secret"] = str(data.get("token_secret") or "").strip()
    data["verify_tls"] = _as_bool(data.get("verify_tls"), True)
    data["enabled"] = _as_bool(data.get("enabled"), False)
    data["include_in_scans"] = _as_bool(data.get("include_in_scans"), True)
    try:
        data["timeout"] = max(2, min(60, int(float(data.get("timeout") or 8))))
    except (TypeError, ValueError):
        data["timeout"] = 8
    data["source"] = source or str(raw.get("source") or "")

    token_id = data["token_id"]
    if token_id and "!" not in token_id:
        raise ValueError("el token ID debe tener el formato usuario@realm!nombre")
    if data["token_secret"] and not token_id:
        raise ValueError("falta el token ID para el secreto indicado")
    return data


def load_config() -> dict:
    """Lee la configuración del fichero y completa con variables de entorno.

    El fichero manda; las variables ``ROVSKA_PROXMOX_*`` solo rellenan campos
    que no estén definidos en él. Así el botón de Ajustes es la fuente
    principal y el despliegue por entorno sigue siendo posible.
    """
    path = Path(CONFIG_PATH)
    file_data: dict = {}
    has_file = path.is_file()
    if has_file:
        try:
            raw = json.loads(path.read_text(encoding="utf-8"))
            if isinstance(raw, dict):
                file_data = raw
        except (OSError, json.JSONDecodeError) as exc:
            raise ProxmoxError(f"no se puede leer {path}: {exc}") from exc

    merged = dict(file_data)
    env_values = {
        "endpoint": _env_text("ROVSKA_PROXMOX_ENDPOINT"),
        "token_id": _env_text("ROVSKA_PROXMOX_TOKEN_ID"),
        "token_secret": _env_text("ROVSKA_PROXMOX_TOKEN_SECRET"),
    }
    env_enabled = _env_bool("ROVSKA_PROXMOX_ENABLED")
    env_verify = _env_bool("ROVSKA_PROXMOX_VERIFY_TLS")
    env_include = _env_bool("ROVSKA_PROXMOX_INCLUDE_IN_SCANS")

    used_env = False
    for key, value in env_values.items():
        if value is None:
            continue
        if not str(merged.get(key) or "").strip():
            merged[key] = value
            used_env = True
    if env_enabled is not None and "enabled" not in merged:
        merged["enabled"] = env_enabled
        used_env = True
    if env_verify is not None and "verify_tls" not in merged:
        merged["verify_tls"] = env_verify
        used_env = True
    if env_include is not None and "include_in_scans" not in merged:
        merged["include_in_scans"] = env_include
        used_env = True

    if has_file and used_env:
        source = "file+env"
    elif has_file:
        source = "file"
    elif used_env:
        source = "env"
    else:
        source = "default"
    return _normalize(merged, source)


def merged_config(updates: dict | None = None) -> dict:
    """Aplica cambios sobre la configuración actual sin escribir en disco."""
    current = load_config()
    data = dict(current)
    updates = updates if isinstance(updates, dict) else {}

    if "endpoint" in updates:
        data["endpoint"] = updates.get("endpoint") or ""
    if "token_id" in updates:
        data["token_id"] = updates.get("token_id") or ""
    if "token_secret" in updates:
        secret = str(updates.get("token_secret") or "").strip()
        if secret:
            data["token_secret"] = secret
    if updates.get("clear_secret") is True:
        data["token_secret"] = ""
    for key in ("verify_tls", "enabled", "include_in_scans"):
        if key in updates:
            data[key] = _as_bool(updates.get(key), bool(data.get(key)))
    if "timeout" in updates:
        data["timeout"] = updates.get("timeout")
    return _normalize(data, current.get("source", ""))


def save_config(updates: dict) -> dict:
    """Guarda la configuración con permisos 600 y devuelve la resultante."""
    data = merged_config(updates)
    path = Path(CONFIG_PATH)
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        tmp = path.with_name(f".{path.name}.tmp")
        payload = {key: data[key] for key in _CONFIG_KEYS}
        tmp.write_text(json.dumps(payload, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
        os.chmod(tmp, 0o600)
        os.replace(tmp, path)
        os.chmod(path, 0o600)
    except OSError as exc:
        raise ProxmoxError(f"no se puede guardar {path}: {exc}") from exc
    invalidate_cache()
    return load_config()


def is_configured(config: dict | None = None) -> bool:
    cfg = config or load_config()
    return bool(cfg.get("endpoint") and cfg.get("token_id") and cfg.get("token_secret"))


def public_config(config: dict | None = None) -> dict:
    """Configuración apta para el navegador: nunca incluye el secreto."""
    cfg = config or load_config()
    return {
        "endpoint": cfg.get("endpoint", ""),
        "token_id": cfg.get("token_id", ""),
        "has_secret": bool(cfg.get("token_secret")),
        "verify_tls": bool(cfg.get("verify_tls", True)),
        "timeout": cfg.get("timeout", 8),
        "enabled": bool(cfg.get("enabled")),
        "include_in_scans": bool(cfg.get("include_in_scans", True)),
        "configured": is_configured(cfg),
        "source": cfg.get("source", ""),
        "config_path": str(CONFIG_PATH),
    }


# ---------------------------------------------------------------------------
# Cliente HTTP (solo GET)
# ---------------------------------------------------------------------------


def _api_get(config: dict, path: str, timeout: float | None = None):
    """GET autenticado contra ``/api2/json``. No existe ninguna ruta de escritura."""
    if not is_configured(config):
        raise ProxmoxError("Proxmox no está configurado (endpoint, token ID y secreto)")
    endpoint = str(config["endpoint"]).rstrip("/")
    url = f"{endpoint}/api2/json/{str(path).lstrip('/')}"
    request = urllib.request.Request(url, method="GET")
    request.add_header(
        "Authorization",
        f"PVEAPIToken={config['token_id']}={config['token_secret']}",
    )
    request.add_header("Accept", "application/json")

    context = None
    if url.startswith("https://"):
        context = ssl.create_default_context()
        if not config.get("verify_tls", True):
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE

    wait = float(timeout or config.get("timeout") or 8)
    try:
        with urllib.request.urlopen(request, timeout=wait, context=context) as response:
            raw = response.read()
    except urllib.error.HTTPError as exc:
        detail = ""
        try:
            body = exc.read().decode("utf-8", errors="replace")
            parsed = json.loads(body)
            errors = parsed.get("errors") if isinstance(parsed, dict) else None
            detail = json.dumps(errors, ensure_ascii=False) if errors else body.strip()
        except Exception:  # noqa: BLE001 - el detalle es solo informativo
            detail = str(exc.reason or "")
        if exc.code in {401, 403}:
            raise ProxmoxError(
                f"HTTP {exc.code}: token sin permiso de lectura o caducado ({detail[:180]})"
            ) from exc
        raise ProxmoxError(f"HTTP {exc.code}: {detail[:240]}") from exc
    except urllib.error.URLError as exc:
        reason = str(exc.reason or exc)
        hint = ""
        if "CERTIFICATE" in reason.upper() or "SSL" in reason.upper():
            hint = " · revisa el certificado o desactiva 'Verificar TLS' para un certificado propio"
        raise ProxmoxError(f"conexión fallida: {reason}{hint}") from exc
    except TimeoutError as exc:
        raise ProxmoxError(f"tiempo de espera agotado ({wait:.0f}s)") from exc
    except OSError as exc:
        raise ProxmoxError(f"conexión fallida: {exc}") from exc

    try:
        payload = json.loads(raw.decode("utf-8", errors="replace"))
    except json.JSONDecodeError as exc:
        raise ProxmoxError("respuesta no JSON de la API de Proxmox") from exc
    if isinstance(payload, dict) and "data" in payload:
        return payload["data"]
    return payload


def test_connection(config: dict | None = None) -> dict:
    """Comprueba versión y acceso al cluster. Devuelve siempre un dict."""
    cfg = config or load_config()
    started = time.monotonic()
    if not is_configured(cfg):
        return {
            "ok": False,
            "error": "faltan endpoint, token ID o secreto",
            "latency_ms": 0,
        }
    try:
        version = _api_get(cfg, "version") or {}
        nodes: list = []
        try:
            nodes = _api_get(cfg, "nodes") or []
        except ProxmoxError:
            nodes = []
        if not isinstance(nodes, list):
            nodes = []
        return {
            "ok": True,
            "version": str(version.get("version") or ""),
            "release": str(version.get("release") or ""),
            "repo_id": str(version.get("repoid") or ""),
            "nodes": len([n for n in nodes if isinstance(n, dict)]),
            "latency_ms": round((time.monotonic() - started) * 1000),
        }
    except ProxmoxError as exc:
        return {
            "ok": False,
            "error": str(exc),
            "latency_ms": round((time.monotonic() - started) * 1000),
        }
    except Exception as exc:  # noqa: BLE001 - no romper el panel
        return {
            "ok": False,
            "error": f"error inesperado: {exc}",
            "latency_ms": round((time.monotonic() - started) * 1000),
        }


# ---------------------------------------------------------------------------
# Normalización de nodos e invitados
# ---------------------------------------------------------------------------


def _clean_ip(value) -> str:
    text = str(value or "").strip()
    if not text:
        return ""
    if text.lower() in {"dhcp", "manual", "auto", "none", "static"}:
        return ""
    text = text.split("/", 1)[0].split("%", 1)[0]
    try:
        address = ipaddress.ip_address(text)
    except ValueError:
        return ""
    if (
        address.is_loopback
        or address.is_link_local
        or address.is_unspecified
        or address.is_multicast
    ):
        return ""
    return str(address)


_VIRTUAL_IFACE_PREFIXES = (
    "docker",
    "veth",
    "br-",
    "virbr",
    "fwbr",
    "fwln",
    "fwpr",
    "tap",
    "tun",
)


def _is_virtual_iface(name) -> bool:
    """Descarta interfaces internas que no son la IP del servicio.

    Dentro de un LXC/VM es habitual encontrar ``docker0`` o ``br-*`` con la
    pasarela interna (172.17.0.1); esa dirección no sirve para localizar el
    invitado en la red del nodo.
    """
    text = str(name or "").strip().lower()
    if not text:
        return False
    if text in {"lo", "lo0"}:
        return True
    return text.startswith(_VIRTUAL_IFACE_PREFIXES)


def _sort_ips(values, prefer_net=None) -> list[str]:
    """Ordena IPs y prioriza las que pertenecen a la red del nodo."""
    unique: list[str] = []
    seen: set[str] = set()
    for value in values:
        ip = _clean_ip(value)
        if ip and ip not in seen:
            seen.add(ip)
            unique.append(ip)

    def sort_key(item: str):
        address = ipaddress.ip_address(item)
        preferred = 0
        if prefer_net is not None and address.version == 4:
            try:
                preferred = 0 if address in prefer_net else 1
            except TypeError:
                preferred = 1
        return (preferred, 0 if address.version == 4 else 1, int(address))

    unique.sort(key=sort_key)
    return unique[:MAX_IPS_PER_GUEST]


def _ips_from_config_value(value) -> list[str]:
    """Extrae IPs de ``net0``/``ipconfig0`` (``...,ip=192.168.1.5/24,...``)."""
    ips: list[str] = []
    for part in str(value or "").split(","):
        if "=" not in part:
            continue
        key, raw = part.split("=", 1)
        if key.strip().lower() in {"ip", "ip6"}:
            ips.append(raw.strip())
    return _sort_ips(ips)


def _ips_from_agent(data) -> list[str]:
    ips: list[str] = []
    for iface in data or []:
        if not isinstance(iface, dict):
            continue
        if _is_virtual_iface(iface.get("name")):
            continue
        for item in iface.get("ip-addresses") or []:
            if isinstance(item, dict):
                ips.append(item.get("ip-address") or item.get("ip") or "")
    return _sort_ips(ips)


def _ips_from_lxc_interfaces(data) -> list[str]:
    ips: list[str] = []
    for iface in data or []:
        if not isinstance(iface, dict):
            continue
        if _is_virtual_iface(iface.get("name")):
            continue
        for key in ("inet", "inet6", "address", "ip"):
            raw = iface.get(key)
            if not raw:
                continue
            for part in str(raw).split():
                ips.append(part)
    return _sort_ips(ips)


def _config_ips(data) -> list[str]:
    ips: list[str] = []
    if isinstance(data, dict):
        for key, value in data.items():
            key_lower = str(key).lower()
            if key_lower.startswith("net") or key_lower.startswith("ipconfig"):
                ips.extend(_ips_from_config_value(value))
    return _sort_ips(ips)


def _agent_enabled(config_data) -> bool:
    if not isinstance(config_data, dict):
        return False
    raw = str(config_data.get("agent") or "").strip().lower()
    if not raw:
        return False
    return any(part.strip() in {"1", "enabled=1", "on", "yes"} for part in raw.split(","))


def _safe_api(config: dict, path: str, timeout: float | None = None):
    try:
        return _api_get(config, path, timeout=timeout)
    except ProxmoxError:
        return None


def _node_network_ip(config: dict, node: str) -> str:
    data = _safe_api(config, f"nodes/{urllib.parse.quote(node, safe='')}/network", timeout=4)
    if not isinstance(data, list):
        return ""
    candidates: list[str] = []
    for iface in data:
        if not isinstance(iface, dict) or not iface.get("active", 1):
            continue
        if str(iface.get("type") or "") in {"loopback"}:
            continue
        if _is_virtual_iface(iface.get("iface")):
            continue
        for key in ("address", "cidr"):
            ip = _clean_ip(iface.get(key))
            if ip:
                candidates.append(ip)
        address = str(iface.get("address") or "")
        if address and ":" in address:
            candidates.append(address)
    candidates = _sort_ips(candidates)
    return candidates[0] if candidates else ""


def _cluster_node_ips(config: dict) -> dict[str, str]:
    data = _safe_api(config, "cluster/status", timeout=5)
    ips: dict[str, str] = {}
    if not isinstance(data, list):
        return ips
    for item in data:
        if not isinstance(item, dict) or str(item.get("type") or "") != "node":
            continue
        name = str(item.get("name") or item.get("node") or "")
        ip = _clean_ip(item.get("ip") or item.get("address") or "")
        if name and ip:
            ips[name] = ip
    return ips


def _guest_ips(
    config: dict,
    node: str,
    kind: str,
    vmid: int,
    status: str,
    node_ip: str = "",
) -> list[str]:
    quoted_node = urllib.parse.quote(node, safe="")
    base = f"nodes/{quoted_node}/{kind}/{vmid}"
    ips: list[str] = []
    config_data = _safe_api(config, f"{base}/config", timeout=4)

    if kind == "qemu":
        if status == "running" and _agent_enabled(config_data):
            agent = _safe_api(config, f"{base}/agent/network-get-interfaces", timeout=5)
            ips = _ips_from_agent(agent)
        if not ips:
            ips = _config_ips(config_data)
    else:
        if status == "running":
            interfaces = _safe_api(config, f"{base}/interfaces", timeout=4)
            ips = _ips_from_lxc_interfaces(interfaces)
        if not ips:
            ips = _config_ips(config_data)

    prefer_net = None
    if node_ip:
        try:
            prefer_net = ipaddress.ip_network(f"{node_ip}/24", strict=False)
        except ValueError:
            prefer_net = None
    return _sort_ips(ips, prefer_net)


def _fetch_guests(config: dict, node: str, node_ip: str = "") -> list[dict]:
    guests: list[dict] = []
    quoted_node = urllib.parse.quote(node, safe="")
    for kind, type_label in (("qemu", "VM"), ("lxc", "LXC")):
        data = _safe_api(config, f"nodes/{quoted_node}/{kind}", timeout=5)
        if not isinstance(data, list):
            continue
        for item in data:
            if not isinstance(item, dict):
                continue
            try:
                vmid = int(item.get("vmid") or 0)
            except (TypeError, ValueError):
                vmid = 0
            if not vmid:
                continue
            status = str(item.get("status") or "")
            name = str(item.get("name") or item.get("hostname") or f"guest-{vmid}")
            ips = _guest_ips(config, node, kind, vmid, status, node_ip)
            guests.append(
                {
                    "vmid": vmid,
                    "name": name,
                    "kind": kind,
                    "type": type_label,
                    "status": status,
                    "ip": ips[0] if ips else "",
                    "ips": ips,
                    "node": node,
                    "node_ip": "",
                    "host_ip": "",
                    "scanned": False,
                }
            )
    guests.sort(key=lambda guest: (guest.get("kind", ""), guest.get("vmid", 0)))
    return guests


def fetch_inventory(config: dict | None = None) -> dict:
    """Consulta nodos e invitados. Lanza ``ProxmoxError`` si no hay acceso."""
    cfg = config or load_config()
    if not is_configured(cfg):
        raise ProxmoxError("Proxmox no está configurado")
    nodes_raw = _api_get(cfg, "nodes")
    if not isinstance(nodes_raw, list):
        raise ProxmoxError("respuesta inesperada de /nodes")
    cluster_ips = _cluster_node_ips(cfg)
    nodes: list[dict] = []
    for item in nodes_raw:
        if not isinstance(item, dict):
            continue
        name = str(item.get("node") or item.get("name") or "").strip()
        if not name:
            continue
        ip = cluster_ips.get(name, "") or _clean_ip(item.get("ip") or "")
        if not ip:
            ip = _node_network_ip(cfg, name)
        nodes.append(
            {
                "name": name,
                "ip": ip,
                "status": str(item.get("status") or ""),
                "guests": _fetch_guests(cfg, name, ip),
            }
        )
    nodes.sort(key=lambda node: node.get("name", ""))
    return {
        "ok": True,
        "error": "",
        "stale": False,
        "fetched_at": _now(),
        "endpoint": cfg.get("endpoint", ""),
        "nodes": nodes,
    }


# ---------------------------------------------------------------------------
# Caché
# ---------------------------------------------------------------------------


def _cache_key(config: dict) -> str:
    return "|".join(
        [
            str(config.get("endpoint", "")),
            str(config.get("token_id", "")),
            "1" if config.get("verify_tls", True) else "0",
        ]
    )


def invalidate_cache() -> None:
    with _LOCK:
        _CACHE.update({"key": "", "at": 0.0, "data": None, "error_at": 0.0, "error": ""})


def inventory(config: dict | None = None, force: bool = False) -> dict:
    """Inventario con caché corta y último resultado bueno si la API falla."""
    cfg = config or load_config()
    if not is_configured(cfg):
        return {
            "ok": False,
            "error": "Proxmox no está configurado",
            "stale": False,
            "fetched_at": "",
            "endpoint": cfg.get("endpoint", ""),
            "nodes": [],
        }
    key = _cache_key(cfg)
    now = time.monotonic()
    with _LOCK:
        if not force and _CACHE.get("key") == key:
            data = _CACHE.get("data")
            if data and now - float(_CACHE.get("at") or 0.0) < CACHE_TTL:
                return copy.deepcopy(data)
            error = str(_CACHE.get("error") or "")
            if error and now - float(_CACHE.get("error_at") or 0.0) < CACHE_ERROR_TTL:
                if data:
                    result = copy.deepcopy(data)
                    result["stale"] = True
                    result["error"] = error
                    return result
                return {
                    "ok": False,
                    "error": error,
                    "stale": False,
                    "fetched_at": "",
                    "endpoint": cfg.get("endpoint", ""),
                    "nodes": [],
                }

    with _FETCH_LOCK:
        # Otra petición pudo rellenar la caché mientras esperábamos.
        now = time.monotonic()
        with _LOCK:
            if not force and _CACHE.get("key") == key and _CACHE.get("data"):
                if now - float(_CACHE.get("at") or 0.0) < CACHE_TTL:
                    return copy.deepcopy(_CACHE["data"])
        try:
            data = fetch_inventory(cfg)
        except Exception as exc:  # noqa: BLE001 - degradar con aviso
            error = str(exc) or "error desconocido"
            with _LOCK:
                previous = _CACHE.get("data") if _CACHE.get("key") == key else None
                _CACHE.update({"key": key, "error_at": time.monotonic(), "error": error})
                if previous:
                    result = copy.deepcopy(previous)
                    result["stale"] = True
                    result["error"] = error
                    return result
                _CACHE.update({"at": 0.0, "data": None})
            return {
                "ok": False,
                "error": error,
                "stale": False,
                "fetched_at": "",
                "endpoint": cfg.get("endpoint", ""),
                "nodes": [],
            }
        with _LOCK:
            _CACHE.update(
                {
                    "key": key,
                    "at": time.monotonic(),
                    "data": data,
                    "error_at": 0.0,
                    "error": "",
                }
            )
        return copy.deepcopy(data)


# ---------------------------------------------------------------------------
# Enriquecimiento de la lista unificada
# ---------------------------------------------------------------------------


def _guest_label(guest: dict) -> str:
    kind = "LXC" if guest.get("kind") == "lxc" else "VM"
    name = str(guest.get("name") or "").strip()
    return f"{kind} {guest.get('vmid', '')}" + (f" · {name}" if name else "")


def _inventory_summary(nodes) -> list[dict]:
    summary: list[dict] = []
    for node in nodes or []:
        if not isinstance(node, dict):
            continue
        guests = node.get("guests") if isinstance(node.get("guests"), list) else []
        summary.append(
            {
                "name": str(node.get("name") or ""),
                "ip": str(node.get("ip") or ""),
                "status": str(node.get("status") or ""),
                "guest_count": len(guests),
            }
        )
    return summary


def _host_names(host: dict) -> set[str]:
    names = {str(name).strip().lower() for name in host.get("hostnames") or [] if name}
    if host.get("name"):
        names.add(str(host["name"]).strip().lower())
    return {name for name in names if name}


def enrich_hosts(hosts: list[dict], include: bool | None = None) -> tuple[list[dict], dict]:
    """Añade el inventario Proxmox a los hosts ya presentes en el contexto.

    No crea hosts nuevos: solo enriquece las filas de nodos que ya existen y
    marca los invitados escaneados con ``parent_ip`` para que la interfaz los
    muestre indentados bajo su nodo. Los invitados que no están en el contexto
    se muestran igualmente en la ficha del nodo como inventario.
    """
    cfg = load_config()
    state: dict = {
        "ok": False,
        "enabled": bool(cfg.get("enabled")),
        "configured": is_configured(cfg),
        "config": public_config(cfg),
        "error": "",
        "stale": False,
        "fetched_at": "",
        "endpoint": cfg.get("endpoint", ""),
        "nodes": [],
        "node_count": 0,
        "guest_count": 0,
        "hidden_guests": 0,
        "skipped": False,
    }
    if not state["configured"]:
        return hosts, state
    if not state["enabled"]:
        state["error"] = "integración desactivada"
        return hosts, state
    if include is None:
        include = bool(cfg.get("include_in_scans", True))
    if not include:
        # La preferencia solo desactiva la lista; Ajustes puede seguir viendo
        # el inventario y su estado de conexión.
        inv = inventory(cfg)
        state.update(
            {
                "ok": bool(inv.get("ok")),
                "error": str(inv.get("error") or ""),
                "stale": bool(inv.get("stale")),
                "fetched_at": str(inv.get("fetched_at") or ""),
                "skipped": True,
            }
        )
        state["nodes"] = _inventory_summary(inv.get("nodes"))
        state["node_count"] = len(state["nodes"])
        state["guest_count"] = sum(node.get("guest_count", 0) for node in state["nodes"])
        return hosts, state

    inv = inventory(cfg)
    state.update(
        {
            "ok": bool(inv.get("ok")),
            "error": str(inv.get("error") or ""),
            "stale": bool(inv.get("stale")),
            "fetched_at": str(inv.get("fetched_at") or ""),
        }
    )
    nodes = inv.get("nodes") or []
    if not isinstance(nodes, list):
        nodes = []
    if not nodes:
        return hosts, state

    host_by_ip = {str(host.get("ip") or ""): host for host in hosts if host.get("ip")}
    hostnames: dict[str, dict] = {}
    for host in hosts:
        for name in _host_names(host):
            hostnames.setdefault(name, host)

    for node in nodes:
        if not isinstance(node, dict):
            continue
        node_ip = str(node.get("ip") or "")
        node_host = host_by_ip.get(node_ip)
        if node_host is None:
            # Solo enriquecemos nodos que ya están en el contexto actual.
            continue
        node_name = str(node.get("name") or node_ip)
        guest_rows: list[dict] = []
        seen_vmid: set[int] = set()
        # Los invitados en marcha tienen prioridad al reclamar una IP: un
        # backup parado con la misma IP configurada no debe ocultar al que
        # realmente está escaneado. El orden de presentación se reordena luego.
        guests = [g for g in node.get("guests") or [] if isinstance(g, dict)]
        guests.sort(key=lambda g: 0 if str(g.get("status") or "") == "running" else 1)
        for guest in guests:
            try:
                vmid = int(guest.get("vmid") or 0)
            except (TypeError, ValueError):
                vmid = 0
            if vmid and vmid in seen_vmid:
                continue
            if vmid:
                seen_vmid.add(vmid)
            row = dict(guest)
            row["node"] = node_name
            row["node_ip"] = node_ip
            row["host_ip"] = ""
            row["scanned"] = False

            candidate = None
            for value in [row.get("ip")] + list(row.get("ips") or []):
                found = host_by_ip.get(str(value or ""))
                if found is None or found is node_host or found.get("parent_ip"):
                    continue
                candidate = found
                break
            if candidate is None:
                guest_name = str(row.get("name") or "").strip().lower()
                if guest_name:
                    found = hostnames.get(guest_name)
                    if found is not None and found is not node_host and not found.get("parent_ip"):
                        candidate = found
            if candidate is not None:
                candidate_ip = str(candidate.get("ip") or "")
                row["host_ip"] = candidate_ip
                row["ip"] = str(row.get("ip") or candidate_ip)
                row["scanned"] = True
                candidate["parent_ip"] = node_ip
                candidate["proxmox_guest"] = {
                    "vmid": row.get("vmid"),
                    "name": row.get("name", ""),
                    "kind": row.get("kind", ""),
                    "type": row.get("type", ""),
                    "node": node_name,
                    "node_ip": node_ip,
                }
            guest_rows.append(row)

        guest_rows.sort(key=lambda guest: (guest.get("kind", ""), guest.get("vmid", 0)))
        node_host["proxmox"] = {
            "node": node_name,
            "node_ip": node_ip,
            "status": str(node.get("status") or ""),
            "fetched_at": state["fetched_at"],
            "guests": guest_rows,
        }
    state["nodes"] = _inventory_summary(nodes)
    state["node_count"] = len(state["nodes"])
    state["guest_count"] = sum(node.get("guest_count", 0) for node in state["nodes"])
    state["hidden_guests"] = sum(1 for host in hosts if host.get("parent_ip"))
    return hosts, state


def status(force: bool = False) -> dict:
    """Estado público para Ajustes: configuración + inventario."""
    try:
        cfg = load_config()
    except (ProxmoxError, ValueError) as exc:
        return {
            "config": {
                "endpoint": "",
                "token_id": "",
                "has_secret": False,
                "verify_tls": True,
                "timeout": 8,
                "enabled": False,
                "include_in_scans": True,
                "configured": False,
                "source": "error",
                "config_path": str(CONFIG_PATH),
            },
            "inventory": None,
            "error": str(exc),
        }
    result: dict = {"config": public_config(cfg), "inventory": None}
    if not is_configured(cfg):
        return result
    inv = inventory(cfg, force=force)
    result["inventory"] = {
        "ok": bool(inv.get("ok")),
        "error": str(inv.get("error") or ""),
        "stale": bool(inv.get("stale")),
        "fetched_at": str(inv.get("fetched_at") or ""),
        "endpoint": str(inv.get("endpoint") or ""),
        "nodes": inv.get("nodes") or [],
    }
    return result
