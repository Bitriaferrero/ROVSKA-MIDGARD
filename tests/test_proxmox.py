#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Tests de la integración Proxmox de solo lectura.

No se toca ``data/`` del usuario: cada test usa un ``proxmox.json`` temporal y
simula la API con respuestas controladas. Nunca se llama a un Proxmox real.
"""

from __future__ import annotations

import atexit
import copy
import io
import json
import os
import shutil
import tempfile
import unittest
import urllib.error
from pathlib import Path
from unittest import mock

# Nunca tocar data/ del usuario.
if "ROVSKA_DATA_DIR" not in os.environ:
    _TEST_DATA = tempfile.mkdtemp(prefix="rovska-proxmox-")
    os.environ["ROVSKA_DATA_DIR"] = _TEST_DATA
    atexit.register(shutil.rmtree, _TEST_DATA, ignore_errors=True)
    from rovvska import config

    config.reset_settings()

from rovvska import proxmox


class ProxmoxTestCase(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp(prefix="rovska-pve-"))
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        self.config_path = self.tmp / "proxmox.json"
        self.patcher = mock.patch.object(proxmox, "CONFIG_PATH", self.config_path)
        self.patcher.start()
        self.addCleanup(self.patcher.stop)
        proxmox.invalidate_cache()

    def save(self, **overrides) -> dict:
        base = {
            "endpoint": "https://10.0.0.1:8006",
            "token_id": "PVEAuditor@pve!rovska",
            "token_secret": "s3cret",
            "enabled": True,
            "include_in_scans": True,
        }
        base.update(overrides)
        return proxmox.save_config(base)


class ConfigTests(ProxmoxTestCase):
    def test_roundtrip_y_permisos(self) -> None:
        cfg = self.save()
        self.assertEqual(cfg["endpoint"], "https://10.0.0.1:8006")
        self.assertTrue(proxmox.is_configured(cfg))
        self.assertEqual(self.config_path.stat().st_mode & 0o777, 0o600)

        public = proxmox.public_config(cfg)
        self.assertNotIn("token_secret", public)
        self.assertTrue(public["has_secret"])
        self.assertTrue(public["configured"])

        reloaded = proxmox.load_config()
        self.assertEqual(reloaded["token_secret"], "s3cret")

    def test_endpoint_sin_esquema(self) -> None:
        cfg = self.save(endpoint="pve.local:8006")
        self.assertEqual(cfg["endpoint"], "https://pve.local:8006")

    def test_token_sin_formato(self) -> None:
        with self.assertRaises(ValueError):
            self.save(token_id="token-sin-formato")

    def test_conserva_secreto_al_cambiar_preferencias(self) -> None:
        self.save()
        cfg = proxmox.save_config({"include_in_scans": False})
        self.assertFalse(cfg["include_in_scans"])
        self.assertEqual(cfg["token_secret"], "s3cret")

    def test_env_como_alternativa(self) -> None:
        if self.config_path.exists():
            self.config_path.unlink()
        env = {
            "ROVSKA_PROXMOX_ENDPOINT": "https://pve.env:8006",
            "ROVSKA_PROXMOX_TOKEN_ID": "PVEAuditor@pve!env",
            "ROVSKA_PROXMOX_TOKEN_SECRET": "env-secret",
            "ROVSKA_PROXMOX_ENABLED": "1",
        }
        with mock.patch.dict(os.environ, env, clear=False):
            cfg = proxmox.load_config()
        self.assertEqual(cfg["source"], "env")
        self.assertTrue(cfg["enabled"])
        self.assertTrue(proxmox.is_configured(cfg))


class ApiClientTests(ProxmoxTestCase):
    class Response:
        def __init__(self, payload):
            self.payload = payload

        def read(self):
            return json.dumps(self.payload).encode("utf-8")

        def __enter__(self):
            return self

        def __exit__(self, *args):
            return False

    def test_get_usa_token_y_lee_data(self) -> None:
        cfg = self.save()
        with mock.patch.object(
            proxmox.urllib.request,
            "urlopen",
            return_value=self.Response({"data": {"version": "8.2.4"}}),
        ) as urlopen:
            result = proxmox._api_get(cfg, "version")
        self.assertEqual(result, {"version": "8.2.4"})
        request = urlopen.call_args.args[0]
        self.assertEqual(request.method, "GET")
        self.assertEqual(
            request.get_header("Authorization"),
            "PVEAPIToken=PVEAuditor@pve!rovska=s3cret",
        )

    def test_http_403_es_error_legible(self) -> None:
        cfg = self.save()
        error = urllib.error.HTTPError(
            "https://10.0.0.1:8006/api2/json/nodes",
            403,
            "Forbidden",
            {},
            io.BytesIO(b'{"errors":{"permission":"denied"}}'),
        )
        self.addCleanup(error.close)
        with mock.patch.object(proxmox.urllib.request, "urlopen", side_effect=error):
            with self.assertRaises(proxmox.ProxmoxError) as ctx:
                proxmox._api_get(cfg, "nodes")
        self.assertIn("403", str(ctx.exception))
        self.assertIn("permiso", str(ctx.exception))

    def test_test_connection_sin_configurar(self) -> None:
        result = proxmox.test_connection(proxmox.load_config())
        self.assertFalse(result["ok"])
        self.assertIn("faltan", result["error"])


class InventoryTests(ProxmoxTestCase):
    RESPONSES = {
        "nodes": [
            {"node": "pve", "status": "online"},
            {"node": "pve2", "status": "online"},
        ],
        "cluster/status": [
            {"type": "node", "name": "pve", "ip": "10.0.0.1"},
            {"type": "node", "name": "pve2", "ip": "10.0.0.2"},
        ],
        "nodes/pve/qemu": [
            {"vmid": 100, "name": "vm-a", "status": "running"},
            {"vmid": 101, "name": "vm-b", "status": "stopped"},
        ],
        "nodes/pve/lxc": [
            {"vmid": 200, "name": "ct-a", "status": "running"},
            {"vmid": 201, "name": "ct-sin-ip", "status": "stopped"},
        ],
        "nodes/pve2/qemu": [],
        "nodes/pve2/lxc": [],
        "nodes/pve/qemu/100/config": {"agent": "1", "ipconfig0": "ip=10.0.0.50/24,gw=10.0.0.254"},
        "nodes/pve/qemu/100/agent/network-get-interfaces": [
            {
                "name": "eth0",
                "ip-addresses": [
                    {"ip-address": "10.0.0.50", "ip-address-type": "ipv4"},
                    {"ip-address": "127.0.0.1", "ip-address-type": "ipv4"},
                ],
            },
            {
                "name": "docker0",
                "ip-addresses": [
                    {"ip-address": "172.17.0.1", "ip-address-type": "ipv4"},
                ],
            },
        ],
        "nodes/pve/qemu/101/config": {"ipconfig0": "ip=10.0.0.51/24"},
        "nodes/pve/lxc/200/config": {"net0": "name=eth0,bridge=vmbr0,ip=10.0.0.60/24"},
        "nodes/pve/lxc/200/interfaces": [
            {"name": "lo", "inet": "127.0.0.1/8"},
            {"name": "eth0", "inet": "10.0.0.60/24"},
            {"name": "docker0", "inet": "172.17.0.1/16"},
            {"name": "br-1a2b3c", "inet": "172.18.0.1/16"},
            {"name": "tailscale0", "inet": "100.97.174.22/32"},
        ],
        "nodes/pve/lxc/201/config": {"net0": "name=eth0,bridge=vmbr0,ip=dhcp"},
        "nodes/pve2/network": [
            {"iface": "vmbr0", "type": "bridge", "active": 1, "address": "10.0.0.2"}
        ],
    }

    def fake_api(self, config, path, timeout=None):
        if path in self.RESPONSES:
            return copy.deepcopy(self.RESPONSES[path])
        raise proxmox.ProxmoxError(f"sin respuesta simulada para {path}")

    def test_inventario_normaliza_nodos_e_invitados(self) -> None:
        self.save()
        with mock.patch.object(proxmox, "_api_get", side_effect=self.fake_api):
            inv = proxmox.fetch_inventory()
        self.assertTrue(inv["ok"])
        nodes = {node["name"]: node for node in inv["nodes"]}
        self.assertEqual(nodes["pve"]["ip"], "10.0.0.1")
        guests = {guest["vmid"]: guest for guest in nodes["pve"]["guests"]}
        self.assertEqual(guests[100]["ip"], "10.0.0.50")
        self.assertEqual(guests[101]["ip"], "10.0.0.51")
        self.assertEqual(guests[200]["ip"], "10.0.0.60")
        self.assertNotIn("172.17.0.1", guests[200]["ips"])
        self.assertNotIn("172.18.0.1", guests[200]["ips"])
        self.assertEqual(guests[200]["ips"][0], "10.0.0.60")
        self.assertNotIn("172.17.0.1", guests[100]["ips"])
        self.assertEqual(guests[201]["ip"], "")
        self.assertEqual(guests[201]["kind"], "lxc")
        self.assertEqual(nodes["pve2"]["ip"], "10.0.0.2")

    def test_enriquece_solo_hosts_del_contexto(self) -> None:
        self.save()
        hosts = [
            {"ip": "10.0.0.1", "hostnames": ["pve"]},
            {"ip": "10.0.0.50", "hostnames": ["vm-a"]},
            {"ip": "10.0.0.60", "hostnames": ["ct-a"]},
            {"ip": "10.0.0.70", "hostnames": ["otro"]},
        ]
        with mock.patch.object(proxmox, "_api_get", side_effect=self.fake_api):
            enriched, state = proxmox.enrich_hosts(hosts)

        self.assertTrue(state["ok"])
        # El inventario completo se ve en Ajustes, pero solo se enriquece pve.
        self.assertEqual(state["node_count"], 2)
        self.assertEqual(state["hidden_guests"], 2)
        by_ip = {host["ip"]: host for host in enriched}
        self.assertIn("proxmox", by_ip["10.0.0.1"])
        guests = {guest["vmid"]: guest for guest in by_ip["10.0.0.1"]["proxmox"]["guests"]}
        self.assertEqual(guests[100]["host_ip"], "10.0.0.50")
        self.assertTrue(guests[100]["scanned"])
        self.assertEqual(guests[200]["host_ip"], "10.0.0.60")
        self.assertFalse(guests[101]["scanned"])
        self.assertEqual(guests[201]["ip"], "")
        self.assertEqual(by_ip["10.0.0.50"]["parent_ip"], "10.0.0.1")
        self.assertEqual(by_ip["10.0.0.50"]["proxmox_guest"]["vmid"], 100)
        self.assertEqual(by_ip["10.0.0.60"]["parent_ip"], "10.0.0.1")
        self.assertNotIn("parent_ip", by_ip["10.0.0.70"])
        self.assertNotIn("proxmox", by_ip["10.0.0.70"])

    def test_empareja_por_cualquier_ip_conocida(self) -> None:
        """Aunque la IP preferida no coincida, otra IP del invitado sí enlaza."""
        self.save()
        inv = {
            "ok": True,
            "error": "",
            "stale": False,
            "fetched_at": "2026-01-01 10:00:00",
            "endpoint": "https://10.0.0.1:8006",
            "nodes": [
                {
                    "name": "pve",
                    "ip": "10.0.0.1",
                    "status": "online",
                    "guests": [
                        {
                            "vmid": 300,
                            "name": "guest-300",
                            "kind": "lxc",
                            "type": "LXC",
                            "status": "running",
                            "ip": "172.17.0.1",
                            "ips": ["172.17.0.1", "10.0.0.88"],
                        }
                    ],
                }
            ],
        }
        hosts = [{"ip": "10.0.0.1"}, {"ip": "10.0.0.88"}]
        with mock.patch.object(proxmox, "inventory", return_value=inv):
            enriched, state = proxmox.enrich_hosts(hosts)

        by_ip = {host["ip"]: host for host in enriched}
        self.assertEqual(by_ip["10.0.0.88"]["parent_ip"], "10.0.0.1")
        self.assertEqual(by_ip["10.0.0.88"]["proxmox_guest"]["vmid"], 300)
        guest = by_ip["10.0.0.1"]["proxmox"]["guests"][0]
        self.assertEqual(guest["host_ip"], "10.0.0.88")
        self.assertTrue(guest["scanned"])
        self.assertEqual(state["hidden_guests"], 1)

    def test_invitado_running_gana_la_ip_frente_a_un_backup_parado(self) -> None:
        """Un backup parado con la misma IP no debe ocultar al invitado activo."""
        self.save()
        inv = {
            "ok": True,
            "error": "",
            "stale": False,
            "fetched_at": "2026-01-01 10:00:00",
            "endpoint": "https://10.0.0.1:8006",
            "nodes": [
                {
                    "name": "pve",
                    "ip": "10.0.0.1",
                    "status": "online",
                    "guests": [
                        {
                            "vmid": 401,
                            "name": "backup-parado",
                            "kind": "lxc",
                            "type": "LXC",
                            "status": "stopped",
                            "ip": "10.0.0.33",
                            "ips": ["10.0.0.33"],
                        },
                        {
                            "vmid": 402,
                            "name": "activo",
                            "kind": "lxc",
                            "type": "LXC",
                            "status": "running",
                            "ip": "10.0.0.33",
                            "ips": ["10.0.0.33"],
                        },
                    ],
                }
            ],
        }
        hosts = [{"ip": "10.0.0.1"}, {"ip": "10.0.0.33"}]
        with mock.patch.object(proxmox, "inventory", return_value=inv):
            enriched, _ = proxmox.enrich_hosts(hosts)

        by_ip = {host["ip"]: host for host in enriched}
        guests = {g["vmid"]: g for g in by_ip["10.0.0.1"]["proxmox"]["guests"]}
        self.assertEqual(guests[402]["host_ip"], "10.0.0.33")
        self.assertTrue(guests[402]["scanned"])
        self.assertEqual(guests[401]["host_ip"], "")
        self.assertFalse(guests[401]["scanned"])
        self.assertEqual(by_ip["10.0.0.33"]["proxmox_guest"]["vmid"], 402)

    def test_no_oculta_invitado_si_el_nodo_no_esta(self) -> None:
        self.save()
        hosts = [{"ip": "10.0.0.50", "hostnames": ["vm-a"]}]
        with mock.patch.object(proxmox, "_api_get", side_effect=self.fake_api):
            enriched, state = proxmox.enrich_hosts(hosts)
        self.assertEqual(state["node_count"], 2)
        self.assertNotIn("parent_ip", enriched[0])
        self.assertEqual(state["hidden_guests"], 0)

    def test_fallo_de_api_no_rompe_la_lista(self) -> None:
        self.save()
        hosts = [{"ip": "10.0.0.1"}]
        with mock.patch.object(
            proxmox, "fetch_inventory", side_effect=proxmox.ProxmoxError("sin conexión")
        ):
            enriched, state = proxmox.enrich_hosts(hosts)
        self.assertFalse(state["ok"])
        self.assertIn("sin conexión", state["error"])
        self.assertEqual(enriched, hosts)

    def test_preferencia_desactivada_no_toca_la_lista(self) -> None:
        self.save(include_in_scans=False)
        hosts = [{"ip": "10.0.0.1"}, {"ip": "10.0.0.50"}]
        with mock.patch.object(proxmox, "_api_get", side_effect=self.fake_api):
            enriched, state = proxmox.enrich_hosts(hosts)
        self.assertTrue(state["ok"])
        self.assertTrue(state["skipped"])
        self.assertEqual(state["node_count"], 2)
        self.assertEqual(enriched, hosts)
        self.assertNotIn("proxmox", enriched[0])
        self.assertNotIn("parent_ip", enriched[1])


if __name__ == "__main__":
    unittest.main()
