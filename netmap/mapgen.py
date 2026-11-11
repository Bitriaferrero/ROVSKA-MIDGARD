#!/usr/bin/env python3
"""Genera un mapa visual de la LAN a partir de datos de descubrimiento.

Entrada: JSON con la estructura que produce netmap.sh.
Salida:  HTML autocontenido (sin CDN) con topología radial + inventario.
"""
import html
import json
import sys
from datetime import datetime

TYPES = {
    "router": ("#ff5d5d", "Router / Gateway"),
    "ap": ("#ffb020", "Access Point"),
    "laptop": ("#4cc9f0", "Portátil / PC"),
    "phone": ("#b388ff", "Móvil / tableta"),
    "server": ("#3ddc97", "Servidor"),
    "unknown": ("#8892a6", "Desconocido"),
}

VENDOR_TYPE = [
    ("routerboard", "router"), ("mikrotik", "router"), ("cisco", "router"),
    ("tp-link", "ap"), ("ubiquiti", "ap"), ("aruba", "ap"), ("ruckus", "ap"),
    ("asus", "laptop"), ("lenovo", "laptop"), ("lcfc", "laptop"),
    ("intel", "laptop"), ("dell", "laptop"), ("hp", "laptop"),
    ("apple", "phone"), ("samsung", "phone"), ("xiaomi", "phone"),
    ("huawei", "phone"), ("oneplus", "phone"), ("motorola", "phone"),
    ("google", "phone"),
    ("proxmox", "server"), ("supermicro", "server"), ("vmware", "server"),
]


def classify(mac: str, vendor: str, ip: str) -> str:
    text = f"{vendor} {mac}".lower()
    for needle, kind in VENDOR_TYPE:
        if needle in text:
            return kind
    # MAC localmente administrada = MAC aleatoria, típica de móvil
    try:
        first = int(mac.split(":")[0], 16)
        if first & 0x02:
            return "phone"
    except (ValueError, IndexError):
        pass
    if ip.endswith(".1") or ip.endswith(".254"):
        return "router"
    return "unknown"


def esc(value) -> str:
    return html.escape(str(value if value is not None else ""))


def main() -> int:
    with open(sys.argv[1], encoding="utf-8") as fh:
        data = json.load(fh)

    hosts = data.get("hosts", [])
    for host in hosts:
        host["type"] = classify(host.get("mac", ""), host.get("vendor", ""), host.get("ip", ""))

    # Orden: gateway primero, luego por IP
    def sort_key(h):
        return (h["type"] != "router", tuple(int(p) for p in h["ip"].split(".")))

    hosts.sort(key=sort_key)

    width, height = 1000, 680
    cx, cy = width / 2, height / 2
    outer = 270
    nodes = []
    for index, host in enumerate(hosts):
        if index == 0:
            x, y = cx, cy
        else:
            import math
            angle = (2 * math.pi * (index - 1)) / max(1, len(hosts) - 1) - math.pi / 2
            x, y = cx + outer * math.cos(angle), cy + outer * math.sin(angle)
        color = TYPES[host["type"]][0]
        label = host["ip"] + (f" · {host['vendor']}" if host.get("vendor") else "")
        nodes.append(
            f'<g class="node"><title>{esc(host["ip"])} — {esc(host.get("vendor") or "sin fabricante")}</title>'
            f'<line x1="{cx:.0f}" y1="{cy:.0f}" x2="{x:.0f}" y2="{y:.0f}" class="link"/>'
            f'<circle cx="{x:.0f}" cy="{y:.0f}" r="{20 if index == 0 else 14}" fill="{color}"/>'
            f'<text x="{x:.0f}" y="{y + 36:.0f}" class="ip">{esc(host["ip"])}</text>'
            f'<text x="{x:.0f}" y="{y + 52:.0f}" class="vend">{esc((host.get("vendor") or "?")[:26])}</text>'
            f"</g>"
        )

    rows = []
    for host in hosts:
        ports = host.get("ports") or []
        port_txt = ", ".join(ports) if ports else "—"
        latency = host.get("latency_ms")
        lat_txt = f"{latency} ms" if latency is not None else "—"
        rows.append(
            "<tr>"
            f'<td><span class="dot" style="background:{TYPES[host["type"]][0]}"></span>{esc(host["ip"])}</td>'
            f'<td class="mono">{esc(host["mac"])}</td>'
            f'<td>{esc(host.get("vendor") or "—")}</td>'
            f'<td>{TYPES[host["type"]][1]}</td>'
            f'<td class="mono">{esc(port_txt)}</td>'
            f'<td class="mono">{esc(lat_txt)}</td>'
            "</tr>"
        )

    counts = {}
    for host in hosts:
        counts[host["type"]] = counts.get(host["type"], 0) + 1
    legend = " ".join(
        f'<span class="chip"><span class="dot" style="background:{TYPES[k][0]}"></span>{TYPES[k][1]} ({v})</span>'
        for k, v in sorted(counts.items(), key=lambda kv: -kv[1])
    )

    gateway = hosts[0] if hosts else {"ip": "—", "vendor": "—"}
    generated = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    notes = data.get("notes", "")

    page = f"""<!doctype html>
<html lang="es">
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Mapa de red — {esc(data.get('ssid') or 'LAN')}</title>
<style>
:root {{ color-scheme: dark; }}
* {{ box-sizing: border-box; }}
body {{ margin:0; background:#0b0f17; color:#e6ebf5;
  font-family: ui-sans-serif, system-ui, "Segoe UI", Roboto, sans-serif; }}
header {{ padding:24px 32px 8px; }}
h1 {{ margin:0 0 6px; font-size:22px; letter-spacing:.2px; }}
.sub {{ color:#8b97ab; font-size:13px; }}
.badge {{ display:inline-block; margin-left:8px; padding:2px 8px; border-radius:999px;
  background:#1b2436; color:#9fb0c9; font-size:11px; border:1px solid #2a3650; }}
.wrap {{ display:grid; grid-template-columns: minmax(0,1.15fr) minmax(320px,.85fr); gap:16px; padding:16px 32px 32px; }}
.card {{ background:#111827; border:1px solid #1f2a3d; border-radius:14px; padding:12px; }}
svg {{ width:100%; height:auto; display:block; }}
.link {{ stroke:#243049; stroke-width:1.5; }}
.node circle {{ stroke:#0b0f17; stroke-width:3; filter: drop-shadow(0 0 10px rgba(0,0,0,.5)); }}
.ip {{ fill:#dbe4f2; font-size:12px; text-anchor:middle; font-family:ui-monospace, monospace; }}
.vend {{ fill:#7f8da3; font-size:10px; text-anchor:middle; }}
table {{ width:100%; border-collapse:collapse; font-size:12.5px; }}
th {{ text-align:left; color:#8b97ab; font-weight:600; padding:8px 6px; border-bottom:1px solid #1f2a3d; }}
td {{ padding:8px 6px; border-bottom:1px solid #17202f; vertical-align:top; }}
.mono {{ font-family:ui-monospace, monospace; font-size:11.5px; color:#aebbd0; }}
.dot {{ display:inline-block; width:8px; height:8px; border-radius:50%; margin-right:7px; }}
.chip {{ display:inline-flex; align-items:center; gap:2px; background:#141d2c; border:1px solid #22304a;
  padding:4px 9px; border-radius:999px; font-size:11.5px; color:#b6c3d8; margin:0 6px 6px 0; }}
.note {{ color:#7f8da3; font-size:12px; padding:0 32px 28px; }}
@media (max-width: 900px) {{ .wrap {{ grid-template-columns: 1fr; }} }}
</style>
<header>
  <h1>Mapa de red <span class="badge">{len(hosts)} dispositivos</span></h1>
  <div class="sub">SSID <b>{esc(data.get('ssid') or '—')}</b> · gateway <b>{esc(gateway['ip'])}</b>
    · {esc(generated)} · solo lectura, sin credenciales</div>
  <div style="margin-top:10px">{legend}</div>
</header>
<div class="wrap">
  <div class="card">
    <svg viewBox="0 0 {width} {height}" role="img" aria-label="Topología de la LAN">
      {''.join(nodes)}
    </svg>
  </div>
  <div class="card" style="overflow:auto">
    <table>
      <thead><tr><th>IP</th><th>MAC</th><th>Fabricante</th><th>Tipo</th><th>Puertos</th><th>Latencia</th></tr></thead>
      <tbody>{''.join(rows)}</tbody>
    </table>
  </div>
</div>
<div class="note">{esc(notes)}</div>
</html>
"""
    with open(sys.argv[2], "w", encoding="utf-8") as fh:
        fh.write(page)
    print(f"OK: {len(hosts)} hosts -> {sys.argv[2]}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
