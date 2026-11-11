"""Informes: consola, JSON, CSV y HTML autocontenido."""

from __future__ import annotations

import csv
import html
import json
from pathlib import Path

from .nmap import Host


def _trunc(value: str, width: int) -> str:
    value = value or ""
    if len(value) <= width:
        return value
    return value[: max(0, width - 1)] + "…"


def _ports_label(host: Host, limit: int = 8) -> str:
    ports = [p.port for p in host.open_ports]
    if not ports:
        return "-"
    shown = ",".join(str(p) for p in ports[:limit])
    if len(ports) > limit:
        shown += f" (+{len(ports) - limit})"
    return shown


def print_summary(hosts: list[Host]) -> None:
    rows = []
    for host in hosts:
        os_info = host.os or {}
        rows.append(
            [
                host.ip,
                os_info.get("name", "SO desconocido"),
                os_info.get("version", "") or "-",
                os_info.get("confidence", "-"),
                _ports_label(host),
                f"{host.mac or '-'} {host.vendor or ''}".strip(),
            ]
        )

    headers = ["IP", "SO", "Versión", "Conf.", "Puertos", "MAC / fabricante"]
    widths = [15, 24, 12, 7, 22, 26]
    for index, header in enumerate(headers):
        widths[index] = max(widths[index], len(header))
    for row in rows:
        for index, value in enumerate(row):
            widths[index] = max(widths[index], min(len(value), 34))

    def line(char: str = "-") -> str:
        return "+" + "+".join(char * (width + 2) for width in widths) + "+"

    def format_row(values: list[str]) -> str:
        cells = []
        for index, value in enumerate(values):
            cells.append(_trunc(str(value), widths[index]).ljust(widths[index]))
        return "| " + " | ".join(cells) + " |"

    print(line("-"))
    print(format_row(headers))
    print(line("="))
    for row in rows:
        print(format_row(row))
    print(line("-"))
    print(f"{len(hosts)} host(s) con datos")


def write_json(run_dir: Path, hosts: list[Host], meta: dict) -> Path:
    path = run_dir / "hosts.json"
    payload = {
        "meta": meta,
        "hosts": [host.to_dict() for host in hosts],
    }
    path.write_text(
        json.dumps(payload, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    return path


def write_csv(run_dir: Path, hosts: list[Host]) -> Path:
    path = run_dir / "hosts.csv"
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.writer(handle)
        writer.writerow(
            [
                "ip",
                "mac",
                "fabricante",
                "tipo",
                "so",
                "version",
                "confianza",
                "fuentes",
                "puertos_abiertos",
                "servicios",
            ]
        )
        for host in hosts:
            os_info = host.os or {}
            writer.writerow(
                [
                    host.ip,
                    host.mac,
                    host.vendor,
                    os_info.get("device", ""),
                    os_info.get("name", ""),
                    os_info.get("version", ""),
                    os_info.get("confidence", ""),
                    "; ".join(os_info.get("sources", [])),
                    ",".join(str(p.port) for p in host.open_ports),
                    "; ".join(f"{p.port}/{p.proto} {p.label}" for p in host.open_ports),
                ]
            )
    return path


def _confidence_class(value: str) -> str:
    return {
        "alta": "conf-high",
        "media": "conf-mid",
        "baja": "conf-low",
        "muy baja": "conf-none",
    }.get(value, "conf-none")


def _host_section(host: Host) -> str:
    os_info = host.os or {}
    esc = html.escape
    confidence = esc(os_info.get("confidence", "muy baja"))
    rows = []
    for port in host.open_ports:
        rows.append(
            "<tr>"
            f"<td>{port.port}/{esc(port.proto)}</td>"
            f"<td>{esc(port.service or '-')}</td>"
            f"<td>{esc(port.product or '-')}</td>"
            f"<td>{esc(port.version or '-')}</td>"
            f"<td>{esc(port.extrainfo or '-')}</td>"
            "</tr>"
        )
    ports_table = (
        "<table class=\"ports\"><thead><tr><th>Puerto</th><th>Servicio</th>"
        "<th>Producto</th><th>Versión</th><th>Extra</th></tr></thead><tbody>"
        + "".join(rows)
        + "</tbody></table>"
        if rows
        else "<p class=\"muted\">Sin puertos abiertos.</p>"
    )

    candidates = os_info.get("candidates") or []
    candidate_rows = "".join(
        f"<li><b>{esc(c.get('name', ''))}</b> {esc(c.get('version', ''))} "
        f"<span class=\"muted\">({esc(', '.join(c.get('sources', [])))}, "
        f"score {c.get('score', 0)})</span></li>"
        for c in candidates
    )
    candidates_html = f"<ul class=\"candidates\">{candidate_rows}</ul>" if candidate_rows else ""

    scripts = []
    for port in host.open_ports:
        for script_id, output in port.scripts.items():
            scripts.append((f"{port.port}/{script_id}", output))
    for script_id, output in host.scripts.items():
        scripts.append((script_id, output))
    scripts_html = ""
    if scripts:
        blocks = "".join(
            f"<details><summary>{esc(name)}</summary><pre>{esc(output[:4000])}</pre></details>"
            for name, output in scripts
        )
        scripts_html = f"<div class=\"scripts\">{blocks}</div>"

    return f"""
    <section class="host">
      <header>
        <div>
          <h2>{esc(host.ip)}</h2>
          <p class="muted">{esc(host.mac or 'MAC no disponible')} {esc(host.vendor or '')}</p>
        </div>
        <div class="os">
          <span class="badge {_confidence_class(os_info.get('confidence', ''))}">{confidence}</span>
          <strong>{esc(os_info.get('name', 'SO desconocido'))}</strong>
          <span>{esc(os_info.get('version', ''))}</span>
          <p class="muted">{esc(os_info.get('device', 'Dispositivo'))} · fuentes: {esc(', '.join(os_info.get('sources', [])) or '-')}</p>
        </div>
      </header>
      {candidates_html}
      {ports_table}
      {scripts_html}
    </section>
    """


CSS = """
:root { color-scheme: dark; --bg:#0b1016; --panel:#121a23; --line:#243244;
        --text:#e6edf5; --muted:#8fa3ba; --accent:#4cc2ff; --high:#2ecc71;
        --mid:#f1c40f; --low:#e67e22; --none:#7f8c8d; }
* { box-sizing: border-box; }
body { margin:0; background:var(--bg); color:var(--text);
       font:14px/1.5 system-ui, -apple-system, Segoe UI, Roboto, sans-serif; }
main { max-width:1180px; margin:0 auto; padding:32px 20px 64px; }
h1 { margin:0 0 4px; font-size:26px; letter-spacing:.5px; }
h2 { margin:0; font-size:18px; color:var(--accent); }
.muted { color:var(--muted); margin:2px 0 0; }
.meta { display:flex; flex-wrap:wrap; gap:10px 24px; background:var(--panel);
        border:1px solid var(--line); border-radius:10px; padding:14px 18px; margin:22px 0; }
.meta div span { color:var(--muted); display:block; font-size:11px;
                 text-transform:uppercase; letter-spacing:.06em; }
.host { background:var(--panel); border:1px solid var(--line); border-radius:10px;
        padding:18px; margin:16px 0; }
.host header { display:flex; justify-content:space-between; gap:20px;
               flex-wrap:wrap; align-items:flex-start; }
.os { text-align:right; }
.badge { display:inline-block; padding:1px 8px; border-radius:999px;
         font-size:11px; font-weight:700; text-transform:uppercase; margin-right:8px; }
.conf-high { background:rgba(46,204,113,.15); color:var(--high); }
.conf-mid { background:rgba(241,196,15,.15); color:var(--mid); }
.conf-low { background:rgba(230,126,34,.15); color:var(--low); }
.conf-none { background:rgba(127,140,141,.15); color:var(--none); }
table { width:100%; border-collapse:collapse; margin-top:14px; font-size:13px; }
th, td { text-align:left; padding:7px 9px; border-bottom:1px solid var(--line); }
th { color:var(--muted); font-size:11px; text-transform:uppercase; letter-spacing:.05em; }
.ports td:first-child { font-variant-numeric:tabular-nums; color:var(--accent); }
.candidates { margin:12px 0 0; padding-left:20px; color:var(--muted); }
.scripts { margin-top:12px; }
details { margin:6px 0; }
summary { cursor:pointer; color:var(--accent); }
pre { overflow:auto; background:#0a0f15; border:1px solid var(--line);
      border-radius:8px; padding:10px; font-size:12px; }
footer { color:var(--muted); margin-top:28px; font-size:12px; text-align:center; }
"""


def write_html(run_dir: Path, hosts: list[Host], meta: dict) -> Path:
    sections = "\n".join(_host_section(host) for host in hosts) or (
        "<p class=\"muted\">No se encontraron hosts.</p>"
    )
    esc = html.escape
    meta_rows = "".join(
        f"<div><span>{esc(str(key))}</span>{esc(str(value))}</div>"
        for key, value in meta.items()
        if key in {"target", "profile", "run_id", "created_at", "status", "operator", "nmap_version"}
    )
    page = f"""<!doctype html>
<html lang="es">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>MIDGARD · {esc(str(meta.get('target', '')))}</title>
<style>{CSS}</style>
</head>
<body>
<main>
  <h1>MIDGARD · Informe de auditoría</h1>
  <p class="muted">Generado sin IA, sin telemetría. Datos locales y verificables por hash.</p>
  <div class="meta">{meta_rows}</div>
  {sections}
  <footer>MIDGARD · evidencia en {esc(str(meta.get('run_id', '')))} · revisa manifest.json para los hashes SHA-256</footer>
</main>
</body>
</html>
"""
    path = run_dir / "report.html"
    path.write_text(page, encoding="utf-8")
    return path
