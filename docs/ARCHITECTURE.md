# Arquitectura de ROVSKA

Documento de referencia para mantener y extender la plataforma. Describe los
componentes, el flujo de un escaneo, el modelo de datos, la API, el servidor MCP
y el contrato de los informes.

---

## 1. Principios de diseño

1. **Cero dependencias en el host.** Backend y panel usan la biblioteca estándar
   de Python y JavaScript nativo. No hay `pip`, `npm`, ni ORM.
2. **Herramientas aisladas.** Todo binario de pentest se ejecuta en el
   contenedor `rovska-kali` mediante `docker exec`. El host nunca instala
   `nmap`, `hydra` ni similares.
3. **Evidencia primero.** Cada ejecución registra comando, salida cruda, código
   de salida y SHA-256. Los informes se reconstruyen desde la base de datos.
4. **Seguro por defecto.** Los objetivos públicos se bloquean, las operaciones
   ofensivas son `dry-run` y el panel escucha en `127.0.0.1`.
5. **Trazabilidad metodológica.** Todo hallazgo lleva severidad, confianza,
   técnica ATT&CK, fase PTES, módulo OSSTMM, categoría OWASP y CWE.

---

## 2. Vista de componentes

```
┌─────────────────────────────── host ───────────────────────────────┐
│                                                                    │
│  web/  ── HTTP/SSE ──►  rovvska/api.py                             │
│  (panel)                    │                                      │
│                             ├── jobs.py        hilos + cancelación   │
│                             ├── scanner.py     perfiles y cadena    │
│                             ├── orchestrator.py OpenCode (opcional) │
│                             ├── mcp_server.py  stdio para OpenCode  │
│                             ├── runner.py      docker | local       │
│                             ├── tools/*.py     16 adaptadores       │
│                             ├── analyzer.py    reglas + enriquecido │
│                             ├── attack.py      ATT&CK + kill chain  │
│                             ├── frameworks.py  PTES/OSSTMM/OWASP/CWE│
│                             ├── report.py      JSON/XML/HTML/PDF    │
│                             ├── compare.py     diff entre escaneos  │
│                             ├── importer.py    importa JSON/XML     │
│                             └── db.py          SQLite + evidencias  │
│                                                                    │
│  data/  ◄── volumen compartido con el contenedor ──►  /data         │
└───────────────────────────────┬────────────────────────────────────┘
                                │ docker exec
                     ┌──────────▼──────────┐
                     │   rovska-kali       │
                     │   network_mode:host │
                     │   cap NET_RAW/ADMIN │
                     └─────────────────────┘
```

### Módulos

| Módulo | Responsabilidad |
| --- | --- |
| `config.py` | Configuración inmutable desde entorno; rutas y valores por defecto. |
| `db.py` | Esquema SQLite, conexión por hilo, transacciones, IDs y eventos. |
| `models.py` | `Host`, `Port`, `Finding`; severidades, deduplicación y riesgo. |
| `scope.py` | Validación de IP/CIDR/hostname, rangos privados, allowlist y autorización. |
| `runner.py` | Ejecuta comandos en Docker o local; mapea rutas del host a `/data`. |
| `tools/base.py` | Contrato `ToolSpec` / `Tool` y `ToolResult`. |
| `tools/*.py` | Un adaptador por herramienta: comando, parseo y normalización. |
| `scanner.py` | Perfiles, cadena de herramientas, persistencia y cierre del escaneo. |
| `analyzer.py` | Reglas heurísticas, exposición, EOL, cabeceras y checks positivos. |
| `attack.py` | Catálogo ATT&CK, matriz por táctica, kill chain y cobertura. |
| `frameworks.py` | Enriquecimiento y resumen PTES/OSSTMM/OWASP/CWE. |
| `report.py` | Construcción del informe y exportadores (JSON, XML, HTML, PDF, SARIF, CSV). |
| `compare.py` | Diff de hosts, puertos, hallazgos y ATT&CK entre dos escaneos. |
| `importer.py` | Normaliza informes JSON/XML externos y los persiste como escaneos. |
| `orchestrator.py` | Prompt a OpenCode, validación y ejecución del plan. |
| `mcp_server.py` | Implementación MCP por stdio (JSON-RPC). |
| `jobs.py` | Pool de hilos, estado, cancelación y logs. |
| `api.py` | HTTP, SSE, estáticos, validación y endpoints. |
| `cli.py` | Interfaz de usuario de terminal. |

---

## 3. Flujo de un escaneo

```
POST /api/scans
   │
   ├─ check_target()          alcance + autorización + máximo de hosts
   ├─ INSERT scans (queued)   visible de inmediato en el panel
   └─ JOBS.submit(scan_id)
          │
          ▼
   scanner.run_scan()
      ├─ _scope_decision()             segunda validación (defensa en profundidad)
      ├─ por herramienta del perfil:
      │    ├─ tool.build(ctx)          construye argv reproducible
      │    ├─ runner.run(argv)         docker exec / subprocess
      │    ├─ tool.parse(result)       normaliza hosts, puertos y hallazgos
      │    └─ db: tool_runs + evidence (SHA-256)
      ├─ _merge_hosts()                fusiona datos de varios escáneres
      ├─ analyzer.analyze()            heurísticas + merge + enriquecimiento
      ├─ _persist_results()            hosts, ports, findings, good_checks
      ├─ UPDATE scans (done, stats)
      └─ report.write_reports()        6 formatos + rutas en stats
```

### Importación y comparación

`importer.py` convierte un informe JSON/XML en el modelo interno y lo persiste
como un escaneo normal (`profile=import`): normaliza hosts, puertos y hallazgos,
reconoce claves propias y de terceros, fusiona duplicados, enriquece con
ATT&CK/marcos y regenera todos los formatos. El fichero original se conserva en
`data/reports/imports/`.

`compare.py` trabaja sobre los informes normalizados (`report.build`) para que
la comparativa funcione igual con escaneos reales e importados. Calcula altas,
bajas, cambios de severidad, diff de puertos/hosts y técnicas ATT&CK nuevas o
desaparecidas. Los nombres de informe incluyen un sufijo cuando dos escaneos
comparten objetivo y fecha, de modo que una importación nunca pisa la evidencia
del escaneo original.

### Perfiles

Los perfiles son datos, no código: `PROFILES` en `scanner.py` define etiqueta,
descripción, perfil de nmap, puertos y lista ordenada de herramientas. Añadir un
perfil nuevo no requiere tocar el resto del backend.

### Herramientas

Cada adaptador declara:

```python
ToolSpec(
    name="nuclei",
    binary="nuclei",
    category="web",
    description="Plantillas de vulnerabilidades conocidas",
    phase="vuln",
    requires_attack=False,
    profiles=("web", "deep"),
    attack=("T1595.002",),
)
```

y expone `available(runner)`, `build(ctx)` y `parse(result)`. `parse` devuelve un
`ToolResult` con `hosts`, `findings`, `good` y `raw`. Las rutas de salida se
escriben bajo `data/work/<scan_id>/` para que el contenedor las vea como
`/data/work/<scan_id>/`.

### Fallos y tolerancia

- Una herramienta ausente se marca `skipped` y el escaneo continúa.
- Un error de parseo no invalida el resto de la cadena; se registra en
  `tool_runs.error`.
- La cancelación usa un `threading.Event` compartido; el estado final es
  `cancelled`.
- Si el escaneo falla, `scans.status = error` y se guarda el mensaje.

---

## 4. Modelo de datos (SQLite)

| Tabla | Clave | Contenido |
| --- | --- | --- |
| `scans` | `id` | Objetivo, perfil, modo, estado, fechas, opciones y estadísticas. |
| `hosts` | `scan_id, ip` | MAC, fabricante, hostnames, SO, tipo, riesgo y extra. |
| `ports` | `scan_id, ip, port, proto` | Estado, servicio, producto, versión y scripts NSE. |
| `findings` | `id` | Severidad, título, evidencia, recomendación, CVE/CWE/ATT&CK, marcos, fuente y confianza. |
| `good_checks` | autoincremental | Comprobaciones positivas (lo que está bien). |
| `operations` | `id` | Herramienta, objetivo, parámetros, estado, `dry_run`, log y resultado. |
| `tool_runs` | `id` | argv, tiempos, exit code, ruta de salida y error. |
| `evidence` | autoincremental | Fichero, ruta, SHA-256 y fechas. |
| `annotations` | `ip` | Tipo y nombre anotados por el analista. |
| `events` | autoincremental | Log persistente para SSE y auditoría. |

Decisiones:

- **Sin migraciones automáticas.** El esquema es idempotente (`IF NOT EXISTS`).
  Para cambios incompatibles se documenta una migración manual.
- **JSON en columnas de texto** para listas y diccionarios (compatibilidad y
  portabilidad). No se consultan por SQL.
- **Conexión por hilo** con `check_same_thread=False` y `WAL` para que API,
  jobs y CLI convivan sin bloquearse.
- **Borrado lógico por escaneo**: al reejecutar un `scan_id`, se reemplazan sus
  hosts, puertos y hallazgos para evitar duplicados.

---

## 5. API HTTP

Servidor `ThreadingHTTPServer` en `127.0.0.1:8780` por defecto. Todas las
respuestas son JSON salvo estáticos e informes.

### Lectura

| Ruta | Devuelve |
| --- | --- |
| `GET /api/health` | Versión, DB, contadores, runner, OpenCode, `allow_attack`. |
| `GET /api/data` | Payload agregado del panel (global, hosts, escaneos, operaciones, tendencia). |
| `GET /api/scans` | Últimos escaneos. |
| `GET /api/scans/<id>` | Detalle de un escaneo. |
| `GET /api/operations` | Últimas operaciones. |
| `GET /api/operations/<id>` | Detalle con log. |
| `GET /api/operations/<id>/stream` | SSE con eventos de la operación. |
| `GET /api/events` | SSE global de escaneos. |
| `GET /api/findings` | Hallazgos filtrables. |
| `GET /api/attack` | Matriz ATT&CK. |
| `GET /api/frameworks` | Resumen de marcos. |
| `GET /api/stats` | Estadísticas agregadas. |
| `GET /api/tools` | Catálogo y disponibilidad. |
| `GET /api/config` | Configuración visible (sin secretos). |
| `GET /api/scope?target=…` | Comprobación de alcance. |
| `GET /api/compare?base=…&target=…` | Diff de hosts, puertos, hallazgos, riesgo y ATT&CK. |
| `GET /api/reports` | Listado de informes con tamaño y URL. |
| `GET /api/jobs` | Estado de trabajos en memoria. |
| `GET /api/tasks` | Tareas unificadas (escaneos, operaciones, importaciones y trabajos en memoria) con estado, duración, último paso y acciones. |
| `GET /reports/<fichero>` | Descarga de un informe. |

### Escritura

| Ruta | Efecto |
| --- | --- |
| `POST /api/scans` | Encola un escaneo; responde `202` con `scan_id`. |
| `POST /api/operations` | Encola una herramienta; responde `202`. |
| `POST /api/operations/<id>/cancel` | Cancela una operación. |
| `POST /api/scans/<id>/cancel` | Cancela un escaneo. |
| `POST /api/annotations` | Guarda tipo/nombre de un host. |
| `POST /api/reports` | Regenera los informes de un `scan_id`. |
| `POST /api/import-report` | Importa `{filename, content}` JSON/XML como escaneo nuevo. |
| `POST /api/orchestrate` | Pide plan a OpenCode y, opcionalmente, lo ejecuta. |

### Controles

- **Token**: si `ROVSKA_API_TOKEN` está definido, las escrituras exigen
  `X-ROVSKA-Token` (o `?token=`).
- **Origen**: se rechaza un `Origin` distinto del `Host` para evitar CSRF.
- **Tamaño**: cuerpos limitados a 2 MB; la importación de informes admite 8 MB.
- **Errores**: 400 validación, 403 alcance/origen, 404 no encontrado, 500 interno
  (sin traza salvo `ROVSKA_DEBUG`).

### SSE

`/api/operations/<id>/stream` emite un `data: {json}` por evento y un evento
`end` al terminar. El panel usa `EventSource` y cierra la conexión al recibirlo.

### Tareas

`GET /api/tasks` es una vista de solo lectura que combina `scans`,
`operations` y la cola en memoria `JOBS`:

- Los escaneos con `profile="import"` o `stats.imported=true` se etiquetan
  como `import`; el resto como `scan`. Las herramientas sueltas se etiquetan
  como `operation`.
- `_task_status()` prioriza el estado terminal de SQLite y, si la fila sigue
  activa, el estado del job en memoria. Una fila `queued`/`running` sin job se
  marca `interrupted`: el panel se reinició y ya no existe el hilo que la
  ejecutaba.
- `_last_task_events()` obtiene el último evento por `operation_id`/`scan_id`
  para rellenar `current`, el paso visible en la tabla.
- `duration_seconds` se calcula con `started_at`/`finished_at` (o la hora
  actual si sigue activa).
- Las tareas activas e interrumpidas se ordenan primero; después, historial por
  fecha descendente.
- Cancelar usa los endpoints existentes de escaneo/operación. Los jobs sin fila
  en base de datos se muestran, pero `can_cancel` es `false` y `cancel_kind`
  queda vacío.
- La cancelación se registra como `cancelled`, no como `error`: el escaneo
  comprueba la señal entre herramientas y la operación antes y después de
  ejecutar su herramienta. `JobManager` conserva ese estado aunque la función
  lance una excepción para detenerse.

`web/app.js` refresca la vista cada 5 segundos solo cuando está visible y cae a
`/api/data` si `/api/tasks` devuelve 404, de modo que la interfaz sigue
funcionando contra un servidor antiguo.

---

## 6. Servidor MCP

`python3 -m rovvska mcp` implementa MCP sobre stdio (JSON-RPC 2.0) sin SDK.
Soporta `initialize`, `tools/list` y `tools/call`.

| Herramienta | Función |
| --- | --- |
| `rovska_scan` | Lanza un escaneo y devuelve el `scan_id`. |
| `rovska_scan_status` | Estado y resumen de un escaneo. |
| `rovska_findings` | Hallazgos filtrados por severidad/host. |
| `rovska_attack_matrix` | Matriz ATT&CK del último escaneo. |
| `rovska_kill_chain` | Cadena de ataque reconstruida. |
| `rovska_run_tool` | Ejecuta una herramienta (dry-run por defecto). |
| `rovska_tools` | Catálogo y disponibilidad. |
| `rovska_scope_check` | Valida un objetivo antes de tocarlo. |
| `rovska_report` | Regenera informes. |
| `rovska_plan` | Plan determinista/OpenCode sin ejecutar. |
| `rovska_narrate` | Resumen en lenguaje natural de un escaneo. |

OpenCode lo consume como servidor local; ver el `README.md` para la
configuración `mcp.servers`.

---

## 7. Orquestador OpenCode

1. `build_context(scan_id)` resume hosts, puertos y hallazgos.
2. `plan(goal, target, context)` construye un prompt con reglas estrictas y
   ejecuta `opencode run --format json -m <modelo> --auto`.
3. `_extract_text()` tolera salida JSON de una línea o por eventos.
4. `validate_plan()` descarta herramientas desconocidas, objetivos fuera de
   alcance y pasos sin `dry_run` cuando la política lo exige.
5. `execute_plan()` llama a `scanner.run_operation()` por paso.
6. Si OpenCode falla o está deshabilitado, `_fallback_plan()` propone una cadena
   determinista según el perfil.

El modelo nunca ejecuta comandos directamente: solo propone un JSON que ROVSKA
valida. Esta separación es deliberada y es la principal frontera de seguridad
del componente de IA.

---

## 8. Contrato del informe

```jsonc
{
  "schema_version": "2.0",
  "generator": "ROVSKA",
  "scan_id": "scan_…",
  "target": "192.168.1.0/24",
  "scanned_at": "2026-11-01 10:00:00",
  "mode": "top-ports-1000",
  "profile": "quick",
  "status": "done",
  "hosts": [ { "ip": "…", "ports": [], "risk": 0, "risk_meta": {}, "severity_counts": {} } ],
  "findings": [ { "severity": "ALTO", "title": "…", "cve": [], "cwe": [], "attack": [], "frameworks": {} } ],
  "good_checks": ["…"],
  "proxmox": {},
  "counts": { "CRÍTICO": 0, "ALTO": 0, "MEDIO": 0, "BAJO": 0, "INFO": 0 },
  "risk": { "score": 0, "label": "…", "cls": "ok" },
  "attack": { "matrix": {}, "kill_chain": {}, "summary": {}, "coverage": {} },
  "frameworks": { "ptes": [], "osstmm": {}, "owasp": {}, "cwe": [] },
  "operations": [],
  "tools": [],
  "stats": { "total_hosts": 0, "reports": {}, "pdf": { "ok": true }, "imported": false },
  "limitations": ["…"],
  "scope": { "allowed": true, "reason": "…" }
}
```

Los seis exportadores consumen este mismo objeto:

- **JSON**: fuente de verdad, esquema `2.0`, con `stats.reports` y `stats.pdf`.
- **XML**: `<rovska-report>` con `hosts`, `findings`, `attack`, `frameworks`.
- **HTML**: autocontenido, con CSS embebido, matriz y kill chain.
- **PDF**: variante imprimible del HTML (`for_pdf=True`) renderizada con
  WeasyPrint en el contenedor. A4, portada, resumen ejecutivo, cabeceras, pies y
  numeración. Un fallo de WeasyPrint no invalida el resto de formatos.
- **SARIF 2.1.0**: una `rule` por título y un `result` por hallazgo, con nivel
  mapeado desde la severidad.
- **CSV**: una fila por hallazgo con columnas estables para triaje.

Los escaneos importados usan el mismo contrato (`stats.imported=true`,
`stats.source_file`, `stats.source_format`) y se pueden comparar y exportar como
cualquier otro. `GET /api/compare` devuelve un objeto independiente con
`base`, `target`, `delta`, `hosts`, `ports`, `findings` y `attack`.

---

## 9. Cómo extender

### Añadir una herramienta

1. Crea `rovvska/tools/mitool.py` con una clase que herede de `Tool`.
2. Declara `ToolSpec` (nombre, binario, categoría, fase, perfiles, ATT&CK).
3. Implementa `build(ctx)` y `parse(result)`.
4. Regístrala en `rovvska/tools/__init__.py`.
5. Añádela al `Dockerfile` y a `docker/kali/tools.txt`.
6. Añade un test de parseo con una salida de ejemplo.

### Añadir una regla de análisis

Añade la regla en `analyzer.py` con `_add(...)` y etiquetas que permitan a
`frameworks.py` y `attack.py` clasificarla. Incluye CWE y recomendación.

### Añadir una vista al panel

1. Añade el botón en `web/index.html` (`data-view`).
2. Implementa `render<View>()` y engánchala en `renderDetail()`.
3. Reutiliza `hero`, `kpis`, `charts`, `table-wrap` y `findingCard` para
   mantener la coherencia visual.

### Añadir un endpoint

1. Añade la ruta en `do_GET`/`do_POST` de `api.py`.
2. Valida el cuerpo con `read_json()` y el alcance con `check_target()`.
3. Devuelve JSON con `send_json()` y usa los códigos existentes.
4. Documenta la ruta en este archivo y en `README.md`.

---

## 10. Decisiones y compromisos

| Decisión | Motivo | Coste |
| --- | --- | --- |
| Python stdlib | Cero instalación, portabilidad | Menos ergonomía que FastAPI |
| SQLite | Un solo fichero, copias simples | Sin concurrencia multi-escritor |
| Docker `network_mode: host` | ARP/SYN reales y rutas de la LAN | No vale en Docker Desktop |
| SSE en vez de WebSocket | Sin dependencias, suficiente | Unidireccional |
| Heurísticas locales | Sin API externa ni claves | Menos precisión que un feed CVE |
| Dry-run por defecto | Seguridad y ética | Requiere opt-in explícito |
| OpenCode solo propone | Contiene el riesgo de la IA | Planes menos creativos |

Las mejoras pendientes están en [`ROADMAP.md`](ROADMAP.md).
