# ROVSKA

Plataforma local de auditoría de red **ofensiva y defensiva** que ejecuta las
herramientas dentro de un contenedor Kali y correlaciona cada resultado con
**MITRE ATT&CK**, **PTES**, **OSSTMM**, **OWASP Top 10 / WSTG** y **CWE**.

El backend y el panel usan únicamente la biblioteca estándar de Python: no hay
`pip install`, ni Node, ni base de datos externa. Las herramientas viven en
Docker; el host solo ejecuta el servidor web y la CLI.

> **Uso responsable.** ROVSKA está pensada para redes propias o auditorías con
> autorización escrita. Por defecto bloquea objetivos públicos y ejecuta las
> herramientas ofensivas en `dry-run`. Ver [`docs/SECURITY.md`](docs/SECURITY.md).

---

## Estado

| Área | Estado |
| --- | --- |
| Backend (Python stdlib) | Operativo |
| CLI (`init`, `doctor`, `scan`, `operation`, `orchestrate`, `serve`, `mcp`) | Operativo |
| Panel web (8 vistas, SSE, ATT&CK, kill chain, comparativa) | Operativo |
| Informes JSON / XML / HTML / PDF / SARIF / CSV | Operativo |
| Importación de informes JSON/XML | Operativa |
| Adaptadores de herramientas | 16 |
| Servidor MCP para OpenCode | Operativo |
| Imagen Kali (`docker/kali`) | Construida y validada (16/16 herramientas) |
| Tests unitarios | 32 en verde |

### Validación realizada

- Imagen `rovvska/kali-tools:latest` construida con Kali rolling, Metasploit,
  Hydra, Exploit-DB, SecLists y las 16 herramientas del catálogo.
- `./run.sh doctor` → **16/16** disponibles.
- Escaneo `quick` real contra `127.0.0.1:8080` con `runner=docker`: nmap,
  sonda HTTP y hallazgos persistidos.
- Escaneo `web` real: nmap, http_probe, WhatWeb, Nikto, Nuclei, testssl y ffuf.
- Operaciones `hydra` y `metasploit` verificadas en **dry-run** (sin tráfico de
  ataque).
- API y panel con Docker: `/api/health`, `/api/tools`, `/api/data`, `/api/scans`,
  `/api/tasks` y descarga de informes → HTTP 200.
- PDF profesional con WeasyPrint 70.0 dentro de Kali: A4, 5 páginas, portada,
  resumen ejecutivo, ATT&CK, cadena de ataque y numeración.
- Comparativa y importación validadas por API y por la interfaz: importación
  JSON/XML de ROVSKA y de terceros, diff de hosts/puertos/hallazgos y descarga
  del PDF importado sin sobrescribir la evidencia original.

> El binario de testssl.sh en Kali se llama `testssl`. El adaptador usa ese
> nombre; el paquete APT sigue siendo `testssl.sh`.

---

## Arquitectura en un minuto

```
┌──────────────────────────── host ────────────────────────────┐
│  Panel web (web/)  ──HTTP/SSE──  API + orquestador (rovvska)  │
│                                      │                        │
│                                      │ docker exec            │
│                                      ▼                        │
│                         ┌──── contenedor rovska-kali ────┐   │
│                         │ nmap · nuclei · nikto · ffuf … │   │
│                         │ hydra · msfconsole (dry-run)   │   │
│                         └───────────────┬────────────────┘   │
│                                         │ /data              │
│                    data/{reports,evidence,work,rovska.db}     │
└───────────────────────────────────────────────────────────────┘
```

- **Runner**: `docker` (por defecto) o `local` para desarrollo.
- **Evidencia**: cada ejecución guarda su salida cruda y su SHA-256.
- **Persistencia**: SQLite (`data/rovska.db`), sin servidor.
- **Informes**: se regeneran desde la base de datos, no desde la salida de la
  herramienta, para que sean reproducibles.

Detalle completo en [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md).

---

## Requisitos

- Linux (probado en Debian/Ubuntu). En macOS/Windows usa una VM Linux: el
  `network_mode: host` de Docker Desktop no equivale al de Linux.
- Python **3.11+** (el host de desarrollo usa 3.14).
- Docker Engine + `docker compose`.
- Opcional: OpenCode con el modelo `opencode/deepseek-v4.1-flash-free` para el
  orquestador y el servidor MCP.

No se instala nada en el host: ni pip, ni npm, ni herramientas de pentest.

---

## Arranque rápido

```bash
cd ~/ROVSKA-MIDGARD

# 1. Configuración local (no sobrescribe un .env existente)
./run.sh env

# 2. Base de datos y directorios
./run.sh init

# 3. Construye y arranca Kali (la primera vez tarda; la imagen es grande)
./run.sh up

# 4. Comprueba Docker, herramientas y OpenCode
./run.sh doctor

# 5. Panel web en http://127.0.0.1:8780
./run.sh serve
```

> Guía paso a paso para arrancar el panel, el contenedor y el primer escaneo:
> [`ARRANQUE.TXT`](ARRANQUE.TXT).

La imagen se puede aligerar omitiendo grupos de herramientas:

```bash
ROVSKA_WITH_ATTACK=0 ROVSKA_WITH_WEB=0 ./run.sh up
```

Con `WITH_ATTACK=0` no se instalan Hydra, Metasploit ni Exploit-DB; el catálogo
las marcará como no disponibles y los perfiles las omitirán.

---

## Uso por CLI

```bash
# Descubrimiento sin escaneo de puertos
python3 -m rovvska scan 192.168.1.0/24 --profile discovery

# Escaneo rápido con informes
python3 -m rovvska scan 192.168.1.0/24 --profile quick

# Web sobre un host concreto
python3 -m rovvska scan 10.0.0.10 --profile web

# SO con -O (por defecto) y sonda SNMP para la versión exacta
python3 -m rovvska scan 192.168.88.1 --profile quick --snmp
python3 -m rovvska scan 192.168.88.1 --profile quick --no-os

# Herramienta suelta (dry-run por defecto)
python3 -m rovvska operation nuclei --target 10.0.0.10
python3 -m rovvska operation nuclei --target 10.0.0.10 --execute --authorization

# Plan con OpenCode (sin ejecutar)
python3 -m rovvska orchestrate -g "audita los servicios web" -t 10.0.0.10

# Estado e informes
python3 -m rovvska status
python3 -m rovvska report --list
python3 -m rovvska report scan_4a13ac0a245d
```

### Perfiles

| Perfil | Qué hace |
| --- | --- |
| `discovery` | Hosts activos, MAC/fabricante y nombres. Sin puertos. |
| `quick` | Top-1000 + puertos curados, versiones, scripts seguros y sonda HTTP. |
| `full` | Los 65535 puertos TCP y detección de versiones. |
| `web` | WhatWeb, Nikto, Nuclei, testssl.sh y ffuf. |
| `infra` | SSH, SMB, SNMP, DNS y servicios de gestión. |
| `deep` | Cadena completa: red, web, infraestructura y búsqueda de exploits públicos. |
| `attack` | Añade Hydra/Metasploit; **siempre dry-run** salvo autorización explícita. |

---

## Panel web

Una sola página, sin dependencias, con la estética de `AUDITORIA_PLUS/OVERSEER`:

- **Panel**: riesgo global, KPIs, severidad, servicios/puertos más vistos,
  evolución entre escaneos, hosts con más riesgo y hallazgos filtrables.
- **Operaciones**: formulario de escaneo y de herramienta, historial y log en
  vivo por SSE.
- **Tareas**: todo lo que corre en segundo plano (escaneos, herramientas e
  importaciones) con objetivo, estado, duración, último paso, log y botón de
  cancelación. Se refresca cada 5 segundos y el contador de la barra superior
  muestra cuántas tareas siguen activas.
- **ATT&CK**: matriz Enterprise por táctica y cadena de ataque reconstruida en
  siete fases (las no evaluadas se marcan como tal, sin inventar evidencia).
- **Marcos**: tablas PTES, OSSTMM, OWASP Top 10, WSTG y CWE con conteos.
- **Comparativa**: diff entre dos escaneos (hosts, puertos, hallazgos nuevos,
  cerrados y cambios de severidad), delta de riesgo y técnicas ATT&CK.
- **Informes**: listado, tamaño, descarga, regeneración del último escaneo e
  importación de informes JSON/XML externos.
- **Ajustes**: runner, seguridad, rutas, comprobación de alcance y catálogo de
  herramientas.

Atajos: `/` busca, `R` recarga, `Esc` cierra el modal.

---

## OpenCode como orquestador

ROVSKA expone sus capacidades como **servidor MCP local** (`python3 -m rovvska mcp`):
`rovska_scan`, `rovska_scan_status`, `rovska_findings`, `rovska_attack_matrix`,
`rovska_kill_chain`, `rovska_run_tool`, `rovska_tools`, `rovska_scope_check`,
`rovska_report`, `rovska_plan` y `rovska_narrate`.

Añádelo a la configuración de OpenCode V2 (`opencode.jsonc` del proyecto o
global):

```jsonc
{
  "$schema": "https://opencode.ai/config.json",
  "mcp": {
    "servers": {
      "rovska": {
        "type": "local",
        "command": ["python3", "-m", "rovska", "mcp"],
        "cwd": "/home/rorshach/ROVSKA-MIDGARD",
        "environment": {
          "ROVSKA_RUNNER": "docker",
          "ROVSKA_ALLOW_ATTACK": "0"
        }
      }
    }
  }
}
```

También se puede registrar desde la CLI:

```bash
opencode mcp add rovvska -- python3 -m rovvska mcp
opencode mcp list
```

El orquestador (`rovvska orchestrate`) usa `opencode run --format json -m
opencode/deepseek-v4.1-flash-free --auto`. ROVSKA **valida el plan**: solo acepta
herramientas registradas y objetivos dentro de alcance; si OpenCode no está
disponible, cae a un plan determinista.

---

## Informes

Cada escaneo genera seis ficheros en `data/reports/`:

| Formato | Uso |
| --- | --- |
| `informe_<objetivo>_<fecha>.json` | Fuente de verdad, esquema `2.0`. |
| `.xml` | Integración con inventarios y herramientas XML. |
| `.html` | Informe autocontenido, imprimible, con ATT&CK y kill chain. |
| `.pdf` | Informe profesional A4: portada, resumen ejecutivo, metodología y hallazgos. |
| `.sarif` | Consumo por CI/IDE y agregadores SARIF 2.1.0. |
| `.csv` | Hoja de cálculo para triaje. |

El PDF se renderiza con **WeasyPrint dentro del contenedor Kali**, no en el
host. Si WeasyPrint no está disponible, el resto de formatos se generan igual y
el error queda en `stats.pdf`. El fichero resultante se devuelve al UID/GID del
usuario del host para que se pueda abrir y mover sin `sudo`.

El JSON conserva las claves compatibles de AUDITORIA_PLUS (`target`,
`scanned_at`, `mode`, `hosts`, `findings`, `good_checks`, `proxmox`, `counts`) y
añade `attack`, `frameworks`, `operations`, `tools`, `stats`, `limitations` y
`scope`.

### Comparativa e importación

- `GET /api/compare?base=<scan_id>&target=<scan_id>` devuelve hosts y puertos
  nuevos/retirados/cambiados, hallazgos nuevos/cerrados, cambios de severidad,
  delta de riesgo y técnicas ATT&CK nuevas o desaparecidas. Sin parámetros
  compara los dos últimos escaneos.
- `POST /api/import-report` acepta `{filename, content}` con un informe JSON o
  XML. Reconoce el formato propio de ROVSKA y claves habituales de terceros
  (`hosts`, `assets`, `findings`, `vulnerabilities`, `issues`, `alerts`). El
  escaneo importado se guarda como uno más, se enriquece con ATT&CK/marcos y
  aparece en el panel, la comparativa y las exportaciones.
- El original se conserva en `data/reports/imports/`. Si el informe importado
  comparte objetivo y fecha con otro escaneo, los nombres de salida reciben un
  sufijo para **no sobrescribir la evidencia** del escaneo original.

### Tareas en segundo plano

- `GET /api/tasks` une el estado persistido en SQLite (`scans`, `operations`)
  con los trabajos en memoria (`JOBS`) y devuelve una lista ordenada: primero
  las tareas activas o interrumpidas y después el historial, de más reciente a
  más antigua.
- Cada tarea incluye `id`, `target`, `type` (`scan`, `operation`, `import`,
  `orchestration`), `label`, `status`, `status_label`, `started_at`,
  `finished_at`, `duration_seconds`, `active`, `can_cancel`, `cancel_kind`,
  `operation_id`, `scan_id`, `log_available` y `current` (último paso). El
  payload incluye además `counts` con los totales por estado.
- Estados: `queued` (en cola), `running` (activo), `cancelling` (cancelando),
  `done` (completado), `error` (fallido), `cancelled` (cancelado) e
  `interrupted` (el panel se reinició mientras la tarea estaba activa).
- La cancelación reutiliza `POST /api/scans/<id>/cancel` y
  `POST /api/operations/<id>/cancel`. Las tareas sin registro en la base de
  datos (por ejemplo, una orquestación en curso) se muestran igualmente, pero
  no se pueden cancelar desde esta vista.
- El panel consulta `/api/tasks` cada 5 segundos solo mientras la vista
  **Tareas** está abierta. Si el servidor aún no expone la ruta, reconstruye la
  tabla con `/api/data` para no romper la interfaz.

---

## Estructura del repositorio

```
ROVSKA/
├── rovvska/               backend (stdlib)
│   ├── tools/             un adaptador por herramienta
│   ├── api.py             HTTP + SSE + estáticos
│   ├── scanner.py         perfiles y orquestación de escaneos
│   ├── analyzer.py        reglas heurísticas y enriquecimiento
│   ├── attack.py          catálogo ATT&CK, matriz y kill chain
│   ├── frameworks.py      PTES/OSSTMM/OWASP/CWE
│   ├── report.py          JSON/XML/HTML/PDF/SARIF/CSV
│   ├── compare.py         diff entre escaneos
│   ├── importer.py        importación JSON/XML
│   ├── orchestrator.py    OpenCode como cerebro
│   ├── mcp_server.py      servidor MCP por stdio
│   └── cli.py             interfaz de línea de comandos
├── web/                   panel (HTML/CSS/JS sin dependencias)
├── docker/kali/           Dockerfile, entrypoint y lista de herramientas
├── data/                  base de datos, informes, evidencias y trabajo
├── docs/                  arquitectura, metodología, seguridad y roadmap
├── tests/                 unittest (sin Docker)
├── docker-compose.yml
├── Makefile
├── ARRANQUE.TXT           guía de arranque paso a paso
└── run.sh
```

`README` (sin extensión) contiene las instrucciones originales del proyecto y
no se modifica.

---

## Tests

```bash
./run.sh test
# o
python3 -m unittest discover -s tests -v
```

Los tests usan una base de datos temporal y no requieren Docker. Cubren alcance,
reglas de análisis, ATT&CK, marcos, los formatos de informe (incluido el HTML
paginado del PDF), la comparativa, la importación JSON/XML y los adaptadores con
salidas simuladas (SMB, SNMP y Metasploit).

---

## Configuración

Todas las variables están documentadas en [`.env.example`](.env.example). Las
más relevantes:

| Variable | Defecto | Efecto |
| --- | --- | --- |
| `ROVSKA_RUNNER` | `docker` | `docker` o `local`. |
| `ROVSKA_CONTAINER` | `rovska-kali` | Contenedor donde se ejecutan las herramientas. |
| `ROVSKA_DATA_DIR` | `data/` | Datos y montaje `/data` del contenedor. |
| `ROVSKA_ALLOW_PUBLIC` | `0` | Permite objetivos públicos (exige autorización). |
| `ROVSKA_ALLOWED_CIDRS` | vacío | Si se define, limita los públicos a esos rangos. |
| `ROVSKA_ALLOW_ATTACK` | `0` | Habilita Hydra/Metasploit reales. |
| `ROVSKA_MAX_HOSTS` | `256` | Máximo de hosts por barrido. |
| `ROVSKA_TOOL_TIMEOUT` | `900` | Segundos por herramienta. |
| `ROVSKA_API_TOKEN` | vacío | Si se define, exige `X-ROVSKA-Token` en escrituras. |
| `ROVSKA_HOST` / `ROVSKA_PORT` | `127.0.0.1` / `8780` | Escucha del panel. |

Si cambias `ROVSKA_DATA_DIR`, ejecuta `./run.sh init` **antes** de
`docker compose up`: el montaje del compose sigue esa variable y el directorio
debe existir con permisos del usuario del host. `./run.sh up` ya lo hace.

---

## Limitaciones conocidas

- El SO y el tipo de host se infieren por banners, puertos y MAC; sin root no
  hay fingerprint `-O`.
- Las reglas EOL/CVE son heurísticas: confirma con los avisos del fabricante.
- La asignación exacta IP → invitado de Proxmox requiere DHCP o la API.
- La exposición desde WAN no se puede comprobar desde la LAN.
- Las operaciones ofensivas son `dry-run` salvo autorización expresa.
- ROVSKA no modifica el objetivo salvo que se habilite una operación de ataque.

Siguientes pasos en [`docs/ROADMAP.md`](docs/ROADMAP.md).

---

## Documentación

- [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) — componentes, flujo, base de
  datos, API, MCP y esquema de informe.
- [`docs/METHODOLOGY.md`](docs/METHODOLOGY.md) — PTES, OSSTMM, OWASP, CWE,
  ATT&CK, severidad y confianza.
- [`docs/SECURITY.md`](docs/SECURITY.md) — modelo de autorización, alcance,
  aislamiento, datos y uso responsable.
- [`docs/ROADMAP.md`](docs/ROADMAP.md) — mejoras propuestas por prioridad.

---

## Licencia y ética

Uso exclusivo en sistemas propios o con autorización escrita. El operador es
responsable del alcance, de la ventana de pruebas y del tratamiento de los
datos. ROVSKA registra cada comando y cada evidencia para que la auditoría sea
trazable.
