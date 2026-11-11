# ROVSKA-MIDGARD

Un solo proyecto y **un solo panel web** para auditar y documentar redes, sin IA
en tiempo de ejecución. Dentro conviven tres motores que antes eran programas
sueltos:

| Motor | Qué hace | Dónde se usa |
|---|---|---|
| **ROVSKA** | Auditoría ofensiva/defensiva, MITRE ATT&CK, PTES, OSSTMM, OWASP, CWE, informes | Pestañas del panel |
| **MIDGARD** | Auditoría determinista con perfiles nmap y evidencias verificables | Pestaña **MIDGARD** |
| **NETMAP** | Mapa de red por ARP + fingerprint, inventario visual | Pestaña **Netmap** |
| **LibreNMS** | Inventario SNMP, histórico y topología L2 cuando hay SNMP | Servicio Docker enlazado |

## Acceso

| Servicio | URL |
|---|---|
| Panel unificado | `http://192.168.88.252:8780/` |
| MIDGARD | `http://192.168.88.252:8780/#midgard` |
| Netmap | `http://192.168.88.252:8780/#netmap` |
| LibreNMS | `http://192.168.88.252:8780/#librenms` (servicio real en `:8000`) |
| Por Tailscale | igual, con `100.88.33.77` |

Credenciales de LibreNMS en `deploy/librenms/ACCESO.txt` (permisos `600`).

Las vistas internas usan hash (`#midgard`, `#netmap`, `#librenms`). Las URLs antiguas `/midgard.html` y `/netmap.html` redirigen a la vista correspondiente del SPA.

## Tareas, informes y detección de SO

- **Tareas** muestra también los trabajos de **MIDGARD** y **NETMAP** mientras
  están en curso, con su último paso y el log en vivo.
- Si el panel se reinicia con un trabajo en marcha, la salida del proceso se
  escribe directamente en su log: al terminar, el estado final se recupera del
  log o de la evidencia MIDGARD. Un proceso desaparecido pasa a
  **Interrumpido** en vez de quedarse «activo» para siempre.
- **Cancelar** en una tarea ROVSKA detiene de verdad la herramienta: termina el
  `docker exec` y mata el proceso dentro del contenedor (no deja nmap huérfano).
- **Cancelar** también funciona con **MIDGARD** y **NETMAP**: termina el grupo
  de proceso y, en MIDGARD, el contenedor efímero. La evidencia parcial queda
  con estado `cancelled` (nunca `ok`). El botón aparece en la fila de Tareas y
  en la franja superior cuando hay una sola tarea activa.
- **Operaciones** reúne el formulario para lanzar herramientas y su catálogo
  completo con la disponibilidad de cada binario. En **Panel** solo queda un
  resumen con enlace al catálogo.
- **Tareas → Limpiar completadas** oculta del listado las tareas ya terminadas
  sin borrar escaneos, informes, evidencia, anotaciones ni eventos. Las tareas
  activas siguen visibles siempre.
- **Informes** incluye **Borrar informes e historial**: elimina los `informe_*`
  generados y vacía escaneos, hosts, puertos, hallazgos y comprobaciones para
  empezar de cero. Los informes importados en `reports/imports/`, las
  anotaciones y el registro de eventos/operaciones se conservan. No se permite
  mientras haya un escaneo activo.
- La lista de IPs unifica los escaneos de **ROVSKA** y la evidencia de
  **MIDGARD**. Un **barrido de subred** (ROVSKA o MIDGARD) abre un contexto
  nuevo: la lista se limpia en cuanto arranca y se rellena al terminar. Un
  **escaneo de una IP suelta** se suma al contexto vigente. No se borra nada:
  escaneos, informes, evidencias, anotaciones e historial se conservan.
- Los hosts que solo ha visto MIDGARD aparecen con su SO y tipo, pero sin
  hallazgos de ROVSKA (riesgo 0) hasta que un escaneo ROVSKA los analice.
- `nmap` reutiliza los hosts que ya ha descubierto `arp-scan` en la misma
  ejecución. Así un barrido de `/24` no lanza `-Pn`, versión y SO contra los
  256 hosts: solo contra los activos, y el escaneo termina dentro del tiempo
  límite con sus puertos y hallazgos.
- Si `arp-scan` no ve nada (objetivo enrutado o en otra subred), `nmap` hace
  un descubrimiento `-sn` y escanea solo los hosts que responden. Si no hay
  ninguno, se omite el escaneo de puertos en vez de marcar todo el rango como
  activo. El objetivo debe ser la subred real de los equipos (por ejemplo
  `192.168.1.0/24` si ahí están Proxmox y sus invitados), no un rango
  arbitrario: un rango equivocado produce 0 puertos, 0 CVE y hosts fantasma.
- La detección de SO combina `nmap -O`, banners de servicio, SNMP, fabricante
  de la MAC y una sonda TTL: 64 ≈ Linux/Unix, 128 ≈ Windows y 255 ≈ equipo de
  red. La versión exacta de un banner de servicio (p. ej. el FTP de RouterOS)
  prevalece sobre la rama aproximada de `nmap -O`. La confianza se muestra
  siempre en la ficha del host.
- La lista de IPs muestra la distro y la virtualización cuando se puede inferir:
  `Ubuntu 22.04`, `Ubuntu 25.04/25.10 (interim)`, `Debian 12 + Proxmox VE`,
  `Guest Proxmox (LXC/VM)`, `LXC`, `Máquina virtual (QEMU/KVM/VMware/VirtualBox)`
  y `Router`. Los escaneos antiguos se reclasifican al abrir el panel, sin
  repetir el escaneo.
- La **tuerca** situada junto a *Resumen general* ordena la lista por IP,
  nombre de host o estado real de Proxmox. El estado usa `running`/`stopped`
  (los LXC/VM de cada nodo siguen la misma regla), no el color de riesgo. Un
  clic ordena y otro invierte el sentido. El orden y el ancho de la barra se
  guardan en el navegador (`localStorage`), no en el servidor.
- El borde entre la lista y el detalle se puede **arrastrar** para ensanchar o
  estrechar la barra (300–680 px). Doble clic lo devuelve a 440 px. Funciona en
  todas las pestañas; por debajo de 980 px de ancho la barra ocupa la pantalla.

## Proxmox (opcional, API de solo lectura)

La lista unificada puede mostrar los nodos Proxmox y sus VM/LXC sin escanear la
API ni ejecutar nada en el hipervisor:

- Se configura en **Ajustes → Proxmox** con el endpoint (`https://host:8006`),
  el **token ID** (`usuario@realm!nombre`) y su secreto. El token debe tener un
  rol de solo lectura (`PVEAuditor`). No se admiten operaciones de escritura:
  todas las llamadas son `GET` a `/api2/json`.
- Las credenciales se guardan en `data/proxmox.json` con permisos `600` y nunca
  llegan al navegador. Como alternativa se pueden definir
  `ROVSKA_PROXMOX_ENDPOINT`, `ROVSKA_PROXMOX_TOKEN_ID`,
  `ROVSKA_PROXMOX_TOKEN_SECRET`, `ROVSKA_PROXMOX_ENABLED`,
  `ROVSKA_PROXMOX_VERIFY_TLS` y `ROVSKA_PROXMOX_INCLUDE_IN_SCANS`.
- **Guardar y validar** comprueba versión y acceso; **Probar conexión** permite
  validar antes de guardar. Para un certificado propio se puede desactivar
  explícitamente la verificación TLS.
- Si la API falla o el token caduca, el escaneo y la lista siguen funcionando:
  se muestra el aviso y se conserva el último inventario bueno.
- Solo se enriquecen los **nodos que ya están en el contexto actual**. No se
  añaden hosts nuevos. Los invitados escaneados se muestran indentados bajo su
  nodo con un chevron; los que no tienen IP aparecen como **«sin IP detectada»**.
- El punto de color de cada invitado indica su estado: verde para LXC en marcha,
  naranja para VM y para cualquier invitado parado o sin IP.
- En el formulario de escaneo hay dos casillas opcionales: incluir VM/LXC en la
  lista y validar el acceso Proxmox antes de lanzar el escaneo.

## Arranque rápido

```bash
cd ~/ROVSKA-MIDGARD
./run.sh init              # base de datos y directorios
./run.sh up                # imagen/contenedor Kali
./run.sh librenms-up       # LibreNMS (opcional)
./run.sh serve             # panel en primer plano
```

Para dejarlo en segundo plano:

```bash
setsid nohup ./run.sh serve >> /tmp/opencode/rovska-serve.log 2>&1 < /dev/null &
```

## Estructura

```text
ROVSKA-MIDGARD/
├── rovvska/            núcleo y panel (ROVSKA) + integraciones.py
├── midgard/            motor MIDGARD (paquete Python)
├── profiles/           perfiles nmap de MIDGARD
├── netmap/             netmap.py, mapgen.py, map/ y su documentación
├── web/                SPA: index.html, app.js, styles.css
├── data/               base de datos, informes, evidencias y trabajo
├── evidence/           evidencias de MIDGARD
├── tests/              tests de ROVSKA
├── midgard_tests/      tests de MIDGARD
├── docker/kali/        imagen rovvska/kali-tools
├── deploy/librenms/    stack LibreNMS (compose, secretos, db, datos)
├── docs/               documentación (ROVSKA.md, MIDGARD.md, assets)
├── _legacy/            material antiguo conservado para revisión
├── run.sh              lanzador único
├── Makefile            atajos
└── LEEME.txt           guía completa de arranque y arquitectura
```

## Comandos útiles

```bash
./run.sh midgard scan 192.168.88.0/24 -p quick -y
./run.sh midgard ls
./run.sh netmap wlan0
./run.sh librenms-status
./run.sh test
./run.sh clean
```

## Documentación

- `LEEME.txt` — arranque desde cero y material para diagramas.
- `docs/ROVSKA.md` — documentación original de ROVSKA.
- `docs/MIDGARD.md` — documentación original de MIDGARD.
- `netmap/README.md` y `netmap/LEEME.txt` — detalle de NETMAP/LibreNMS.

## Seguridad

- Solo LAN y Tailscale; nada publicado en Internet.
- MariaDB y Redis escuchan en `127.0.0.1`.
- Secretos en `.env`, `deploy/librenms/.env`, `deploy/librenms/librenms.env`,
  `data/proxmox.json` y `ACCESO.txt`, todos con permisos `600`.
- El token de Proxmox es de solo lectura y se usa únicamente en el servidor.
- Auditorías solo con autorización. MIDGARD bloquea objetivos públicos salvo
  `MIDGARD_ALLOW_PUBLIC=1` y `--authorized`.
- Sin IA, sin telemetría y sin envío de datos a la nube.
