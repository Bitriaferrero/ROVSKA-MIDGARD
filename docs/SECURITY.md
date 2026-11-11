# Seguridad y uso responsable

ROVSKA ejecuta herramientas ofensivas reales. Este documento describe el modelo
de autorización, las fronteras de aislamiento, los datos que maneja y las reglas
que el operador debe respetar.

> Si no puedes demostrar autorización escrita sobre un objetivo, no lo escanees.

---

## 1. Modelo de autorización

Hay tres puertas independientes:

1. **Alcance** (`scope.py`): el objetivo debe ser privado o estar explícitamente
   permitido.
2. **Autorización expresa** (`authorization=true`): obligatoria para objetivos
   públicos y para ejecutar Hydra/Metasploit.
3. **Interruptor de ataque** (`ROVSKA_ALLOW_ATTACK=1`): sin él, las herramientas
   ofensivas se fuerzan a `dry-run` aunque se pida ejecución.

Ninguna operación real depende de una sola de ellas.

### Reglas de alcance

| Objetivo | Requisito |
| --- | --- |
| `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, `127.0.0.0/8`, `169.254.0.0/16`, `100.64.0.0/10`, `::1/128`, `fc00::/7`, `fe80::/10` | Permitido por defecto. |
| Público, sin `ROVSKA_ALLOW_PUBLIC` | Bloqueado. |
| Público, con `ROVSKA_ALLOW_PUBLIC=1` | Requiere `authorization=true`. |
| Público con `ROVSKA_ALLOWED_CIDRS` definido | Debe estar dentro de un rango de la lista. |
| Cualquier objetivo | No puede superar `ROVSKA_MAX_HOSTS` (256 por defecto). |
| Hostname | Se resuelve y se valida cada IP resultante. |
| Entrada con caracteres raros, vacía o > 512 caracteres | Rechazada. |

La validación se aplica **dos veces**: al encolar (API/CLI) y al ejecutar
(`scanner`). Es defensa en profundidad, no redundancia decorativa.

### Operaciones ofensivas

| Condición | Resultado |
| --- | --- |
| `requires_attack=true` y `ROVSKA_ALLOW_ATTACK=0` | `dry-run` forzado; se registra en `operations.dry_run=1`. |
| `ROVSKA_ALLOW_ATTACK=1` y `execute=false` | `dry-run`. |
| `ROVSKA_ALLOW_ATTACK=1`, `execute=true`, `authorization=false` | El adaptador rechaza la ejecución con error explícito. |
| Las tres condiciones | Ejecución real, registrada con comando y salida. |

Hydra y Metasploit comprueban `authorization` **dentro del adaptador**, no solo
en la capa superior. Esto evita que una llamada directa al runner se salte la
política.

---

## 2. Aislamiento de las herramientas

El contenedor `rovska-kali`:

- Usa `network_mode: host` para ver la LAN real (ARP y SYN scan). **Esto
  significa que no hay aislamiento de red**: el contenedor ve las mismas
  interfaces que el host.
- Añade solo `NET_RAW` y `NET_ADMIN`, necesarias para ARP/ICMP/SYN.
- Aplica `no-new-privileges:true`.
- Monta únicamente `./data:/data`; no monta el resto del host.
- Usa `tmpfs` para `/tmp` y un `stop_grace_period` corto.
- No publica puertos ni ejecuta un servicio de red propio.

Recomendaciones:

- Ejecuta ROVSKA en una máquina de auditoría dedicada, no en tu estación diaria.
- No uses `network_mode: host` en Docker Desktop; usa una VM Linux.
- Revisa el `Dockerfile` antes de construir: instala Metasploit y Exploit-DB.
- Si no necesitas ataque, construye con `WITH_ATTACK=0`.
- No ejecutes el contenedor con `--privileged`.

El runner `local` (`ROVSKA_RUNNER=local`) existe para desarrollo y tests. Usa
los binarios del host y **no** ofrece aislamiento; no lo uses en producción.

---

## 3. Superficie del panel y la API

- **Escucha local por defecto**: `127.0.0.1:8780`. No lo expongas a Internet.
- **Token de API**: si `ROVSKA_API_TOKEN` está definido, toda escritura exige
  `X-ROVSKA-Token`. Las lecturas no lo exigen; si necesitas confidencialidad,
  usa un proxy con autenticación o túnel SSH.
- **Same-origin**: se rechazan escrituras con `Origin` distinto del `Host` para
  mitigar CSRF.
- **Límite de cuerpo**: 2 MB por petición.
- **Errores**: no se devuelve traza salvo `ROVSKA_DEBUG=1`.
- **Estáticos**: solo se sirven ficheros de `web/` y de `data/reports/`; las
  rutas se normalizan para evitar traversal.
- **Sin TLS**: si lo expones fuera de localhost, pon delante un reverse proxy
  con TLS y autenticación.

Checklist mínima antes de compartir el panel:

```bash
export ROVSKA_API_TOKEN="$(python3 -c 'import secrets; print(secrets.token_urlsafe(32))')"
export ROVSKA_HOST=127.0.0.1
python3 -m rovvska serve
```

---

## 4. Datos y privacidad

ROVSKA almacena:

- Direcciones IP, MAC, fabricantes, hostnames, SO y puertos.
- Banners, versiones y salidas crudas de las herramientas.
- Hallazgos, evidencias y recomendaciones.
- Comandos ejecutados y logs.

Todo queda en `data/` (SQLite + ficheros). No hay telemetría ni envío a
terceros. El orquestador OpenCode **sí** envía el contexto del escaneo al
proveedor del modelo cuando se usa `orchestrate` o `rovska_plan`; si esto no es
aceptable, desactívalo con `ROVSKA_OPENCODE_ENABLED=0`.

Buenas prácticas:

- Cifra el disco o el directorio `data/` si contiene datos de cliente.
- Limita los permisos (`chmod 700 data`).
- Borra evidencias antiguas según la política de retención acordada.
- No adjuntes informes con datos personales sin anonimizar.
- Revisa las salidas antes de compartirlas: pueden contener banners con
  información sensible.

---

## 5. Riesgos del componente de IA

OpenCode propone planes; ROVSKA los valida. Aun así:

- **Prompt injection**: la salida de una herramienta (banner, título HTTP,
  fichero) puede contener texto malicioso. ROVSKA lo trata como datos y no como
  instrucciones; el orquestador solo acepta un JSON de plan y valida cada paso.
- **Alucinación**: el modelo puede proponer herramientas o módulos inexistentes.
  `validate_plan()` los descarta y el plan cae a la lista permitida.
- **Fuga de contexto**: el prompt incluye hosts, puertos y hallazgos. No lo uses
  con datos que no puedas enviar al proveedor del modelo.
- **Coste/tiempo**: `ROVSKA_OPENCODE_TIMEOUT` limita la espera (300 s por
  defecto).

Regla: la IA **nunca** ejecuta comandos directamente. Solo produce un plan que
el código determinista valida y ejecuta.

---

## 6. Registro y auditoría

- Cada operación guarda `argv`, estado, `dry_run`, `exit_code`, log y resultado.
- Cada evidencia guarda su SHA-256.
- Cada escaneo guarda objetivo, perfil, opciones, alcance y estadísticas.
- Los eventos se persisten en `events` y se pueden seguir por SSE.

Para una auditoría formal, exporta también:

```bash
sqlite3 data/rovska.db ".backup 'data/backup-$(date +%F).db'"
sha256sum data/reports/*
```

---

## 7. Respuesta ante incidentes

Si un escaneo sale del alcance previsto:

1. Cancela el trabajo (`POST /api/scans/<id>/cancel` o `Ctrl-C` en la CLI).
2. Detén el contenedor: `docker compose stop kali`.
3. Revisa `operations`, `tool_runs` y `events` para reconstruir lo ejecutado.
4. Conserva las evidencias y notifica al responsable del sistema afectado.
5. Documenta la causa (objetivo mal escrito, allowlist demasiado amplia, error
   humano) y corrige la configuración antes de reanudar.

Si detectas una vulnerabilidad real durante una prueba:

- No la explotes más allá de lo autorizado.
- Documenta la evidencia mínima necesaria.
- Notifica por el canal acordado y respeta los plazos de divulgación.

---

## 8. Lista de comprobación previa

- [ ] Tengo autorización escrita y vigente.
- [ ] El alcance está escrito: IPs/CIDR, ventana horaria y contactos.
- [ ] `ROVSKA_MAX_HOSTS` y `ROVSKA_TOOL_TIMEOUT` son razonables.
- [ ] `./run.sh init` se ejecutó antes de `docker compose up` (evita que `data/` quede propiedad de root).
- [ ] `ROVSKA_ALLOW_PUBLIC` está en `0` salvo necesidad justificada.
- [ ] `ROVSKA_ALLOWED_CIDRS` limita los públicos si aplica.
- [ ] `ROVSKA_ALLOW_ATTACK` está en `0` salvo prueba ofensiva autorizada.
- [ ] El panel escucha en `127.0.0.1` o detrás de un proxy autenticado.
- [ ] `data/` tiene permisos restringidos y política de retención.
- [ ] Sé cómo cancelar y detener el contenedor.
- [ ] He leído las limitaciones del informe y las incluiré en el entregable.

---

## 9. Divulgación responsable

ROVSKA no incluye exploits funcionales ni payloads. Los adaptadores de ataque
invocan herramientas estándar (Hydra, Metasploit) y quedan desactivados por
defecto. Si encuentras un fallo en ROVSKA, documenta la reproducción y evita
publicar detalles que permitan abuso antes de que se corrija.
