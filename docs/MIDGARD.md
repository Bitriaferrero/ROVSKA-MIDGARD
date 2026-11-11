# MIDGARD

Auditoría de red **determinista y offline**. La IA solo se usó para escribir
este paquete; en tiempo de ejecución **no hay modelos, prompts, API keys ni
telemetría**.

```text
Tú eliges objetivo y perfil
        ↓
MIDGARD construye el comando de Nmap (sin shell)
        ↓
Docker (imagen Kali de ROVSKA) ejecuta nmap
        ↓
Parsers locales + reglas fijas de SO
        ↓
Evidencias con hash + JSON + CSV + HTML
```

## Garantías

- **Sin IA en runtime.** No se importan clientes de IA ni se leen sus variables.
- **Sin telemetría.** No hay envío de datos a terceros.
- **Sin actualizaciones remotas.** No se ejecuta `--script-updatedb`.
- **Alcance explícito.** Por defecto solo redes privadas; un objetivo público
  exige `--authorized` y `MIDGARD_ALLOW_PUBLIC=1`.
- **Sin `shell=True`.** Cada herramienta se ejecuta como lista de argumentos.
- **Evidencias verificables.** `manifest.json` incluye SHA-256 de cada artefacto.
- **Metasploit controlado.** Se genera un `.rc` con módulos *auxiliary*;
  la ejecución exige `MIDGARD_ALLOW_MSF=1`, `--yes` y validación previa.
  MIDGARD no incluye exploits ni payloads.

## Requisitos

- Python 3.11 o superior (solo biblioteca estándar).
- Docker con la imagen de ROVSKA: `rovvska/kali-tools:latest`.
- El contenedor de ROVSKA no necesita estar arrancado: MIDGARD usa
  contenedores efímeros con `--network host` y `NET_RAW`/`NET_ADMIN`.

## Uso rápido

```bash
cd ~/ROVSKA-MIDGARD

./run.sh doctor
./run.sh profiles
./run.sh menu

# Escaneo de la LAN con SO y versiones
./run.sh scan 192.168.88.0/24 --profile quick --yes

# Solo ver el comando, sin ejecutar
./run.sh scan 192.168.88.1 --profile router --dry-run

# Sonda SNMP para la versión exacta (RouterOS, Linux, etc.)
./run.sh scan 192.168.88.1 --profile router --snmp --snmp-community public --yes

# Ver resultados
./run.sh ls
./run.sh show <run_id> --details
./run.sh report <run_id> --open

# Metasploit: plan y ejecución controlada de módulos auxiliary
./run.sh msf plan <run_id>
MIDGARD_ALLOW_MSF=1 ./run.sh msf run <run_id> --dry-run
MIDGARD_ALLOW_MSF=1 ./run.sh msf run <run_id> --yes
```

## Perfiles

| Perfil | Uso |
|---|---|
| `discovery` | Descubrir hosts vivos (`-sn`), sin puertos ni SO |
| `quick` | Top 1000 TCP + versiones + SO + banners |
| `web` | Puertos web habituales + cabeceras + SO |
| `infra` | Servicios de red, SMB, SNMP (TCP+UDP) + SO |
| `router` | Administración de routers/MikroTik + SNMP + SO |
| `full` | 65535 TCP + versiones + SO + scripts seguros |
| `custom` | Exige `--ports` |

Los perfiles están en `profiles/*.json` y no contienen código.

## Detección de sistema operativo

MIDGARD combina, en este orden:

1. `nmap -O --osscan-guess` → familia (Linux 5.x, Windows, macOS…).
2. Banner SSH → `OpenSSH 7.2p2 Ubuntu-4ubuntu2.10` = Ubuntu 16.04.
3. Cabecera HTTP → `Apache/2.4.56 (Debian)` = Debian 11.
4. SMB → `smb-os-discovery` con build de Windows (22631 = Windows 11 23H2).
5. SNMP → `sysDescr` con `RouterOS 6.49.23`.
6. Fabricante de la MAC → Samsung/Apple/etc. (solo familia, no modelo).

Cada host muestra **nombre, versión, confianza y fuentes**. La detección es
best-effort: un equipo que no exponga banners puede quedarse en
“SO desconocido” o en una familia genérica. En móviles lo normal es detectar
Android/iOS y el fabricante, no el modelo exacto.

## Evidencias

Cada ejecución crea `evidence/<fecha>-<perfil>-<objetivo>/` con:

```text
command.txt        comando exacto y metadatos
nmap.xml           salida cruda de Nmap
nmap.stderr.txt    errores/progreso
snmp.json          sysDescr/versión exacta (solo con --snmp)
hosts.json         hosts, puertos, scripts y SO
hosts.csv          tabla para Excel
report.html        informe autocontenido
manifest.json      hashes SHA-256, versiones y declaración offline
```

El manifiesto contiene:

```json
{
  "ai_runtime": false,
  "telemetry": false,
  "external_network": "solo el objetivo autorizado"
}
```

## Metasploit

```bash
./run.sh msf plan <run_id>
```

Genera `msf_plan.rc` con módulos de reconocimiento (`ssh_version`,
`smb_version`, `http_version`…). No incluye exploits ni payloads. El comando
para ejecutarlo manualmente se imprime en pantalla.

La ejecución automática es opcional y defensiva:

```bash
MIDGARD_ALLOW_MSF=1 ./run.sh msf run <run_id> --dry-run
MIDGARD_ALLOW_MSF=1 ./run.sh msf run <run_id> --yes
```

Antes de ejecutar se valida el RC: solo se aceptan líneas `use auxiliary/...`;
se rechazan exploits, payloads, sesiones y módulos `post/`. El contenedor
monta la evidencia en `/out:ro`, usa `msfconsole -q -n` y deja
`msf_run.log`, `msf_run.stderr.txt` y `msf_run.json` en la evidencia.

## Variables de entorno

| Variable | Por defecto | Efecto |
|---|---|---|
| `MIDGARD_IMAGE` | `rovvska/kali-tools:latest` | Imagen de herramientas |
| `MIDGARD_CONTAINER` | `rovska-kali` | Contenedor de ROVSKA (solo diagnóstico) |
| `MIDGARD_EVIDENCE` | `./evidence` | Directorio de evidencias |
| `MIDGARD_PROFILES` | `./profiles` | Directorio de perfiles |
| `MIDGARD_ALLOW_PUBLIC` | `0` | Permitir objetivos públicos (requiere `--authorized`) |
| `MIDGARD_ALLOW_MSF` | `0` | Permite `msf run` (solo módulos auxiliary) |
| `MIDGARD_OPERATOR` | usuario del sistema | Nombre en el manifiesto |

## Verificación

```bash
./run.sh verify
python3 -m unittest discover -s tests -v
```

`verify` comprueba que el código no importa clientes de IA, sockets directos
ni endpoints de telemetría. Los tests usan XML de laboratorio, no datos reales.

## Límites conocidos

- La versión exacta de SO no siempre es posible; depende de banners y SNMP.
- SNMP requiere UDP/161 accesible y la comunidad correcta; por defecto se
  prueba `public` y la comunidad usada nunca se guarda en claro si no es pública.
- `-O` necesita al menos un puerto abierto y uno cerrado en el objetivo.
- Los escaneos UDP son lentos y pueden generar falsos negativos.
- Los scripts NSE están limitados a una allowlist segura.
- No se ejecutan exploits. Cualquier acción ofensiva requiere autorización
  escrita, alcance firmado y una decisión humana.

## Relación con ROVSKA

MIDGARD reutiliza la **imagen** de herramientas de ROVSKA, no su base de datos
ni su panel. Así el paquete es autónomo, reproducible y no duplica el motor.
