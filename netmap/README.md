# ROVSKA NETMAP

Inventario y mapa visual de la red para visitas. Dos capas:

1. **Mapa de visita (sin credenciales)** — ARP + fingerprint de puertos. Funciona siempre.
2. **LibreNMS** — inventario SNMP, histórico y topología L2 real cuando los equipos tienen SNMP.

## Acceso

| Servicio | URL |
|---|---|
| Mapa de visita | `http://192.168.88.252:8000/netmap/index.html` |
| LibreNMS | `http://192.168.88.252:8000/` |
| Por Tailscale | `http://100.88.33.77:8000/` |

Credenciales del panel en `ACCESO.txt` (permisos `600`). No se publica en Internet.

## Operación

```bash
cd ~/ROVSKA-MIDGARD/netmap
docker compose ps                 # estado
docker compose logs -f librenms   # logs
docker compose down               # parar
docker compose up -d              # arrancar
```

### Regenerar el mapa de visita

```bash
cd ~/ROVSKA-MIDGARD/netmap
python3 netmap.py                 # interfaz por defecto: wlan0
python3 netmap.py --iface eth0
```

Hace un `arp-scan` (contenedor `rovska-kali`) y un `nmap --top-ports 200 -sV` por host.
Solo lectura: no autentica, no explota nada y no modifica equipos.

Salida: `map/index.html` y `map/scan.json`. Se sirve en `/netmap/index.html`.

Si hay que analizar otra subred, ejecutar `arp-scan`/`nmap` contra ella y adaptar
`netmap.py`; por defecto usa la `/24` de la interfaz.

## Topología real con SNMP (opcional, recomendado)

LibreNMS construye el mapa L2 (switches, puertos, LLDP/CDP, VLAN) **solo con SNMP**.
Sin SNMP únicamente puede hacer ping.

En el MikroTik (RouterOS), con autorización del responsable:

```routeros
/snmp set enabled=yes
/snmp community add name=rovska_ro addresses=192.168.88.0/24 read-access=yes write-access=no
```

Después, en LibreNMS: *Devices → Add Device* → IP `192.168.88.1`, versión `v2c`,
comunidad `rovska_ro`. Repetir con cada switch/AP que soporte SNMP.

No se ha tocado la configuración del router: el SNMP está cerrado (`UDP/161` sin respuesta).

### Proxmox (opcional)

En el host Proxmox:

```bash
apt install librenms-agent
systemctl enable --now check_mk@8892
```

En LibreNMS, en el dispositivo Proxmox, activar `enable_proxmox` y añadir la aplicación
`Proxmox` (aplicaciones → proxmox). Requiere que el host tenga SNMP habilitado.
Solo aporta tráfico por VM; no sustituye la API de Proxmox.

## Limitaciones conocidas

- Docker de este host no puede publicar puertos (fallo DNAT). Todo usa `network_mode: host`.
  MariaDB escucha en `127.0.0.1:3306` y Redis en `127.0.0.1:6379`.
- Los equipos con ICMP filtrado aparecen sin latencia; los que filtran ARP no aparecen.
- La red actual tiene aislamiento de clientes: solo se ven ARP de los activos en ese momento.
- El router expone `21/ftp`, `23/telnet` y `2000/bandwidth-test`; conviene revisarlo.
