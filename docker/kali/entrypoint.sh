#!/bin/sh
# ROVSKA — entrypoint del contenedor Kali.
# Prepara el volumen de datos y muestra un resumen de herramientas.
set -eu

mkdir -p /data/work /data/reports /data/evidence

if [ "${ROVSKA_QUIET:-0}" != "1" ]; then
    echo "=============================================================="
    echo "  ROVSKA · contenedor de herramientas"
    echo "  datos: /data"
    echo "--------------------------------------------------------------"
    for bin in nmap arp-scan masscan whatweb nikto nuclei ffuf \
               testssl ssh-audit enum4linux-ng snmpwalk dnsrecon \
               hydra msfconsole searchsploit; do
        if command -v "$bin" >/dev/null 2>&1; then
            printf '  %-18s %s\n' "$bin" "ok"
        else
            printf '  %-18s %s\n' "$bin" "no instalado"
        fi
    done
    echo "=============================================================="
fi

exec "$@"
