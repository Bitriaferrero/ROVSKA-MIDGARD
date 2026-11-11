#!/usr/bin/env bash
# ROVSKA-MIDGARD — arranque unificado. No instala nada en el host.
set -euo pipefail

cd "$(dirname "$0")"

# Carga .env para que el panel y las CLIs vean la misma configuración.
if [ -f .env ]; then
  set -a
  # shellcheck disable=SC1091
  . ./.env
  set +a
fi

PYTHON="${PYTHON:-python3}"
HOST="${ROVSKA_HOST:-0.0.0.0}"
PORT="${ROVSKA_PORT:-8780}"
NETMAP_IFACE="${NETMAP_IFACE:-wlan0}"

usage() {
  cat <<'EOF'
ROVSKA-MIDGARD — un solo panel, tres motores

  ./run.sh init              crea la base de datos y los directorios
  ./run.sh doctor            comprueba Docker, contenedor y herramientas
  ./run.sh up                construye y arranca el contenedor Kali
  ./run.sh down              para y elimina el contenedor Kali
  ./run.sh shell             consola dentro del contenedor Kali
  ./run.sh serve             panel unificado en http://0.0.0.0:8780
  ./run.sh scan TARGET [p]   auditoría ROVSKA
  ./run.sh midgard [...]      CLI de MIDGARD (scan, ls, show, doctor...)
  ./run.sh netmap [iface]     regenera el mapa de red
  ./run.sh librenms-up        arranca LibreNMS (deploy/librenms)
  ./run.sh librenms-down      para LibreNMS
  ./run.sh librenms-status    estado de LibreNMS
  ./run.sh status             escaneos y operaciones recientes
  ./run.sh test              tests de ROVSKA y MIDGARD
  ./run.sh env               crea .env desde .env.example si no existe
  ./run.sh clean             borra caché de Python (no borra datos)

UI:      http://<host>:8780/            (Panel · MIDGARD · Netmap)
LibreNMS http://<host>:8000/            (servicio aparte, mismo host)
Perfiles ROVSKA: discovery, quick, full, web, infra, deep, attack
Perfiles MIDGARD: discovery, quick, full, web, infra, router, custom
EOF
}

need_docker() {
  if ! command -v docker >/dev/null 2>&1; then
    echo "[!] Docker no está instalado o no está en PATH." >&2
    exit 1
  fi
}

case "${1:-help}" in
  init)
    "$PYTHON" -m rovvska init
    ;;
  doctor)
    "$PYTHON" -m rovvska doctor
    ;;
  env)
    if [ -f .env ]; then
      echo "[i] .env ya existe; no se toca."
    else
      cp .env.example .env
      echo "[i] .env creado a partir de .env.example"
    fi
    ;;
  up)
    need_docker
    [ -f .env ] || cp .env.example .env
    "$PYTHON" -m rovvska init
    docker compose up -d --build
    echo "[i] contenedor Kali en marcha. Comprueba con: ./run.sh doctor"
    ;;
  down)
    need_docker
    docker compose down
    ;;
  shell)
    need_docker
    docker compose exec kali bash
    ;;
  serve)
    "$PYTHON" -m rovvska serve --host "$HOST" --port "$PORT"
    ;;
  scan)
    shift || true
    target="${1:-}"
    profile="${2:-quick}"
    if [ -z "$target" ]; then
      echo "[!] falta el objetivo. Ejemplo: ./run.sh scan 192.168.1.0/24 quick" >&2
      exit 1
    fi
    "$PYTHON" -m rovvska scan "$target" --profile "$profile"
    ;;
  midgard)
    shift || true
    exec "$PYTHON" -m midgard "$@"
    ;;
  netmap)
    shift || true
    exec "$PYTHON" netmap/netmap.py --iface "${1:-$NETMAP_IFACE}"
    ;;
  librenms-up)
    need_docker
    docker compose -f deploy/librenms/compose.yml up -d
    ;;
  librenms-down)
    need_docker
    docker compose -f deploy/librenms/compose.yml down
    ;;
  librenms-status)
    need_docker
    docker compose -f deploy/librenms/compose.yml ps
    ;;
  status)
    "$PYTHON" -m rovvska status
    ;;
  test)
    "$PYTHON" -m unittest discover -s tests -v
    "$PYTHON" -m unittest discover -s midgard_tests -t . -v
    ;;
  clean)
    find . -type d -name __pycache__ -prune -exec rm -rf {} + 2>/dev/null || true
    find . -type f -name '*.pyc' -delete 2>/dev/null || true
    echo "[i] caché de Python limpiada."
    ;;
  help|-h|--help|*)
    usage
    ;;
esac
