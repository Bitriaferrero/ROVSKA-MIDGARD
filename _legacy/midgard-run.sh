#!/usr/bin/env bash
# MIDGARD — envoltorio de arranque. No instala nada en el host.
set -euo pipefail

cd "$(dirname "$0")"

PYTHON="${PYTHON:-python3}"

if ! command -v "$PYTHON" >/dev/null 2>&1; then
  echo "[error] no encuentro $PYTHON" >&2
  exit 1
fi

exec "$PYTHON" -m midgard "$@"
