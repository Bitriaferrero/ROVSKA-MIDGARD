"""Configuración común de los tests.

Se ejecutan contra una base de datos temporal para no tocar ``data/``.
"""

from __future__ import annotations

import os
import tempfile

_TMP = tempfile.mkdtemp(prefix="rovska-tests-")

os.environ.setdefault("ROVSKA_DATA_DIR", _TMP)
os.environ.setdefault("ROVSKA_RUNNER", "local")
os.environ.setdefault("ROVSKA_OPENCODE_ENABLED", "0")
os.environ.setdefault("ROVSKA_ALLOW_ATTACK", "0")
