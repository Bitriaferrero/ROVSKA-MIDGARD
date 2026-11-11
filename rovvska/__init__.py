#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""ROVSKA — plataforma de auditoría de red ofensiva y defensiva.

Backend en biblioteca estándar de Python. Las herramientas se ejecutan en un
contenedor Kali (Docker) y los resultados se correlacionan con MITRE ATT&CK,
PTES, OSSTMM, OWASP y CWE.

Uso rápido::

    python3 -m rovvska init
    python3 -m rovvska serve
    python3 -m rovvska scan 192.168.1.0/24 --profile quick
"""

from __future__ import annotations

__version__ = "1.0.0"
__all__ = ["__version__"]
