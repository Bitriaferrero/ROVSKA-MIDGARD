# ROVSKA-MIDGARD — atajos. Backend en Python estándar; herramientas en Docker.

PYTHON ?= python3
TARGET ?= 192.168.1.0/24
PROFILE ?= quick
HOST ?= 0.0.0.0
PORT ?= 8780
IFACE ?= wlan0

.PHONY: help init doctor up down shell serve scan midgard netmap \
        librenms-up librenms-down librenms-status status report tools test clean env

help:
	@echo "ROVSKA-MIDGARD"
	@echo "  make init              crea base de datos y directorios"
	@echo "  make doctor            comprueba Docker, herramientas y contenedor"
	@echo "  make up                construye y arranca el contenedor Kali"
	@echo "  make down              para el contenedor Kali"
	@echo "  make shell             consola dentro del contenedor"
	@echo "  make serve             panel unificado en http://$(HOST):$(PORT)"
	@echo "  make scan TARGET=... PROFILE=quick"
	@echo "  make midgard ARGS='scan 192.168.1.0/24 -p quick -y'"
	@echo "  make netmap IFACE=wlan0"
	@echo "  make librenms-up       arranca LibreNMS"
	@echo "  make librenms-down     para LibreNMS"
	@echo "  make librenms-status   estado de LibreNMS"
	@echo "  make status            escaneos y operaciones recientes"
	@echo "  make report SCAN=...   regenera informes"
	@echo "  make tools             catálogo de herramientas"
	@echo "  make test              tests de ROVSKA y MIDGARD"
	@echo "  make clean             borra caché de Python (no borra datos)"

init:
	./run.sh init


doctor:
	./run.sh doctor


env:
	@[ -f .env ] || cp .env.example .env
	@echo ".env listo"

up:
	@[ -f .env ] || cp .env.example .env
	docker compose up -d --build

down:
	docker compose down

shell:
	docker compose exec kali bash

serve:
	./run.sh serve


scan:
	./run.sh scan "$(TARGET)" "$(PROFILE)"


midgard:
	./run.sh midgard $(ARGS)


netmap:
	./run.sh netmap "$(IFACE)"


librenms-up:
	docker compose -f deploy/librenms/compose.yml up -d

librenms-down:
	docker compose -f deploy/librenms/compose.yml down

librenms-status:
	./run.sh status


status:
	./run.sh status

report:
	$(PYTHON) -m rovvska report $(SCAN)

tools:
	$(PYTHON) -m rovvska tools

test:
	./run.sh test


clean:
	./run.sh clean

