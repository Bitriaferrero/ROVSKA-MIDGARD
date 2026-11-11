# ROVSKA — contenedor de herramientas (Kali Rolling)
#
# La imagen es grande porque incluye Metasploit y las plantillas de Nuclei.
# Puedes aligerarla con argumentos de build:
#   docker compose build --build-arg WITH_ATTACK=0 --build-arg WITH_WEB=0
#
# El contenedor no se publica en la red: usa network_mode: host y solo
# ejecuta las herramientas que ROVSKA le pasa por `docker exec`.

FROM kalilinux/kali-rolling

ARG DEBIAN_FRONTEND=noninteractive
ARG WITH_WEB=1
ARG WITH_INFRA=1
ARG WITH_ATTACK=1

LABEL org.opencontainers.image.title="ROVSKA Kali tools"
LABEL org.opencontainers.image.description="Herramientas de auditoría para ROVSKA (nmap, nuclei, nikto, hydra, metasploit...)"
LABEL org.opencontainers.image.licenses="GPL-3.0-or-later"

ENV LANG=C.UTF-8 \
    LC_ALL=C.UTF-8 \
    PYTHONUNBUFFERED=1 \
    TERM=xterm-256color

# Utilidades base imprescindibles para el runner y los parsers.
RUN set -eux; \
    apt-get update; \
    apt-get install -y --no-install-recommends \
        ca-certificates \
        curl \
        wget \
        jq \
        git \
        python3 \
        python3-pip \
        iproute2 \
        iputils-ping \
        net-tools \
        procps \
        dnsutils \
        whois \
        openssl \
        libssl-dev \
        ruby \
        perl \
        tini; \
    rm -rf /var/lib/apt/lists/*

# Herramientas de red (siempre).
RUN set -eux; \
    apt-get update; \
    for pkg in nmap arp-scan masscan; do \
        apt-get install -y --no-install-recommends "$pkg" || echo "AVISO: no se pudo instalar $pkg"; \
    done; \
    rm -rf /var/lib/apt/lists/*

# Web: fingerprinting, escaneo de vulnerabilidades y fuzzing.
RUN set -eux; \
    if [ "$WITH_WEB" = "1" ]; then \
        apt-get update; \
        for pkg in whatweb nikto nuclei ffuf testssl.sh seclists; do \
            apt-get install -y --no-install-recommends "$pkg" || echo "AVISO: no se pudo instalar $pkg"; \
        done; \
        rm -rf /var/lib/apt/lists/*; \
    fi

# Infraestructura: SSH, SMB, SNMP y DNS.
RUN set -eux; \
    if [ "$WITH_INFRA" = "1" ]; then \
        apt-get update; \
        for pkg in ssh-audit enum4linux-ng snmp snmp-mibs-downloader dnsrecon smbclient; do \
            apt-get install -y --no-install-recommends "$pkg" || echo "AVISO: no se pudo instalar $pkg"; \
        done; \
        rm -rf /var/lib/apt/lists/*; \
    fi

# Ofensivas: fuerza bruta, explotación y Exploit-DB.
RUN set -eux; \
    if [ "$WITH_ATTACK" = "1" ]; then \
        apt-get update; \
        for pkg in hydra metasploit-framework exploitdb; do \
            apt-get install -y --no-install-recommends "$pkg" || echo "AVISO: no se pudo instalar $pkg"; \
        done; \
        rm -rf /var/lib/apt/lists/*; \
    fi

# Informes PDF profesionales. WeasyPrint renderiza el HTML con CSS de impresión;
# las fuentes evitan que el PDF dependa de las del host.
RUN set -eux; \
    apt-get update; \
    apt-get install -y --no-install-recommends \
        weasyprint \
        fonts-dejavu-core \
        fonts-liberation; \
    rm -rf /var/lib/apt/lists/*

# Plantillas de Nuclei (si el binario está disponible). No rompe el build si falla.
RUN if command -v nuclei >/dev/null 2>&1; then \
        nuclei -update-templates -silent || true; \
    fi

# Exploit-DB local (searchsploit). Tolerante a fallos de red.
RUN if command -v searchsploit >/dev/null 2>&1; then \
        searchsploit -u >/dev/null 2>&1 || true; \
    fi

# Wordlists: enlaza las de Kali y deja una ruta estable para ffuf.
RUN set -eux; \
    mkdir -p /wordlists; \
    if [ -d /usr/share/seclists ]; then ln -sfn /usr/share/seclists /wordlists/seclists; fi; \
    if [ -d /usr/share/wordlists ]; then ln -sfn /usr/share/wordlists /wordlists/wordlists; fi; \
    mkdir -p /data/work /data/reports /data/evidence

COPY entrypoint.sh /usr/local/bin/rovska-entrypoint
RUN chmod +x /usr/local/bin/rovska-entrypoint

WORKDIR /data
VOLUME ["/data"]

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD test -d /data/work || exit 1

ENTRYPOINT ["/usr/bin/tini", "--", "/usr/local/bin/rovska-entrypoint"]
CMD ["sleep", "infinity"]
