# Stdlib-only project → a minimal image, no pip install step at all.
FROM python:3.12-slim

WORKDIR /app
COPY dns_server/ ./dns_server/
COPY web/ ./web/
COPY blocklists/ ./blocklists/

# 53 = DNS (UDP + TCP), 8053 = dashboard. In-container we bind 0.0.0.0 so the
# published ports are reachable from the host / LAN.
EXPOSE 53/udp 53/tcp 8053/tcp

ENTRYPOINT ["python", "-m", "dns_server.main", \
    "--host", "0.0.0.0", "--port", "53", "--web-port", "8053", \
    "--blocklist", "blocklists/sample.txt"]
