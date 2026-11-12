# Build context is the REPO ROOT (see docker-compose.yml: context ../..).

FROM python:3.11-slim

RUN useradd -m -s /usr/sbin/nologin player
WORKDIR /service

COPY services/net-ssrf-pivot/src/gateway.py .

COPY platform/common/flagd.py /opt/flagd.py
COPY services/net-ssrf-pivot/entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

ARG INITIAL_FLAG=FLAG{waiting_for_first_round}
ENV FLAG_PATH="/flag.txt"
ENV FLAGD_PORT="10000"
ENV GATEWAY_PORT="6002"
RUN echo "$INITIAL_FLAG" > /flag.txt && chown player:player /flag.txt && chmod 644 /flag.txt

EXPOSE 6002
# The echo service (6000) and admin service (6001) are NOT exposed or
# published anywhere in docker-compose.yml -- they bind to 127.0.0.1
# inside the container, and are only reachable at all through the
# gateway's own missing allowlist, which is exactly the bug.
# FLAGD_PORT (10000) is intentionally NOT exposed/published anywhere in
# docker-compose.yml either: it must only be reachable from the
# checker's container on the internal Docker network.

USER player
CMD ["/entrypoint.sh"]
