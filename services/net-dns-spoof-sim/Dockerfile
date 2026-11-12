# Build context is the REPO ROOT (see docker-compose.yml: context ../..).

FROM python:3.11-slim

RUN useradd -m -s /usr/sbin/nologin player
WORKDIR /service

COPY services/net-dns-spoof-sim/src/resolver.py .

COPY platform/common/flagd.py /opt/flagd.py
COPY services/net-dns-spoof-sim/entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

ARG INITIAL_FLAG=FLAG{waiting_for_first_round}
ENV FLAG_PATH="/flag.txt"
ENV FLAGD_PORT="10000"
ENV RESOLVER_PORT="6003"
RUN echo "$INITIAL_FLAG" > /flag.txt && chown player:player /flag.txt && chmod 644 /flag.txt

EXPOSE 6003
# FLAGD_PORT (10000) is intentionally NOT exposed/published anywhere in
# docker-compose.yml: it must only be reachable from the checker's
# container on the internal Docker network.

USER player
CMD ["/entrypoint.sh"]
