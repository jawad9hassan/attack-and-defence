# Build context is the REPO ROOT (see docker-compose.yml: context ../..).

FROM ubuntu:22.04

RUN apt-get update && \
    apt-get install -y --no-install-recommends gcc libc6-dev socat python3 && \
    rm -rf /var/lib/apt/lists/*

RUN useradd -m -s /usr/sbin/nologin player
WORKDIR /service

COPY services/re-crackme/src/crackme.c .
# -no-pie keeps addresses fixed and predictable, same as pwn-baby/
# pwn-format, even though this challenge needs no memory corruption --
# it just keeps the training environment consistent across services.
RUN gcc -no-pie -o crackme crackme.c && \
    chown root:root crackme && chmod 755 crackme

COPY platform/common/flagd.py /opt/flagd.py
COPY services/re-crackme/entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

ARG INITIAL_FLAG=FLAG{waiting_for_first_round}
ENV FLAG_PATH="/flag.txt"
ENV FLAGD_PORT="10000"
RUN echo "$INITIAL_FLAG" > /flag.txt && chown player:player /flag.txt && chmod 644 /flag.txt

EXPOSE 9997
# FLAGD_PORT (10000) is intentionally NOT exposed/published anywhere in
# docker-compose.yml: it must only be reachable from the checker's
# container on the internal Docker network.

USER player
CMD ["/entrypoint.sh"]
