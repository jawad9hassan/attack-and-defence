# Build context is the REPO ROOT (see docker-compose.yml: context ../..).

FROM ubuntu:22.04

RUN apt-get update && \
    apt-get install -y --no-install-recommends gcc libc6-dev python3 && \
    rm -rf /var/lib/apt/lists/*

RUN useradd -m -s /usr/sbin/nologin player
WORKDIR /service

COPY services/pwn-canary-bypass/src/server.c .
# -fstack-protector: the WHOLE POINT of this challenge is that a canary
# is present. -no-pie: fixed load address, so win()'s address (and the
# alignment-fixing ret gadget) stay constant and predictable for training.
# This binary is its OWN TCP server (it calls socket/bind/listen/accept
# itself) -- unlike the other pwn/* services it is NOT run under socat,
# because socat's EXEC:...,fork re-execs a brand-new process per
# connection, which would re-randomize the canary every time and defeat
# the entire challenge. This binary forks internally instead, so every
# connection's child shares the one canary the parent picked at startup.
RUN gcc -m64 -fstack-protector -no-pie -O0 -o server server.c && \
    chown root:root server && chmod 755 server

COPY platform/common/flagd.py /opt/flagd.py
COPY services/pwn-canary-bypass/entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

ARG INITIAL_FLAG=FLAG{waiting_for_first_round}
ENV FLAG_PATH="/flag.txt"
ENV FLAGD_PORT="10000"
RUN echo "$INITIAL_FLAG" > /flag.txt && chown player:player /flag.txt && chmod 644 /flag.txt

EXPOSE 9992
# FLAGD_PORT (10000) is intentionally NOT exposed/published anywhere in
# docker-compose.yml: it must only be reachable from the checker's
# container on the internal Docker network.

USER player
CMD ["/entrypoint.sh"]
