# Build context is the REPO ROOT (see docker-compose.yml: context ../..).

FROM ubuntu:22.04

RUN apt-get update && \
    apt-get install -y --no-install-recommends gcc socat python3 && \
    rm -rf /var/lib/apt/lists/*

RUN useradd -m -s /usr/sbin/nologin player
WORKDIR /service

COPY services/pwn-baby/src/vuln.c .
# Same flags we used while developing locally: no stack canary, fixed
# load address (no PIE), so the win() address stays constant and
# predictable for training.
RUN gcc -m64 -fno-stack-protector -no-pie -z execstack -o vuln vuln.c && \
    chown root:root vuln && chmod 755 vuln

COPY platform/common/flagd.py /opt/flagd.py
COPY services/pwn-baby/entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

ARG INITIAL_FLAG=FLAG{waiting_for_first_round}
ENV FLAG_PATH="/flag.txt"
ENV FLAGD_PORT="10000"
# Pre-create the flag file owned by the unprivileged `player` user, so the
# service (and flagd) can run as a normal user for its whole life and never
# need root — writing to an EXISTING file only needs file permissions, not
# directory permissions, so this still works at runtime.
RUN echo "$INITIAL_FLAG" > /flag.txt && chown player:player /flag.txt && chmod 644 /flag.txt

EXPOSE 9999
# FLAGD_PORT (10000) is intentionally NOT exposed/published anywhere in
# docker-compose.yml: it must only be reachable from the checker's
# container on the internal Docker network.

USER player
CMD ["/entrypoint.sh"]
