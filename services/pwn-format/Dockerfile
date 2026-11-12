# Build context is the REPO ROOT (see docker-compose.yml: context ../..).

FROM ubuntu:22.04

RUN apt-get update && \
    apt-get install -y --no-install-recommends gcc socat python3 && \
    rm -rf /var/lib/apt/lists/*

RUN useradd -m -s /usr/sbin/nologin player
WORKDIR /service

COPY services/pwn-format/src/vuln.c .
# Same flags as pwn-baby: no stack canary, fixed load address (no PIE) so
# the `unlocked` global's address stays constant and discoverable via
# `nm`/`objdump -t`, exactly like win()'s address in pwn-baby.
RUN gcc -m64 -fno-stack-protector -no-pie -o vuln vuln.c && \
    chown root:root vuln && chmod 755 vuln

COPY platform/common/flagd.py /opt/flagd.py
COPY services/pwn-format/entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

ARG INITIAL_FLAG=FLAG{waiting_for_first_round}
ENV FLAG_PATH="/flag.txt"
ENV FLAGD_PORT="10000"
RUN echo "$INITIAL_FLAG" > /flag.txt && chown player:player /flag.txt && chmod 644 /flag.txt

EXPOSE 9998
# FLAGD_PORT (10000) is intentionally NOT exposed/published anywhere in
# docker-compose.yml: it must only be reachable from the checker's
# container on the internal Docker network.

USER player
CMD ["/entrypoint.sh"]
