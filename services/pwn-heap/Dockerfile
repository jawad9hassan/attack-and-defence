# Build context is the REPO ROOT (see docker-compose.yml: context ../..).

FROM ubuntu:22.04

RUN apt-get update && \
    apt-get install -y --no-install-recommends gcc libc6-dev socat python3 && \
    rm -rf /var/lib/apt/lists/*

RUN useradd -m -s /usr/sbin/nologin player
WORKDIR /service

COPY services/pwn-heap/src/notes.c .
# -no-pie: fixed load address, so win()'s address stays constant and
# predictable for training. Stack protector stays at its default (this
# is a HEAP bug, not a stack one) -- nothing here needs shellcode or a
# stack-alignment gadget, since the hijack is a normal C function call
# through a corrupted function pointer, not a hand-crafted return.
RUN gcc -m64 -no-pie -O0 -o notes notes.c && \
    chown root:root notes && chmod 755 notes

COPY platform/common/flagd.py /opt/flagd.py
COPY services/pwn-heap/entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

ARG INITIAL_FLAG=FLAG{waiting_for_first_round}
ENV FLAG_PATH="/flag.txt"
ENV FLAGD_PORT="10000"
RUN echo "$INITIAL_FLAG" > /flag.txt && chown player:player /flag.txt && chmod 644 /flag.txt

EXPOSE 9991
# FLAGD_PORT (10000) is intentionally NOT exposed/published anywhere in
# docker-compose.yml: it must only be reachable from the checker's
# container on the internal Docker network.

USER player
CMD ["/entrypoint.sh"]
