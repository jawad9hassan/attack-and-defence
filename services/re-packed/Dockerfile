# Build context is the REPO ROOT (see docker-compose.yml: context ../..).

FROM ubuntu:22.04

RUN apt-get update && \
    apt-get install -y --no-install-recommends gcc libc6-dev zlib1g-dev socat python3 && \
    rm -rf /var/lib/apt/lists/*

RUN useradd -m -s /usr/sbin/nologin player
WORKDIR /service

COPY services/re-packed/src/ .

# 1. Compile the real program.
# 2. Compress it into a C header the stub embeds (our dependency-free
#    stand-in for a real packer like UPX -- see stub.c's docstring).
# 3. Compile the stub, which decompresses+execs the real program at
#    runtime. Only the STUB is what players actually connect to.
RUN gcc -no-pie -o inner inner.c && \
    python3 make_payload.py inner packed_payload.h && \
    gcc -no-pie -I. -o vault_packed stub.c -lz && \
    chown root:root inner vault_packed && chmod 755 inner vault_packed

COPY platform/common/flagd.py /opt/flagd.py
COPY services/re-packed/entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

ARG INITIAL_FLAG=FLAG{waiting_for_first_round}
ENV FLAG_PATH="/flag.txt"
ENV FLAGD_PORT="10000"
RUN echo "$INITIAL_FLAG" > /flag.txt && chown player:player /flag.txt && chmod 644 /flag.txt

EXPOSE 9994
# FLAGD_PORT (10000) is intentionally NOT exposed/published anywhere in
# docker-compose.yml: it must only be reachable from the checker's
# container on the internal Docker network.

USER player
CMD ["/entrypoint.sh"]
