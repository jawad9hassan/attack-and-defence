# Build context is the REPO ROOT (see docker-compose.yml: context ../..).

FROM ubuntu:22.04

RUN apt-get update && \
    apt-get install -y --no-install-recommends gcc libc6-dev socat python3 binutils && \
    rm -rf /var/lib/apt/lists/*

RUN useradd -m -s /usr/sbin/nologin player
WORKDIR /service

COPY services/pwn-rop-chain/src/vuln.c services/pwn-rop-chain/src/gadgets.s ./
# -no-pie: fixed, predictable addresses for vulnerable(), win(), the
# provided gadgets, and a spare ret instruction (needed to fix the
# stack-alignment issue documented in pwn-canary-bypass/pwn-ret2libc
# when jumping straight into win(), which itself calls libc's fopen/
# fgets/printf). -fno-stack-protector: this challenge is about
# multi-gadget ROP chain construction, not the canary. -fcf-
# protection=none: disables Intel CET so landing on arbitrary gadget
# addresses doesn't get rejected for lacking an endbr64 landing pad.
RUN gcc -m64 -no-pie -fno-stack-protector -fcf-protection=none -O0 \
        -o vuln vuln.c gadgets.s && \
    chown root:root vuln && chmod 755 vuln

COPY platform/common/flagd.py /opt/flagd.py
COPY services/pwn-rop-chain/entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

ARG INITIAL_FLAG=FLAG{waiting_for_first_round}
ENV FLAG_PATH="/flag.txt"
ENV FLAGD_PORT="10000"
RUN echo "$INITIAL_FLAG" > /flag.txt && chown player:player /flag.txt && chmod 644 /flag.txt

EXPOSE 9989
# FLAGD_PORT (10000) is intentionally NOT exposed/published anywhere in
# docker-compose.yml: it must only be reachable from the checker's
# container on the internal Docker network.

USER player
CMD ["/entrypoint.sh"]
