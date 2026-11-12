# Build context is the REPO ROOT (see docker-compose.yml: context ../..).

FROM ubuntu:22.04

RUN apt-get update && \
    apt-get install -y --no-install-recommends gcc libc6-dev socat python3 binutils && \
    rm -rf /var/lib/apt/lists/*

RUN useradd -m -s /usr/sbin/nologin player
WORKDIR /service

COPY services/pwn-ret2libc/src/vuln.c services/pwn-ret2libc/src/gadgets.s ./
# -no-pie: the EXECUTABLE's own code (vulnerable(), the PLT stub for
# puts, the GOT, the provided pop_rdi_ret gadget) stays at fixed,
# predictable addresses -- same convenience as pwn-baby/pwn-heap.
# -fno-stack-protector: this challenge is about ret2libc, not the
# canary (already covered by pwn-canary-bypass).
# -fcf-protection=none: disables Intel CET indirect-branch tracking,
# which would otherwise reject landing on arbitrary ROP gadget
# addresses that aren't valid "endbr64" landing pads.
# libc itself is NOT specially built or pinned here -- it's the
# distro's normal, dynamically loaded libc, and its ASLR is NOT
# disabled. That's the one source of real randomness this challenge
# is about: the executable's addresses are fixed, but libc's base
# address changes every time the process starts.
RUN gcc -m64 -no-pie -fno-stack-protector -fcf-protection=none -O0 \
        -o vuln vuln.c gadgets.s && \
    chown root:root vuln && chmod 755 vuln

COPY platform/common/flagd.py /opt/flagd.py
COPY services/pwn-ret2libc/entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

ARG INITIAL_FLAG=FLAG{waiting_for_first_round}
ENV FLAG_PATH="/flag.txt"
ENV FLAGD_PORT="10000"
RUN echo "$INITIAL_FLAG" > /flag.txt && chown player:player /flag.txt && chmod 644 /flag.txt

EXPOSE 9990
# FLAGD_PORT (10000) is intentionally NOT exposed/published anywhere in
# docker-compose.yml: it must only be reachable from the checker's
# container on the internal Docker network.

USER player
CMD ["/entrypoint.sh"]
