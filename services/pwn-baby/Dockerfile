FROM ubuntu:22.04

RUN apt-get update && \
    apt-get install -y --no-install-recommends gcc socat && \
    rm -rf /var/lib/apt/lists/*

RUN useradd -m -s /usr/sbin/nologin player
WORKDIR /service

COPY src/vuln.c .
# Same flags we used locally: no stack canary, fixed load address (no PIE),
# so the win() address stays constant and predictable for training.
RUN gcc -m64 -fno-stack-protector -no-pie -z execstack -o vuln vuln.c && \
    chown root:root vuln && chmod 755 vuln

ARG FLAG=FLAG{b4by_st4ck_0v3rfl0w_g0tcha}
RUN echo "$FLAG" > /flag.txt && chmod 644 /flag.txt

EXPOSE 9999
USER player
CMD ["socat", "-T30", "TCP-LISTEN:9999,reuseaddr,fork", "EXEC:/service/vuln,pty,stderr"]
