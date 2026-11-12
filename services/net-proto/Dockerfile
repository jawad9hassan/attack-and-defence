# Build context is the REPO ROOT.
FROM python:3.11-slim

RUN apt-get update && \
    apt-get install -y --no-install-recommends iputils-ping && \
    rm -rf /var/lib/apt/lists/*

RUN useradd -m -s /usr/sbin/nologin player
WORKDIR /service

COPY services/net-proto/src/diag.py .
COPY platform/common/flagd.py /opt/flagd.py
COPY services/net-proto/entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

ENV FLAG_PATH="/flag.txt"
ENV FLAGD_PORT="10000"
ENV DIAG_PORT="9200"

ARG INITIAL_FLAG=FLAG{waiting_for_first_round}
RUN echo "$INITIAL_FLAG" > /flag.txt && chown player:player /flag.txt && chmod 644 /flag.txt

EXPOSE 9200
# FLAGD_PORT (10000) is intentionally NOT exposed/published anywhere.

USER player
CMD ["/entrypoint.sh"]
