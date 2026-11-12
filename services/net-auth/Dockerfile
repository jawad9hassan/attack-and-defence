# Build context is the REPO ROOT.
FROM python:3.11-slim

RUN useradd -m -s /usr/sbin/nologin player
WORKDIR /service

COPY services/net-auth/src/console.py .
COPY platform/common/flagd.py /opt/flagd.py
COPY services/net-auth/entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

ENV FLAG_PATH="/flag.txt"
ENV FLAGD_PORT="10000"
ENV CONSOLE_PORT="9400"

ARG INITIAL_FLAG=FLAG{waiting_for_first_round}
RUN echo "$INITIAL_FLAG" > /flag.txt && chown player:player /flag.txt && chmod 644 /flag.txt

EXPOSE 9400
# FLAGD_PORT (10000) is intentionally NOT exposed/published anywhere.

USER player
CMD ["/entrypoint.sh"]
