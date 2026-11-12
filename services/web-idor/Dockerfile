# Build context is the REPO ROOT (see docker-compose.yml: context ../..).

FROM python:3.11-slim

WORKDIR /app
COPY services/web-idor/app/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY services/web-idor/app/ .
COPY platform/common/flagd.py /opt/flagd.py
COPY services/web-idor/entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

ENV FLAG_PATH="/flag.txt"
ENV FLAGD_PORT="10000"
# FLAGD_SECRET is set per-deployment via docker-compose / .env.

EXPOSE 5000
# FLAGD_PORT (10000) is intentionally NOT exposed/published anywhere in
# docker-compose.yml: it must only be reachable from the checker.

CMD ["/entrypoint.sh"]
