# Build context is the REPO ROOT (see docker-compose.yml: context ../..),
# so every COPY path below is relative to the repository root, not this
# file's own directory. This lets the service share platform/common/
# without duplicating it into every service folder.

FROM python:3.11-slim

WORKDIR /app
COPY services/web-sqli-union/app/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY services/web-sqli-union/app/ .
COPY platform/common/flagd.py /opt/flagd.py
COPY services/web-sqli-union/entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

ENV FLAG_PATH="/flag.txt"
ENV FLAGD_PORT="10000"
# FLAGD_SECRET is set per-deployment via docker-compose / .env, never baked
# into the image, since it's what lets the checker control this service.

EXPOSE 5000
# FLAGD_PORT (10000) is intentionally NOT exposed/published anywhere in
# docker-compose.yml: it must only be reachable from the checker's
# container on the internal Docker network.

CMD ["/entrypoint.sh"]
