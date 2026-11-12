# Build context is the REPO ROOT (see docker-compose.yml: context ../..).
FROM python:3.11-slim

WORKDIR /app
COPY services/web-path-traversal/app/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY services/web-path-traversal/app/ .
COPY platform/common/flagd.py /opt/flagd.py
COPY services/web-path-traversal/entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

ENV FLAG_PATH="/flag.txt"
ENV FLAGD_PORT="10000"

EXPOSE 5000
# FLAGD_PORT (10000) is intentionally NOT exposed/published anywhere.

CMD ["/entrypoint.sh"]
