# Build context is the REPO ROOT (see docker-compose.yml: context ../..).
FROM python:3.11-slim

WORKDIR /app
COPY services/web-xss-stored/app/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY services/web-xss-stored/app/ .
COPY platform/common/flagd.py /opt/flagd.py
COPY services/web-xss-stored/entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

ENV FLAG_PATH="/flag.txt"
ENV FLAGD_PORT="10000"
ENV SELF_URL="http://127.0.0.1:5000"

EXPOSE 5000
# FLAGD_PORT (10000) is intentionally NOT exposed/published anywhere.

CMD ["/entrypoint.sh"]
