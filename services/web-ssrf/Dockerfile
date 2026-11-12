# Build context is the REPO ROOT (see docker-compose.yml: context ../..).
FROM python:3.11-slim

WORKDIR /app
COPY services/web-ssrf/app/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY services/web-ssrf/app/ .
COPY platform/common/flagd.py /opt/flagd.py
COPY services/web-ssrf/entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

ENV FLAG_PATH="/flag.txt"
ENV FLAGD_PORT="10000"
ENV INTERNAL_PORT="6677"

EXPOSE 5000
# Neither FLAGD_PORT (10000) nor INTERNAL_PORT (6677, bound to
# 127.0.0.1 only anyway) is exposed/published anywhere in
# docker-compose.yml.

CMD ["/entrypoint.sh"]
