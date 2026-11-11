# Build context is the REPO ROOT.
FROM python:3.11-slim

WORKDIR /app
COPY platform/checker/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY platform/checker/ .
COPY config/game.yml /config/game.yml

ENV GAME_CONFIG="/config/game.yml"

CMD ["python3", "engine.py"]
