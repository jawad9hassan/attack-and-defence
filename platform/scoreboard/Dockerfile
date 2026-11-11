# Build context is the REPO ROOT.
FROM python:3.11-slim

WORKDIR /app
COPY platform/scoreboard/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY platform/scoreboard/ .

ENV DB_PATH="/data/scoreboard.db"

EXPOSE 8080
CMD ["python3", "app.py"]
