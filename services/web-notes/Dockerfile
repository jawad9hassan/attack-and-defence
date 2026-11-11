FROM python:3.11-slim

WORKDIR /app
COPY app/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app/ .

# Flag and admin password are injected as environment variables so each
# "round" / instance can have a different one, just like in a real A/D game.
ENV FLAG="FLAG{sql1_1nj3ct10n_1s_f0rever}"
ENV ADMIN_PASSWORD="sup3rSecretAdminPW!"

EXPOSE 5000
CMD ["python", "app.py"]
