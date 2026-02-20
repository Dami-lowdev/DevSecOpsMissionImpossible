# EXPERT Dockerfile (intentionally imperfect)
FROM python:3.11-slim

WORKDIR /app

RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates \
 && update-ca-certificates \
 && rm -rf /var/lib/apt/lists/*

# Still copies too much (students should add .dockerignore)
COPY . /app

RUN pip install --no-cache-dir -r web/requirements.txt && \
    pip install --no-cache-dir -r vault/requirements.txt

# Still runs as root (students should fix with USER)
EXPOSE 5000 7000

CMD ["python","web/app.py"]
