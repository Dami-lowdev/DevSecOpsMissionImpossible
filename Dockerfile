# EXPERT Dockerfile (intentionally imperfect)
FROM python:3.11-slim

WORKDIR /app

RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates \
 && update-ca-certificates \
 && rm -rf /var/lib/apt/lists/*

# Securise grace au .dockerignore a la racine
COPY . /app

RUN pip install --no-cache-dir -r web/requirements.txt && \
    pip install --no-cache-dir -r vault/requirements.txt

# Creation d'un utilisateur non-root pour eviter privilege escalation (CWE-269)
RUN useradd -r -ms /bin/false appuser && chown -R appuser:appuser /app
USER appuser

EXPOSE 5000 7000

HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
  CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:5000/status')" || exit 1

CMD ["python","web/app.py"]
