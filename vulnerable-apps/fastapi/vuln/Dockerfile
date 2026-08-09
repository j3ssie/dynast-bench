FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

RUN apt-get update \
 && apt-get install -y --no-install-recommends curl \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt
COPY . .
RUN chmod +x /app/entrypoint.sh

EXPOSE 3000
HEALTHCHECK --interval=10s --timeout=5s --retries=30 --start-period=60s \
  CMD curl -sf http://localhost:3000/api/_verify/health || exit 1
CMD ["/app/entrypoint.sh"]
