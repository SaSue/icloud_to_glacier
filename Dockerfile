
FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates tzdata \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

RUN pip install --no-cache-dir --upgrade pip
RUN pip install --no-cache-dir boto3 pyicloud botocore

COPY sync_icloud_to_s3.py /app/sync_icloud_to_s3.py
RUN chmod +x /app/sync_icloud_to_s3.py

ENV TZ=Europe/Berlin
VOLUME ["/state", "/cookies"]

CMD ["python", "/app/sync_icloud_to_s3.py"]
