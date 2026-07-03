FROM python:3.12-slim
WORKDIR /app
COPY app.py index.html ./
RUN apt-get update \
    && apt-get install -y --no-install-recommends curl openssl \
    && rm -rf /var/lib/apt/lists/*
CMD ["python", "app.py"]
