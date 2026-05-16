FROM python:3.13-slim

WORKDIR /app

ENV PYTHONUNBUFFERED=1

RUN pip install --no-cache-dir dnslib

COPY . .

CMD ["python", "poison.py"]