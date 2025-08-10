FROM python:3.11-slim

WORKDIR /app

COPY main.py .

RUN pip install dnslib requests

# DNS uses privileged port 53, so run container with --cap-add=NET_BIND_SERVICE
CMD ["python3", "main.py"]
