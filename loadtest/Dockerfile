FROM python:3.12-slim

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY dictionary .
COPY locustfile.py .

CMD ["locust", "-f", "locustfile.py"]
