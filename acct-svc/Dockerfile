FROM python:3.12-slim

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app/ app/

CMD ["gunicorn", "-k", "uvicorn.workers.UvicornWorker", "-w", "8", "--threads", "1", "--worker-connections", "1000", "--bind", "0.0.0.0:8002", "--access-logfile", "/dev/null", "app.main:app"]
