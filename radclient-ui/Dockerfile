FROM python:3.12-slim

RUN apt-get update && \
    apt-get install -y --no-install-recommends freeradius-utils wget && \
    wget -q https://networkradius.com/assets/packages/radperf/radperf_2.0.1_amd64.deb && \
    dpkg -i radperf_2.0.1_amd64.deb || apt-get install -y -f --no-install-recommends && \
    rm -f radperf_2.0.1_amd64.deb && \
    rm -rf /var/lib/apt/lists/* && \
    echo 'hosts: files dns' > /etc/nsswitch.conf

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app/ app/

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000", "--reload", "--reload-dir", "/app/app"]
