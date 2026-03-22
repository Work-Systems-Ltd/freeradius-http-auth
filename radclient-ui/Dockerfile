FROM python:3.12-slim

RUN apt-get update && \
    apt-get install -y --no-install-recommends freeradius-utils curl gnupg && \
    curl -fsSL https://packages.networkradius.com/pgp/packages%40networkradius.com \
      | gpg --dearmor > /etc/apt/trusted.gpg.d/networkradius.gpg && \
    echo "deb https://packages.networkradius.com/extras/debian/bookworm bookworm main" \
      > /etc/apt/sources.list.d/networkradius-extras.list && \
    apt-get update && \
    apt-get install -y --no-install-recommends radperf || true && \
    rm -rf /var/lib/apt/lists/* && \
    echo 'hosts: files dns' > /etc/nsswitch.conf

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app/ app/

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000", "--reload", "--reload-dir", "/app/app"]
