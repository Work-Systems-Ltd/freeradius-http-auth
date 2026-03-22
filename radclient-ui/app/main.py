import logging
import os
import re
import socket
import subprocess
import threading
import time

from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

logger = logging.getLogger("radclient-ui")
logging.basicConfig(level=logging.INFO, format="%(asctime)s %(name)s %(levelname)s %(message)s")

app = FastAPI(title="radclient-ui")
app.mount("/static", StaticFiles(directory="/app/app/static"), name="static")
templates = Jinja2Templates(directory="/app/app/templates")

RADIUS_HOST = os.environ.get("RADIUS_HOST", "freeradius")
RADIUS_SECRET = os.environ.get("RADIUS_SECRET", "testing123")
LOADTEST_TARGETS = os.environ.get("LOADTEST_TARGETS", RADIUS_HOST)


def _resolve_radius_host() -> str:
    return socket.gethostbyname(RADIUS_HOST)


def _run_radclient(port: int, packet_type: str, attr_input: str) -> tuple[str, dict]:
    try:
        radius_ip = _resolve_radius_host()
        result = subprocess.run(
            ["radclient", "-x", f"{radius_ip}:{port}", packet_type, RADIUS_SECRET],
            input=attr_input,
            capture_output=True,
            text=True,
            timeout=10,
        )
        output = result.stdout + result.stderr
        logger.info("radclient exit code: %d", result.returncode)
        parsed = _parse_radclient_output(output)
    except subprocess.TimeoutExpired:
        output = "Error: radclient timed out"
        parsed = {"result": "Timeout", "attributes": {}}
    except Exception as e:
        output = f"Error: {e}"
        parsed = {"result": "Error", "attributes": {}}
    return output, parsed


@app.get("/", response_class=HTMLResponse)
async def index(request: Request) -> HTMLResponse:
    return templates.TemplateResponse("index.html", {
        "request": request,
        "default_targets": LOADTEST_TARGETS,
    })


@app.post("/api/auth")
async def api_auth(request: Request) -> JSONResponse:
    body = await request.json()
    username = body.get("username", "")
    password = body.get("password", "")
    auth_type = body.get("auth_type", "PAP")
    nas_ip = body.get("nas_ip", "127.0.0.1")
    nas_port = body.get("nas_port", "0")

    logger.info("Sending %s auth request for user=%s", auth_type, username)

    attrs = [
        f'User-Name = "{username}"',
        f'NAS-IP-Address = {nas_ip}',
        f'NAS-Port = {nas_port}',
    ]

    if auth_type == "CHAP":
        attrs.append(f'User-Password = "{password}"')
        attrs.append("Auth-Type = CHAP")
    else:
        attrs.append(f'User-Password = "{password}"')

    output, parsed = _run_radclient(1812, "auth", "\n".join(attrs))
    return JSONResponse({"raw": output, **parsed})


@app.post("/api/acct")
async def api_acct(request: Request) -> JSONResponse:
    body = await request.json()
    username = body.get("username", "")
    acct_status_type = body.get("acct_status_type", "Start")
    acct_session_id = body.get("acct_session_id", "")
    nas_ip = body.get("nas_ip", "127.0.0.1")
    nas_port = body.get("nas_port", "0")
    framed_ip = body.get("framed_ip", "")
    acct_session_time = body.get("acct_session_time", "0")
    acct_input_octets = body.get("acct_input_octets", "0")
    acct_output_octets = body.get("acct_output_octets", "0")

    logger.info("Sending accounting %s for user=%s", acct_status_type, username)

    attrs = [
        f'User-Name = "{username}"',
        f'Acct-Status-Type = {acct_status_type}',
        f'NAS-IP-Address = {nas_ip}',
        f'NAS-Port = {nas_port}',
    ]

    if acct_session_id:
        attrs.append(f'Acct-Session-Id = "{acct_session_id}"')
    if framed_ip:
        attrs.append(f'Framed-IP-Address = {framed_ip}')
    if acct_session_time and acct_session_time != "0":
        attrs.append(f'Acct-Session-Time = {acct_session_time}')
    if acct_input_octets and acct_input_octets != "0":
        attrs.append(f'Acct-Input-Octets = {acct_input_octets}')
    if acct_output_octets and acct_output_octets != "0":
        attrs.append(f'Acct-Output-Octets = {acct_output_octets}')

    output, parsed = _run_radclient(1813, "acct", "\n".join(attrs))
    return JSONResponse({"raw": output, **parsed})


def _parse_radclient_output(output: str) -> dict:
    result = "Unknown"
    attributes: dict[str, str] = {}

    if re.search(r"Received Access-Reject", output):
        result = "Access-Reject"
    elif re.search(r"Received Access-Accept", output):
        result = "Access-Accept"
    elif re.search(r"Received Accounting-Response", output):
        result = "Accounting-Response"
    elif "no response" in output.lower():
        result = "No Response"

    received = False
    for line in output.splitlines():
        if "Received" in line:
            received = True
            continue
        if received and line.startswith("Sent"):
            break
        if received:
            match = re.match(r"^\s+(\S[\w-]+)\s+=\s+(.+)$", line)
            if match:
                attr_name = match.group(1)
                attr_value = match.group(2).strip()
                if attr_name != "Message-Authenticator":
                    attributes[attr_name] = attr_value

    return {"result": result, "attributes": attributes}


# ---------------------------------------------------------------------------
# Load test manager — runs radclient in batch mode from a background thread
# ---------------------------------------------------------------------------

def _parse_radclient_batch(output: str, count: int) -> dict:
    accepted = output.count("Received Access-Accept")
    accepted += output.count("Received Accounting-Response")
    rejected = output.count("Received Access-Reject")
    lost = max(0, count - accepted - rejected)
    return {"sent": count, "accepted": accepted, "rejected": rejected, "lost": lost}


class LoadTestManager:
    def __init__(self):
        self.running = False
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self._lock = threading.Lock()
        self._procs: list[subprocess.Popen] = []
        self._stats = self._empty()

    def _empty(self):
        return {
            "state": "idle",
            "elapsed": 0.0,
            "sent": 0,
            "accepted": 0,
            "rejected": 0,
            "lost": 0,
            "rps": 0,
            "batch_rps": 0,
        }

    def start(self, targets: list[str], target_rps: int, batch_size: int):
        if self.running:
            self.stop()  # force-stop any stuck test
        self.running = True
        self._stop.clear()
        with self._lock:
            self._stats = self._empty()
            self._stats["state"] = "running"
        self._thread = threading.Thread(
            target=self._run, args=(targets, target_rps, batch_size), daemon=True
        )
        self._thread.start()
        return True

    def stop(self):
        self._stop.set()
        for p in list(self._procs):
            try:
                p.kill()
            except Exception:
                pass
        self._procs.clear()
        # Give the thread a moment to exit, then force cleanup
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=3)
        self.running = False
        with self._lock:
            self._stats["state"] = "idle"

    def status(self):
        with self._lock:
            return dict(self._stats)

    def _run(self, targets: list[str], target_rps: int, batch_size: int):
        t0 = time.monotonic()

        # Write request files
        auth_file = "/tmp/lt_auth.txt"
        acct_file = "/tmp/lt_acct.txt"
        with open(auth_file, "w") as f:
            f.write('User-Name = "subscriber1"\nUser-Password = "secret123"\n'
                    'NAS-IP-Address = 127.0.0.1\nNAS-Port = 0\n')
        with open(acct_file, "w") as f:
            f.write('User-Name = "subscriber1"\nAcct-Status-Type = Start\n'
                    'Acct-Session-Id = "loadtest"\nNAS-IP-Address = 127.0.0.1\n'
                    'NAS-Port = 0\n')

        # Calculate -p (concurrency) to achieve target RPS
        # RPS ≈ p / response_time. Auth takes ~15ms (2 HTTP calls), acct ~8ms.
        num_hosts = len(targets)
        auth_rps_per_host = max(1, int(target_rps * 0.7) // num_hosts)
        acct_rps_per_host = max(1, int(target_rps * 0.3) // num_hosts)
        auth_par = min(256, max(5, int(auth_rps_per_host * 0.015)))
        acct_par = min(256, max(3, int(acct_rps_per_host * 0.008)))
        # Auto-size batches to complete in ~3 seconds for responsive UI updates
        auth_batch = min(batch_size, max(50, auth_rps_per_host * 3))
        acct_batch = min(batch_size, max(50, acct_rps_per_host * 3))

        try:
            while not self._stop.is_set():
                batch_t0 = time.monotonic()
                results = []

                # Spawn one auth + one acct process PER host simultaneously
                threads = []
                for host in targets:
                    host = host.strip()
                    threads.append(threading.Thread(
                        target=lambda h, f, p, pt, c, par: results.append(
                            self._batch(f, h, p, pt, c, par)),
                        args=(host, auth_file, 1812, "auth", auth_batch, auth_par),
                    ))
                    threads.append(threading.Thread(
                        target=lambda h, f, p, pt, c, par: results.append(
                            self._batch(f, h, p, pt, c, par)),
                        args=(host, acct_file, 1813, "acct", acct_batch, acct_par),
                    ))

                for t in threads:
                    t.start()
                for t in threads:
                    t.join()

                if self._stop.is_set():
                    break

                batch_elapsed = time.monotonic() - batch_t0
                batch_sent = 0

                with self._lock:
                    for r in results:
                        self._stats["sent"] += r["sent"]
                        self._stats["accepted"] += r["accepted"]
                        self._stats["rejected"] += r["rejected"]
                        self._stats["lost"] += r["lost"]
                        batch_sent += r["sent"]
                    elapsed = time.monotonic() - t0
                    self._stats["elapsed"] = round(elapsed, 1)
                    self._stats["rps"] = round(self._stats["sent"] / elapsed) if elapsed > 0 else 0
                    self._stats["batch_rps"] = round(batch_sent / batch_elapsed) if batch_elapsed > 0 else 0
        finally:
            with self._lock:
                self._stats["state"] = "idle"
                self._stats["elapsed"] = round(time.monotonic() - t0, 1)
                if self._stats["elapsed"] > 0:
                    self._stats["rps"] = round(self._stats["sent"] / self._stats["elapsed"])
            self.running = False

    def _batch(self, request_file, host, port, ptype, count, parallel):
        try:
            host_ip = socket.gethostbyname(host)
            proc = subprocess.Popen(
                ["radclient", "-c", str(count), "-p", str(parallel),
                 "-r", "3", "-t", "3",
                 "-f", request_file,
                 f"{host_ip}:{port}", ptype, RADIUS_SECRET],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
            )
            self._procs.append(proc)
            try:
                stdout, stderr = proc.communicate(timeout=120)
            except subprocess.TimeoutExpired:
                proc.kill()
                stdout, stderr = proc.communicate()
            if proc in self._procs:
                self._procs.remove(proc)
            return _parse_radclient_batch(stdout + stderr, count)
        except Exception as e:
            logger.error("radclient batch error: %s", e)
            return {"sent": 0, "accepted": 0, "rejected": 0, "lost": 0}


_loadtest = LoadTestManager()


@app.post("/api/loadtest/start")
async def loadtest_start(request: Request) -> JSONResponse:
    body = await request.json()
    targets = [t.strip() for t in body.get("targets", LOADTEST_TARGETS).split(",") if t.strip()]
    target_rps = min(50000, max(10, int(body.get("target_rps", 5000))))
    batch_size = min(50000, max(100, int(body.get("batch_size", 5000))))
    ok = _loadtest.start(targets=targets, target_rps=target_rps, batch_size=batch_size)
    return JSONResponse({"started": ok})


@app.post("/api/loadtest/stop")
async def loadtest_stop() -> JSONResponse:
    _loadtest.stop()
    return JSONResponse({"stopped": True})


@app.get("/api/loadtest/status")
async def loadtest_status() -> JSONResponse:
    return JSONResponse(_loadtest.status())
