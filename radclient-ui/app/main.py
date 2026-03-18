import logging
import os
import re
import socket
import subprocess

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
    return templates.TemplateResponse("index.html", {"request": request})


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
