import logging
import os
import re
import socket
import subprocess

from fastapi import FastAPI, Form, Request
from fastapi.responses import HTMLResponse
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
    """Run radclient and return (raw_output, parsed_result)."""
    try:
        radius_ip = _resolve_radius_host()
        result = subprocess.run(
            [
                "radclient",
                "-x",
                f"{radius_ip}:{port}",
                packet_type,
                RADIUS_SECRET,
            ],
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


@app.post("/send", response_class=HTMLResponse)
async def send_auth(
    request: Request,
    username: str = Form(...),
    password: str = Form(...),
    auth_type: str = Form("PAP"),
    nas_ip: str = Form("127.0.0.1"),
    nas_port: str = Form("0"),
) -> HTMLResponse:
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

    return templates.TemplateResponse(
        "index.html",
        {
            "request": request,
            "output": output,
            "parsed": parsed,
            "username": username,
            "password": password,
            "auth_type": auth_type,
            "nas_ip": nas_ip,
            "nas_port": nas_port,
        },
    )


@app.post("/send-acct", response_class=HTMLResponse)
async def send_acct(
    request: Request,
    username: str = Form(...),
    acct_status_type: str = Form("Start"),
    acct_session_id: str = Form(""),
    nas_ip: str = Form("127.0.0.1"),
    nas_port: str = Form("0"),
    framed_ip: str = Form(""),
    acct_session_time: str = Form("0"),
    acct_input_octets: str = Form("0"),
    acct_output_octets: str = Form("0"),
) -> HTMLResponse:
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

    return templates.TemplateResponse(
        "index.html",
        {
            "request": request,
            "acct_output": output,
            "acct_parsed": parsed,
            "acct_username": username,
            "acct_status_type": acct_status_type,
            "acct_session_id": acct_session_id,
            "nas_ip": nas_ip,
            "nas_port": nas_port,
            "framed_ip": framed_ip,
            "acct_session_time": acct_session_time,
            "acct_input_octets": acct_input_octets,
            "acct_output_octets": acct_output_octets,
        },
    )


def _parse_radclient_output(output: str) -> dict:
    """Parse radclient -x output to extract result and attributes."""
    result = "Unknown"
    attributes: dict[str, str] = {}

    if "Access-Accept" in output:
        result = "Access-Accept"
    elif "Access-Reject" in output:
        result = "Access-Reject"
    elif "Accounting-Response" in output:
        result = "Accounting-Response"
    elif "no response" in output.lower():
        result = "No Response"

    for match in re.finditer(r"^\s+(\S[\w-]+)\s+=\s+(.+)$", output, re.MULTILINE):
        attr_name = match.group(1)
        attr_value = match.group(2).strip()
        if attr_name not in ("User-Name", "User-Password", "NAS-IP-Address", "NAS-Port"):
            attributes[attr_name] = attr_value

    return {"result": result, "attributes": attributes}
