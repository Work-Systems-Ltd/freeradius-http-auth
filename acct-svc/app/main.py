import logging

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

logger = logging.getLogger("acct-svc")
logging.basicConfig(level=logging.WARNING, format="%(asctime)s %(name)s %(levelname)s %(message)s")

app = FastAPI(title="acct-svc")


def _extract_attr(body: dict, attr: str) -> str:
    """Extract attribute value from rlm_rest JSON body."""
    val = body.get(attr, "")
    if isinstance(val, dict):
        values = val.get("value", [])
        return values[0] if values else ""
    return str(val)


@app.post("/post-auth")
async def post_auth(request: Request) -> JSONResponse:
    body = await request.json()
    username = _extract_attr(body, "User-Name")
    packet_type = _extract_attr(body, "Packet-Type")

    logger.info(
        "post-auth: user=%s result=%s attributes=%s",
        username,
        packet_type,
        body,
    )
    return JSONResponse({"Reply-Message": "Post-auth logged"})


@app.post("/accounting")
async def accounting(request: Request) -> JSONResponse:
    body = await request.json()
    username = _extract_attr(body, "User-Name")
    status_type = _extract_attr(body, "Acct-Status-Type")
    session_id = _extract_attr(body, "Acct-Session-Id")

    logger.info(
        "accounting: user=%s status=%s session=%s attributes=%s",
        username,
        status_type,
        session_id,
        body,
    )
    return JSONResponse({"Reply-Message": "Accounting logged"})
