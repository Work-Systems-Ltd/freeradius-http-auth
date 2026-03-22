import hashlib
import json
from pathlib import Path
from typing import Any

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse, Response

app = FastAPI(title="auth-svc", docs_url=None, redoc_url=None, openapi_url=None)

USERS_FILE = Path("/app/data/users.json")
_users_cache: dict[str, Any] = json.loads(USERS_FILE.read_text())


def _extract_attr(body: dict, attr: str) -> str:
    val = body.get(attr, "")
    if isinstance(val, dict):
        values = val.get("value", [])
        return values[0] if values else ""
    return str(val)


@app.get("/health")
async def health():
    return Response(content=b"ok", media_type="text/plain")


@app.post("/authenticate")
async def authenticate(request: Request) -> JSONResponse:
    body = await request.json()
    username = _extract_attr(body, "User-Name")

    user = _users_cache.get(username)
    if user is None:
        return JSONResponse({"Reply-Message": "User not found"}, status_code=401)

    stored_password = user["password"]

    # CHAP authentication
    chap_password = _extract_attr(body, "CHAP-Password")
    if chap_password:
        chap_challenge = _extract_attr(body, "CHAP-Challenge")
        if not _verify_chap(chap_password, chap_challenge, stored_password):
            return JSONResponse({"Reply-Message": "CHAP authentication failed"}, status_code=401)
        return JSONResponse(user["attributes"])

    # PAP authentication
    user_password = _extract_attr(body, "User-Password")
    if user_password != stored_password:
        return JSONResponse({"Reply-Message": "Invalid password"}, status_code=401)

    return JSONResponse(user["attributes"])


def _verify_chap(chap_password_hex: str, chap_challenge_hex: str, stored_password: str) -> bool:
    try:
        chap_bytes = bytes.fromhex(chap_password_hex.replace("0x", ""))
        challenge_bytes = bytes.fromhex(chap_challenge_hex.replace("0x", ""))
        chap_id = chap_bytes[0:1]
        received_hash = chap_bytes[1:17]
        expected = hashlib.md5(chap_id + stored_password.encode() + challenge_bytes).digest()
        return received_hash == expected
    except Exception:
        return False
