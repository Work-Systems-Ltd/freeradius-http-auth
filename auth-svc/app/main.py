import hashlib
import json
import logging
from pathlib import Path
from typing import Any

import orjson
from fastapi import FastAPI, Request
from fastapi.responses import Response

logger = logging.getLogger("auth-svc")
logging.basicConfig(level=logging.WARNING, format="%(asctime)s %(name)s %(levelname)s %(message)s")

app = FastAPI(title="auth-svc", docs_url=None, redoc_url=None, openapi_url=None)

USERS_FILE = Path("/app/data/users.json")
_users_cache: dict[str, Any] = json.loads(USERS_FILE.read_text())

# Pre-serialize all user attribute responses at startup
_response_cache: dict[str, bytes] = {
    username: orjson.dumps(user["attributes"])
    for username, user in _users_cache.items()
}

_REJECT_USER_NOT_FOUND = orjson.dumps({"Reply-Message": "User not found"})
_REJECT_CHAP_FAILED = orjson.dumps({"Reply-Message": "CHAP authentication failed"})
_REJECT_INVALID_PASS = orjson.dumps({"Reply-Message": "Invalid password"})
_JSON_CT = "application/json"


def _extract_attr(body: dict, attr: str) -> str:
    val = body.get(attr, "")
    if isinstance(val, dict):
        values = val.get("value", [])
        return values[0] if values else ""
    return str(val)


@app.get("/health")
async def health():
    return Response(b'{"status":"ok"}', media_type=_JSON_CT)


@app.post("/authenticate")
async def authenticate(request: Request) -> Response:
    body = orjson.loads(await request.body())
    username = _extract_attr(body, "User-Name")

    user = _users_cache.get(username)
    if user is None:
        return Response(_REJECT_USER_NOT_FOUND, status_code=401, media_type=_JSON_CT)

    stored_password = user["password"]

    # CHAP authentication
    chap_password = _extract_attr(body, "CHAP-Password")
    if chap_password:
        chap_challenge = _extract_attr(body, "CHAP-Challenge")
        if not _verify_chap(chap_password, chap_challenge, stored_password):
            return Response(_REJECT_CHAP_FAILED, status_code=401, media_type=_JSON_CT)
        return Response(_response_cache[username], media_type=_JSON_CT)

    # PAP authentication
    user_password = _extract_attr(body, "User-Password")
    if user_password != stored_password:
        return Response(_REJECT_INVALID_PASS, status_code=401, media_type=_JSON_CT)

    return Response(_response_cache[username], media_type=_JSON_CT)


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
