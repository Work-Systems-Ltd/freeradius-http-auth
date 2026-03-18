import hashlib
import json
import logging
from pathlib import Path
from typing import Any

from fastapi import FastAPI, Request, Response
from fastapi.responses import JSONResponse

logger = logging.getLogger("auth-svc")
logging.basicConfig(level=logging.INFO, format="%(asctime)s %(name)s %(levelname)s %(message)s")

app = FastAPI(title="auth-svc")

USERS_FILE = Path("/app/data/users.json")


def load_users() -> dict[str, Any]:
    return json.loads(USERS_FILE.read_text())


def _extract_attr(body: dict, attr: str) -> str:
    """Extract attribute value from rlm_rest JSON body.

    rlm_rest sends attributes as either plain values or structured objects:
      {"User-Name": {"value": ["subscriber1"], "op": ":="}}
    This helper handles both formats.
    """
    val = body.get(attr, "")
    if isinstance(val, dict):
        values = val.get("value", [])
        return values[0] if values else ""
    return str(val)


@app.post("/authorize")
async def authorize(request: Request) -> JSONResponse:
    body = await request.json()
    username = _extract_attr(body, "User-Name")
    logger.info("authorize request for user=%s body=%s", username, body)

    users = load_users()
    user = users.get(username)

    if user is None:
        logger.warning("authorize: user %s not found", username)
        return JSONResponse({"Reply-Message": "User not found"}, status_code=404)

    reply: dict[str, Any] = {}
    for attr, value in user["attributes"].items():
        reply[attr] = value

    logger.info("authorize: user %s found, returning %d attributes", username, len(reply))
    return JSONResponse(reply)


@app.post("/authenticate")
async def authenticate(request: Request) -> JSONResponse:
    body = await request.json()
    username = _extract_attr(body, "User-Name")
    user_password = _extract_attr(body, "User-Password")
    chap_password = _extract_attr(body, "CHAP-Password")
    chap_challenge = _extract_attr(body, "CHAP-Challenge")

    logger.info("authenticate request for user=%s chap=%s", username, bool(chap_password))

    users = load_users()
    user = users.get(username)

    if user is None:
        logger.warning("authenticate: user %s not found", username)
        return JSONResponse({"Reply-Message": "User not found"}, status_code=401)

    stored_password = user["password"]

    # CHAP authentication
    if chap_password:
        if not _verify_chap(chap_password, chap_challenge, stored_password):
            logger.warning("authenticate: CHAP failed for user %s", username)
            return JSONResponse({"Reply-Message": "CHAP authentication failed"}, status_code=401)
        logger.info("authenticate: CHAP success for user %s", username)
        return Response(status_code=204)

    # PAP authentication
    if user_password != stored_password:
        logger.warning("authenticate: PAP failed for user %s", username)
        return JSONResponse({"Reply-Message": "Invalid password"}, status_code=401)

    logger.info("authenticate: PAP success for user %s", username)
    return Response(status_code=204)


def _verify_chap(chap_password_hex: str, chap_challenge_hex: str, stored_password: str) -> bool:
    """Verify CHAP-Password against stored password and CHAP-Challenge.

    CHAP-Password is: 1 byte CHAP ID + 16 bytes MD5 hash
    MD5 hash = MD5(CHAP_ID + password + CHAP_Challenge)
    """
    try:
        chap_bytes = bytes.fromhex(chap_password_hex.replace("0x", ""))
        challenge_bytes = bytes.fromhex(chap_challenge_hex.replace("0x", ""))

        chap_id = chap_bytes[0:1]
        received_hash = chap_bytes[1:17]

        expected = hashlib.md5(
            chap_id + stored_password.encode() + challenge_bytes
        ).digest()

        return received_hash == expected
    except Exception:
        logger.exception("CHAP verification error")
        return False
