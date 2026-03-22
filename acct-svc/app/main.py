import orjson
from fastapi import FastAPI, Request
from fastapi.responses import Response

app = FastAPI(title="acct-svc", docs_url=None, redoc_url=None, openapi_url=None)

_RESP_POST_AUTH = orjson.dumps({"Reply-Message": "Post-auth logged"})
_RESP_ACCOUNTING = orjson.dumps({"Reply-Message": "Accounting logged"})
_JSON_CT = "application/json"


@app.get("/health")
async def health():
    return Response(b'{"status":"ok"}', media_type=_JSON_CT)


@app.post("/post-auth")
async def post_auth(request: Request) -> Response:
    await request.body()  # drain the body without parsing
    return Response(_RESP_POST_AUTH, media_type=_JSON_CT)


@app.post("/accounting")
async def accounting(request: Request) -> Response:
    await request.body()
    return Response(_RESP_ACCOUNTING, media_type=_JSON_CT)
