from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse, Response

app = FastAPI(title="acct-svc", docs_url=None, redoc_url=None, openapi_url=None)


@app.get("/health")
async def health():
    return Response(content=b"ok", media_type="text/plain")


@app.post("/post-auth")
async def post_auth(request: Request) -> JSONResponse:
    await request.body()
    return JSONResponse({"Reply-Message": "Post-auth logged"})


@app.post("/accounting")
async def accounting(request: Request) -> JSONResponse:
    await request.body()
    return JSONResponse({"Reply-Message": "Accounting logged"})
