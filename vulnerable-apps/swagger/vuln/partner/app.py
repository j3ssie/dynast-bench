from fastapi import FastAPI, Request
from fastapi.responses import PlainTextResponse

app = FastAPI(title="internal partner api")


@app.get("/health")
async def health():
    return {"status": "ok", "service": "partner-api"}


@app.get("/internal/metadata", response_class=PlainTextResponse)
async def metadata():
    return "SWAGGER-PARTNER-INTERNAL metadata service=partner-api token=partner-internal-7a2"


@app.get("/profile", response_class=PlainTextResponse)
async def profile(email: str = "user1@bench.local", role: str = "user"):
    return f"email: {email}\nname: Partner Profile\nrole: {role}\n"
