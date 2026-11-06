import time
import uuid
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from sqlalchemy import text

import models  # noqa: F401  (registers the tables)
from db import Base, engine
from request_log import event_time, parse_object, user_id_from_header, write_event
from routes import router
from seed import seed


@asynccontextmanager
async def lifespan(app: FastAPI):
    Base.metadata.create_all(engine)
    seed()
    yield


app = FastAPI(title="bola-detect target app (intentionally vulnerable)", lifespan=lifespan)
app.include_router(router)


@app.middleware("http")
async def log_requests(request: Request, call_next):
    request_id = request.headers.get("x-request-id") or str(uuid.uuid4())
    start = time.perf_counter()
    status_code = 500
    try:
        response = await call_next(request)
        status_code = response.status_code
        response.headers["X-Request-ID"] = request_id
        return response
    finally:
        object_type, object_id = parse_object(request.url.path)
        client_ip = request.client.host if request.client else None
        write_event({
            "timestamp": event_time(request.headers.get("x-sim-time")),
            "request_id": request_id,
            "user_id": user_id_from_header(request.headers.get("authorization")),
            "method": request.method,
            "path": request.url.path,
            "object_type": object_type,
            "object_id": object_id,
            "status_code": status_code,
            "source_ip": request.headers.get("x-lab-source-ip") or client_ip,
            "duration_ms": round((time.perf_counter() - start) * 1000, 1),
        })


@app.get("/health")
def health():
    with engine.connect() as conn:
        conn.execute(text("SELECT 1"))
    return {"status": "ok"}