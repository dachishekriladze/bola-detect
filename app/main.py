from contextlib import asynccontextmanager

from fastapi import FastAPI
from sqlalchemy import text

import models  # noqa: F401  (registers the tables)
from db import Base, engine
from seed import seed


@asynccontextmanager
async def lifespan(app: FastAPI):
    Base.metadata.create_all(engine)
    seed()
    yield


app = FastAPI(title="bola-detect target app (intentionally vulnerable)", lifespan=lifespan)


@app.get("/health")
def health():
    with engine.connect() as conn:
        conn.execute(text("SELECT 1"))
    return {"status": "ok"}