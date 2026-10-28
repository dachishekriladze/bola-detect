import os
from fastapi import FastAPI
from sqlalchemy import create_engine, text

engine = create_engine(os.environ["DATABASE_URL"])
app = FastAPI(title="bola-detect target app (intentionally vulnerable)")


@app.get("/health")
def health():
    with engine.connect() as conn:
        conn.execute(text("SELECT 1"))
    return {"status": "ok"}