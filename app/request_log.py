import json
import os
import re
import threading
from datetime import datetime, timezone

from security import decode_token

LOG_PATH = os.environ.get("REQUEST_LOG_PATH", "/logs/app.jsonl")
os.makedirs(os.path.dirname(LOG_PATH), exist_ok=True)
_lock = threading.Lock()

OBJECT_PATH = re.compile(r"^/(invoices|orders|documents)(?:/([^/]+))?$")
SINGULAR = {"invoices": "invoice", "orders": "order", "documents": "document"}


def parse_object(path: str):
    match = OBJECT_PATH.match(path)
    if not match:
        return None, None
    return SINGULAR[match.group(1)], match.group(2)


def user_id_from_header(auth_header: str | None):
    if not auth_header or not auth_header.lower().startswith("bearer "):
        return None
    return decode_token(auth_header[7:].strip())


def event_time(sim_header: str | None) -> str:
    if sim_header:
        try:
            return datetime.fromisoformat(sim_header.replace("Z", "+00:00")).isoformat()
        except ValueError:
            pass
    return datetime.now(timezone.utc).isoformat()


def write_event(event: dict) -> None:
    line = json.dumps(event, separators=(",", ":"))
    with _lock:
        with open(LOG_PATH, "a", encoding="utf-8") as f:
            f.write(line + "\n")