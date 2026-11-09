"""Load a dataset: logs + labels + ownership.

Detectors may only see LogEvent. Ground truth (Truth) is kept separate, so a detector
cannot read labels by accident.

Usage (from the repo root): python -m evaluation.dataset datasets\\dev
"""
import csv
import json
import sys
from collections import Counter
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

from detector.models import LogEvent

KIND = {"invoice": "invoices", "order": "orders", "document": "documents"}


@dataclass(frozen=True)
class Truth:
    """Ground truth. Never given to a detector."""
    label: str          # "normal" or "attack"
    scenario: str
    episode: str        # empty for normal traffic
    unauthorized: bool  # requester is neither owner nor admin of an existing object


@dataclass
class Dataset:
    events: list
    truth: dict
    ownership: dict
    skipped_without_label: int


def load_dataset(folder) -> Dataset:
    folder = Path(folder)
    ownership = json.loads((folder / "ownership.json").read_text(encoding="utf-8"))
    roles = {u["id"]: u["role"] for u in ownership["users"].values()}

    labels = {}
    with open(folder / "labels.csv", newline="", encoding="utf-8") as f:
        for row in csv.DictReader(f):
            labels[row["request_id"]] = row

    events, truth, skipped = [], {}, 0
    with open(folder / "app.jsonl", encoding="utf-8") as f:
        for line in f:
            raw = json.loads(line)
            row = labels.get(raw["request_id"])
            if row is None:
                skipped += 1
                continue
            event = LogEvent(
                request_id=raw["request_id"],
                timestamp=datetime.fromisoformat(raw["timestamp"]),
                user_id=raw["user_id"],
                method=raw["method"],
                path=raw["path"],
                object_type=raw["object_type"],
                object_id=raw["object_id"],
                status_code=raw["status_code"],
                source_ip=raw["source_ip"],
            )
            owner = None
            if event.object_type and event.object_id:
                owner = ownership[KIND[event.object_type]].get(event.object_id)
            unauthorized = (
                owner is not None
                and event.user_id is not None
                and event.user_id != owner
                and roles.get(event.user_id) != "admin"
            )
            events.append(event)
            truth[event.request_id] = Truth(row["label"], row["scenario"],
                                            row["episode"], unauthorized)
    events.sort(key=lambda e: e.timestamp)
    return Dataset(events, truth, ownership, skipped)


if __name__ == "__main__":
    ds = load_dataset(sys.argv[1])
    t = ds.truth
    attack = [e for e in ds.events if t[e.request_id].label == "attack"]
    unauth = [e for e in ds.events if t[e.request_id].unauthorized]
    confirmed = [e for e in unauth if e.succeeded]
    own_objects = [e for e in attack if not t[e.request_id].unauthorized]
    missed_label = [e for e in unauth if t[e.request_id].label != "attack"]
    print(f"events: {len(ds.events)} (log lines without a label, skipped: {ds.skipped_without_label})")
    print(f"attack requests: {len(attack)}")
    print(f"unauthorized-target requests: {len(unauth)} (confirmed, 2xx: {len(confirmed)})")
    print(f"attack requests on the attacker's own objects (not violations): {len(own_objects)}")
    print(f"unauthorized requests NOT labeled attack (must be 0): {len(missed_label)}")
    print("unauthorized by scenario:", dict(Counter(t[e.request_id].scenario for e in unauth)))