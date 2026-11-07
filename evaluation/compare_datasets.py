"""Check that SPEEDUP does not change the simulated behavior.
Usage: python evaluation\\compare_datasets.py <app_a.jsonl> <app_b.jsonl>
"""
import json
import sys
from collections import Counter, defaultdict
from datetime import datetime


def load(path):
    with open(path, encoding="utf-8") as f:
        events = [json.loads(line) for line in f]
    for e in events:
        e["t"] = datetime.fromisoformat(e["timestamp"])
    events.sort(key=lambda e: e["t"])
    return events


def summarize(path):
    events = load(path)
    hours = (events[-1]["t"] - events[0]["t"]).total_seconds() / 3600
    by_user = defaultdict(list)
    for e in events:
        if e["user_id"] is not None:
            by_user[e["user_id"]].append(e["t"])
    gaps = []
    for times in by_user.values():
        gaps += [(b - a).total_seconds() for a, b in zip(times, times[1:])]
    gaps.sort()

    def q(p):
        return gaps[int(p * (len(gaps) - 1))]

    print(path)
    print(f"  simulated span: {hours:.1f} h, requests: {len(events)}, "
          f"per simulated hour: {len(events) / hours:.0f}")
    print(f"  gap between a user's consecutive requests (sim seconds): "
          f"p25={q(0.25):.1f} p50={q(0.5):.1f} p75={q(0.75):.1f} p95={q(0.95):.0f}")
    print(f"  methods: {dict(Counter(e['method'] for e in events))}")
    print(f"  statuses: {dict(sorted(Counter(e['status_code'] for e in events).items()))}")


for p in sys.argv[1:3]:
    summarize(p)