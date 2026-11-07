import csv
import json
import sys
from collections import Counter

log_path, labels_path = sys.argv[1], sys.argv[2]

events = {}
log_ids = Counter()
with open(log_path, encoding="utf-8") as f:
    for line in f:
        event = json.loads(line)
        log_ids[event["request_id"]] += 1
        events[event["request_id"]] = event

with open(labels_path, newline="", encoding="utf-8") as f:
    rows = list(csv.DictReader(f))
label_ids = Counter(r["request_id"] for r in rows)

print(f"log events: {sum(log_ids.values())}, label rows: {len(rows)}")
print(f"duplicate label ids:    {sum(1 for c in label_ids.values() if c > 1)}")
print(f"labels without a log line: {len(set(label_ids) - set(log_ids))}")
print(f"log lines without a label: {len(set(log_ids) - set(label_ids))}")
print("scenarios:", dict(Counter(r["scenario"] for r in rows)))
for r in (r for r in rows if r["request_id"] not in log_ids):
    print("orphan label:", r["scenario"], r["actor"], r["sim_time"])
print("label time range:", min(r["sim_time"] for r in rows), "->", max(r["sim_time"] for r in rows))

episodes = {}
for r in rows:
    if r.get("episode") and r["request_id"] in events:
        episodes.setdefault(r["episode"], []).append(events[r["request_id"]])
print(f"attack episodes: {len(episodes)}")
for name, evs in sorted(episodes.items()):
    evs.sort(key=lambda e: e["timestamp"])
    print(f"  {name}: {len(evs)} requests, user {evs[0]['user_id']}, "
          f"{evs[0]['timestamp']} -> {evs[-1]['timestamp']}, "
          f"ids {evs[0]['object_id']}..{evs[-1]['object_id']}")