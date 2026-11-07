import csv
import json
import sys
from collections import Counter
from datetime import datetime

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

attack_rows = sum(1 for r in rows if r["label"] == "attack")
print(f"attack requests: {attack_rows} of {len(rows)} ({100 * attack_rows / len(rows):.1f}%)")
print(f"attack episodes: {len(episodes)}")
by_type = {}
for name, evs in episodes.items():
    evs.sort(key=lambda e: e["timestamp"])
    kind = name.rsplit("-", 1)[0]
    span = (datetime.fromisoformat(evs[-1]["timestamp"])
            - datetime.fromisoformat(evs[0]["timestamp"])).total_seconds()
    by_type.setdefault(kind, []).append((len(evs), span))
for kind, items in sorted(by_type.items()):
    sizes = [n for n, _ in items]
    spans = [s for _, s in items]
    print(f"  {kind}: {len(items)} episodes, {min(sizes)}-{max(sizes)} requests, "
          f"span {min(spans):.0f}-{max(spans):.0f} s")