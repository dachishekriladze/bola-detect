import sys
from collections import defaultdict

from detector.behavioral import FirstAccessRule
from detector.engine import run_rules
from evaluation.dataset import load_dataset
from evaluation.metrics import score_alerts

N = 5
ds = load_dataset(sys.argv[1])
alerts = run_rules(ds.events, [FirstAccessRule(3600, N)])
detected = score_alerts(alerts, ds.truth)["detected"]

seen = defaultdict(set)
new_in_episode = defaultdict(int)
start = {}
for event in ds.events:
    truth = ds.truth[event.request_id]
    if truth.episode:
        start.setdefault(truth.episode, event.timestamp)
    if event.user_id is None or event.object_id is None or not event.succeeded:
        continue
    obj = (event.object_type, event.object_id)
    if obj not in seen[event.user_id]:
        seen[event.user_id].add(obj)
        if truth.episode:
            new_in_episode[truth.episode] += 1

t0 = ds.events[0].timestamp
print(f"B3 with N={N}; first-time = first successful access by that user")
for kind in ("sequential", "slow", "uuid", "write"):
    episodes = [e for e in start
                if e.startswith(kind + "-") and (start[e] - t0).total_seconds() >= 86400]
    enough = [e for e in episodes if new_in_episode[e] >= N]
    print(f"{kind:<11} eligible {len(episodes):>2} | >= {N} first-time objects: {len(enough):>2} "
          f"(detected {len(set(enough) & detected):>2}) | fewer: {len(episodes) - len(enough):>2} "
          f"(detected {len((set(episodes) - set(enough)) & detected):>2})")