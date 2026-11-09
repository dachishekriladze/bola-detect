"""Run rule B1 on a dataset at several thresholds and show what its alerts hit.

Usage (from the repo root): python -m evaluation.run_detector datasets\\dev [window_seconds]
Tune on datasets\\dev only.
"""
import sys
from collections import Counter

from detector.behavioral import DistinctObjectsRule
from detector.engine import run_rules
from evaluation.dataset import load_dataset

folder = sys.argv[1]
window = int(sys.argv[2]) if len(sys.argv) > 2 else 60
thresholds = [5, 10, 15, 20, 30, 40]

ds = load_dataset(folder)
episodes = {}
for truth in ds.truth.values():
    if truth.episode:
        episodes.setdefault(truth.episode.rsplit("-", 1)[0], set()).add(truth.episode)
kinds = sorted(episodes)

print(f"{folder}, window {window}s")
print(f"{'thr':>4} {'alerts':>7} {'attack':>7}  "
      + "  ".join(f"{k:>11}" for k in kinds) + "  false alerts by scenario")
for threshold in thresholds:
    alerts = run_rules(ds.events, [DistinctObjectsRule(window, threshold)])
    dominant = Counter()
    detected = set()
    for alert in alerts:
        scenarios = Counter(ds.truth[r].scenario for r in alert.request_ids)
        dominant[scenarios.most_common(1)[0][0]] += 1
        detected.update(ds.truth[r].episode for r in alert.request_ids if ds.truth[r].episode)
    attack_alerts = sum(n for s, n in dominant.items() if s.startswith("attack_"))
    cols = "  ".join(f"{len(detected & episodes[k])}/{len(episodes[k])}".rjust(11) for k in kinds)
    false_alerts = {s: n for s, n in sorted(dominant.items()) if not s.startswith("attack_")}
    print(f"{threshold:>4} {len(alerts):>7} {attack_alerts:>7}  {cols}  {false_alerts}")