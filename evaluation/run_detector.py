"""Evaluate rule configurations on a dataset (tune on datasets\\dev only).

Usage (from the repo root): python -m evaluation.run_detector datasets\\dev
"""
import sys

from detector.behavioral import ConsecutiveIdsRule, DistinctObjectsRule
from detector.engine import run_rules
from evaluation.dataset import load_dataset
from evaluation.metrics import KINDS, episodes_by_kind, score_alerts

CONFIGS = [
    ("B1 window 60s, thr 20", lambda: DistinctObjectsRule(60, 20)),
    ("B1 window 60s, thr 40", lambda: DistinctObjectsRule(60, 40)),
    ("B2 window 1h, run 10", lambda: ConsecutiveIdsRule(3600, 10)),
    ("B2 window 4h, run 10", lambda: ConsecutiveIdsRule(14400, 10)),
    ("B2 window 8h, run 10", lambda: ConsecutiveIdsRule(28800, 10)),
    ("B2 window 8h, run 5", lambda: ConsecutiveIdsRule(28800, 5)),
]

ds = load_dataset(sys.argv[1])
episodes = episodes_by_kind(ds.truth)
days = (ds.events[-1].timestamp - ds.events[0].timestamp).total_seconds() / 86400

print(f"{sys.argv[1]}: {len(ds.events)} events, {days:.1f} simulated days")
print(f"{'rule':<24} {'alerts':>6} {'prec':>5} {'false/day':>9}  "
      + "  ".join(f"{k:>10}" for k in KINDS) + "  false alerts by scenario")
for name, make_rule in CONFIGS:
    alerts = run_rules(ds.events, [make_rule()])
    score = score_alerts(alerts, ds.truth)
    precision = score["true_alerts"] / score["alerts"] if score["alerts"] else float("nan")
    false_alerts = score["alerts"] - score["true_alerts"]
    cols = "  ".join(
        f"{len(score['detected'] & episodes[k])}/{len(episodes[k])}".rjust(10) for k in KINDS)
    print(f"{name:<24} {score['alerts']:>6} {precision:>5.2f} {false_alerts / days:>9.1f}  "
          f"{cols}  {score['false_by_scenario']}")