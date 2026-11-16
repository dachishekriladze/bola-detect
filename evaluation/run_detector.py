import sys
from datetime import timedelta

from detector.authorization import UnauthorizedAccessRule
from detector.behavioral import (ConsecutiveIdsRule, DistinctObjectsRule, FailedRequestsRule,
                                 FirstAccessRule, RequestRateRule)
from detector.engine import run_rules
from detector.policy import Policy
from evaluation.dataset import load_dataset
from evaluation.metrics import KINDS, episodes_by_kind, score_alerts

ds = load_dataset(sys.argv[1])
policy = Policy.from_ownership(ds.ownership)

CONFIGS = [

    ("B1 60s, thr 20", lambda: DistinctObjectsRule(60, 20), 0),
    ("B1 60s, thr 40", lambda: DistinctObjectsRule(60, 40), 0),
    ("B2 1h, run 10", lambda: ConsecutiveIdsRule(3600, 10), 0),
    ("B2 4h, run 10, quiet 30m", lambda: ConsecutiveIdsRule(14400, 10, 1800), 0),
    ("B2 8h, run 5", lambda: ConsecutiveIdsRule(28800, 5), 0),
    ("B3 1h, N=3", lambda: FirstAccessRule(3600, 3), 86400),
    ("B3 1h, N=5", lambda: FirstAccessRule(3600, 5), 86400),
    ("B3 1h, N=8", lambda: FirstAccessRule(3600, 8), 86400),
    ("B4 rate 60s, 10 req", lambda: RequestRateRule(60, 10), 0),
    ("B4 rate 60s, 30 req", lambda: RequestRateRule(60, 30), 0),
    ("B5 4xx 1h, N=3", lambda: FailedRequestsRule(3600, 3), 0),
    ("B5 4xx 1h, N=5", lambda: FailedRequestsRule(3600, 5), 0),
    ("A1 unauthorized access", lambda: UnauthorizedAccessRule(policy), 0),
    ("A1 per request", lambda: UnauthorizedAccessRule(policy, window_seconds=0, quiet_seconds=0), 0),
]

episodes = episodes_by_kind(ds.truth)
dataset_start = ds.events[0].timestamp
episode_start = {}
for event in ds.events:
    episode = ds.truth[event.request_id].episode
    if episode and episode not in episode_start:
        episode_start[episode] = event.timestamp
days = (ds.events[-1].timestamp - dataset_start).total_seconds() / 86400

print(f"{sys.argv[1]}: {len(ds.events)} events, {days:.1f} simulated days")
print("recall columns: detected / eligible episodes (episodes starting inside a rule's warm-up are not eligible)")
print("ep_prec = detected episodes / (detected episodes + false incidents)")
print(f"{'rule':<26} {'alerts':>6} {'incid':>5} {'ep_prec':>7} {'false/day':>9}  "
      + "  ".join(f"{k:>10}" for k in KINDS) + "  false incidents by scenario")
for name, make_rule, warmup in CONFIGS:
    alerts = run_rules(ds.events, [make_rule()])
    score = score_alerts(alerts, ds.truth)
    limit = timedelta(seconds=warmup)
    eligible = {k: {e for e in episodes[k] if episode_start[e] - dataset_start >= limit}
                for k in KINDS}
    hits = {k: score["detected"] & eligible[k] for k in KINDS}
    detected_total = sum(len(v) for v in hits.values())
    false_incidents = score["incidents"] - score["true_incidents"]
    denominator = detected_total + false_incidents
    ep_precision = detected_total / denominator if denominator else float("nan")
    scored_days = days - warmup / 86400
    cols = "  ".join(f"{len(hits[k])}/{len(eligible[k])}".rjust(10) for k in KINDS)
    print(f"{name:<26} {score['alerts']:>6} {score['incidents']:>5} {ep_precision:>7.2f} "
          f"{false_incidents / scored_days:>9.1f}  {cols}  {score['false_by_scenario']}")