"""Degradation experiment: how does A1 behave when the ownership data is incomplete or wrong?

A1 runs in per-request mode (every violating request is its own alert), so quiet periods
and mixed evidence cannot hide anything. A request is a true violation when it targets an
object owned by someone else and the requester is not an admin (the full ownership data).

Usage (from the repo root): python -m evaluation.run_degradation datasets\\dev
Degraded cases are averaged over 5 random seeds.
"""
import sys
from statistics import mean

from detector.authorization import UnauthorizedAccessRule
from detector.engine import run_rules
from detector.policy import Policy
from evaluation.dataset import load_dataset
from evaluation.metrics import KINDS, episodes_by_kind

SEEDS = range(5)
ds = load_dataset(sys.argv[1])
full = Policy.from_ownership(ds.ownership)
truth = ds.truth
episodes = episodes_by_kind(truth)
total_episodes = {k: len(episodes[k]) for k in KINDS}
days = (ds.events[-1].timestamp - ds.events[0].timestamp).total_seconds() / 86400

violations = {rid for rid, t in truth.items() if t.unauthorized}
non_violations = len(ds.events) - len(violations)
episode_of = {rid: t.episode for rid, t in truth.items() if t.episode}


def evaluate(policy):
    alerts = run_rules(ds.events, [UnauthorizedAccessRule(policy, window_seconds=0, quiet_seconds=0)])
    flagged = {rid for alert in alerts for rid in alert.request_ids}
    true_flagged = flagged & violations
    false_flagged = flagged - violations
    hit = {episode_of[r] for r in true_flagged if r in episode_of}
    return {
        "episodes": {k: len(hit & episodes[k]) for k in KINDS},
        "recall": len(true_flagged) / len(violations),
        "precision": len(true_flagged) / len(flagged) if flagged else float("nan"),
        "fpr": len(false_flagged) / non_violations,
        "false_per_day": len(false_flagged) / days,
    }


cases = [("complete data", None, 0.0)]
cases += [(f"{int(f * 100)}% of objects missing", "missing", f) for f in (0.1, 0.3, 0.5, 0.7)]
cases += [(f"{int(f * 100)}% of owners wrong", "wrong", f) for f in (0.05, 0.1, 0.2)]

print(f"{sys.argv[1]}: A1 per request, {len(violations)} true violations, "
      f"{non_violations} other requests, {days:.1f} simulated days")
print(f"{'ownership data':<24}" + "".join(f"{k:>12}" for k in KINDS)
      + f"{'req recall':>12}{'precision':>11}{'FPR':>9}{'false/day':>11}")
for label, kind, fraction in cases:
    runs = []
    for seed in SEEDS:
        if kind == "missing":
            policy = full.without_objects(fraction, seed)
        elif kind == "wrong":
            policy = full.with_wrong_owners(fraction, seed)
        else:
            policy = full
        runs.append(evaluate(policy))
        if kind is None:
            break
    cols = "".join(f"{mean(r['episodes'][k] for r in runs):>6.1f}/{total_episodes[k]:<5}" for k in KINDS)
    print(f"{label:<24}{cols}{mean(r['recall'] for r in runs):>12.3f}"
          f"{mean(r['precision'] for r in runs):>11.3f}{mean(r['fpr'] for r in runs):>9.4f}"
          f"{mean(r['false_per_day'] for r in runs):>11.1f}")