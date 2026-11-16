import json
import sys
from datetime import timedelta
from pathlib import Path
from statistics import mean

from detector.authorization import UnauthorizedAccessRule
from detector.factory import make_rule
from detector.engine import run_rules
from detector.policy import Policy
from evaluation.dataset import load_dataset
from evaluation.metrics import KINDS, episodes_by_kind, score_alerts, wilson

FROZEN = Path("evaluation/frozen_config.json")
WARMUP = {"B3": 86400}  # episodes starting inside a rule's warm-up cannot be judged

GRID = {
    "B1": [{"rule": "B1", "window": 60, "threshold": t} for t in (10, 15, 20, 30, 40)],
    "B2": [{"rule": "B2", "window": w, "run": r, "quiet": q}
           for w in (3600, 14400, 28800) for r in (5, 10) for q in ("window", 1800)],
    "B3": [{"rule": "B3", "window": w, "threshold": n} for w in (3600, 28800) for n in (3, 5, 8)],
    "B4": [{"rule": "B4", "window": 60, "threshold": t} for t in (10, 20, 30, 40)],
    "B5": [{"rule": "B5", "window": 3600, "threshold": n} for n in (3, 5, 10)],
}

def describe(cfg):
    return ", ".join(f"{k}={v}" for k, v in cfg.items() if k != "rule")


def f1(precision, recall):
    return 0.0 if precision + recall == 0 else 2 * precision * recall / (precision + recall)


def ci_text(k, n):
    if n == 0:
        return "n/a"
    low, high = wilson(k, n)
    return f"{k}/{n} ({low * 100:.0f}-{high * 100:.0f}%)"


class Context:
    def __init__(self, ds):
        self.ds = ds
        self.episodes = episodes_by_kind(ds.truth)
        self.start = ds.events[0].timestamp
        self.days = (ds.events[-1].timestamp - self.start).total_seconds() / 86400
        self.episode_start = {}
        for event in ds.events:
            episode = ds.truth[event.request_id].episode
            if episode and episode not in self.episode_start:
                self.episode_start[episode] = event.timestamp


def evaluate(ctx, cfg):
    ds = ctx.ds
    alerts = run_rules(ds.events, [make_rule(cfg)])
    score = score_alerts(alerts, ds.truth)
    warmup = timedelta(seconds=WARMUP.get(cfg["rule"], 0))
    eligible = {k: {e for e in ctx.episodes[k] if ctx.episode_start[e] - ctx.start >= warmup}
                for k in KINDS}
    hits = {k: len(score["detected"] & eligible[k]) for k in KINDS}
    n_eligible = {k: len(eligible[k]) for k in KINDS}
    detected, total = sum(hits.values()), sum(n_eligible.values())
    false_incidents = score["incidents"] - score["true_incidents"]
    precision = detected / (detected + false_incidents) if detected + false_incidents else 0.0
    recall = detected / total if total else 0.0
    scored_days = ctx.days - warmup.total_seconds() / 86400
    return {
        "hits": hits, "eligible": n_eligible, "detected": detected, "total": total,
        "false_incidents": false_incidents, "alerts": len(alerts), "incidents": score["incidents"],
        "recall": recall, "precision": precision, "f1": f1(precision, recall),
        "false_per_day": false_incidents / scored_days,
    }


def evaluate_a1(ctx, policy):
    ds = ctx.ds
    violations = {rid for rid, t in ds.truth.items() if t.unauthorized}
    episode_of = {rid: t.episode for rid, t in ds.truth.items() if t.episode}
    alerts = run_rules(ds.events, [UnauthorizedAccessRule(policy, window_seconds=0, quiet_seconds=0)])
    flagged = {rid for alert in alerts for rid in alert.request_ids}
    true_positive = flagged & violations
    false_positive = flagged - violations
    hit = {episode_of[r] for r in true_positive if r in episode_of}
    return {
        "hits": {k: len(hit & ctx.episodes[k]) for k in KINDS},
        "eligible": {k: len(ctx.episodes[k]) for k in KINDS},
        "tp": len(true_positive), "fp": len(false_positive), "flagged": len(flagged),
        "violations": len(violations), "non_violations": len(ds.events) - len(violations),
        "days": ctx.days,
    }


def degradation_rows(ctx, full):
    cases = [("complete data", None, 0.0)]
    cases += [(f"{int(f * 100)}% of objects missing", "missing", f) for f in (0.1, 0.3, 0.5, 0.7)]
    cases += [(f"{int(f * 100)}% of owners wrong", "wrong", f) for f in (0.05, 0.1, 0.2)]
    rows = []
    for label, kind, fraction in cases:
        runs = []
        for seed in range(5):
            if kind == "missing":
                policy = full.without_objects(fraction, seed)
            elif kind == "wrong":
                policy = full.with_wrong_owners(fraction, seed)
            else:
                policy = full
            runs.append(evaluate_a1(ctx, policy))
            if kind is None:
                break
        rows.append({
            "case": label,
            "episodes": {k: mean(r["hits"][k] for r in runs) for k in KINDS},
            "recall": mean(r["tp"] / r["violations"] for r in runs),
            "precision": mean(r["tp"] / r["flagged"] if r["flagged"] else float("nan") for r in runs),
            "fpr": mean(r["fp"] / r["non_violations"] for r in runs),
            "false_per_day": mean(r["fp"] / r["days"] for r in runs),
        })
    return rows


def run_select(folder):
    ds = load_dataset(folder)
    ctx = Context(ds)
    frozen = {}
    print(f"Selection on {folder} ({len(ds.events)} events, {ctx.days:.1f} simulated days)")
    print("Rule: highest F1 of pooled episode recall and episode precision; "
          "ties go to fewer false incidents per day, then to the earlier grid entry.")
    for family, grid in GRID.items():
        results = [(cfg, evaluate(ctx, cfg)) for cfg in grid]
        best = max(range(len(results)),
                   key=lambda i: (results[i][1]["f1"], -results[i][1]["false_per_day"], -i))
        print(f"\n{family}")
        print(f"  {'configuration':<40}{'recall':>8}{'ep_prec':>9}{'F1':>7}{'false/day':>11}")
        for i, (cfg, r) in enumerate(results):
            mark = "*" if i == best else " "
            print(f"{mark} {describe(cfg):<40}{r['recall']:>8.2f}{r['precision']:>9.2f}"
                  f"{r['f1']:>7.2f}{r['false_per_day']:>11.1f}")
        frozen[family] = results[best][0]
    FROZEN.write_text(json.dumps(frozen, indent=1), encoding="utf-8")
    print(f"\nWritten {FROZEN}. Commit it BEFORE running the test phase.")


def run_test(folder):
    results_path = Path(folder) / "final_results.json"
    if results_path.exists():
        sys.exit(f"{results_path} already exists: this dataset was already used for a final run. "
                 "See the burned-test rule in docs/evaluation-protocol.md.")
    if not FROZEN.exists():
        sys.exit("Run the select phase first and commit evaluation/frozen_config.json.")
    frozen = json.loads(FROZEN.read_text(encoding="utf-8"))
    ds = load_dataset(folder)
    ctx = Context(ds)
    full = Policy.from_ownership(ds.ownership)

    print(f"FINAL EVALUATION on {folder}: {len(ds.events)} events, {ctx.days:.1f} simulated days")
    print("Frozen configurations:", {family: describe(cfg) for family, cfg in frozen.items()})

    behavioral = {family: {"config": cfg, **evaluate(ctx, cfg)} for family, cfg in frozen.items()}

    print("\nTable 1: behavioral rules (frozen configurations)")
    print(f"{'rule':<5}{'configuration':<34}" + "".join(f"{k:>11}" for k in KINDS)
          + f"{'all episodes':>22}{'ep_prec':>22}{'false/day':>11}")
    for family, r in behavioral.items():
        cols = "".join(f"{r['hits'][k]}/{r['eligible'][k]}".rjust(11) for k in KINDS)
        print(f"{family:<5}{describe(r['config']):<34}{cols}"
              f"{ci_text(r['detected'], r['total']):>22}"
              f"{ci_text(r['detected'], r['detected'] + r['false_incidents']):>22}"
              f"{r['false_per_day']:>11.1f}")

    print("\nTable 2: episode recall per attack type (95% Wilson intervals)")
    for family, r in behavioral.items():
        print(f"{family}: " + "   ".join(
            f"{k} {ci_text(r['hits'][k], r['eligible'][k])}" for k in KINDS))

    a1 = evaluate_a1(ctx, full)
    print("\nTable 3: A1 per request, complete ownership data")
    print("episodes: " + "   ".join(f"{k} {ci_text(a1['hits'][k], a1['eligible'][k])}" for k in KINDS))
    print(f"request recall      {ci_text(a1['tp'], a1['violations'])}")
    print(f"request precision   {ci_text(a1['tp'], a1['flagged'])}")
    print(f"false positive rate {ci_text(a1['fp'], a1['non_violations'])}  "
          "(false positives / requests that are not violations)")

    rows = degradation_rows(ctx, full)
    print("\nTable 4: A1 with degraded ownership data (mean of 5 seeds)")
    print(f"{'ownership data':<24}" + "".join(f"{k:>12}" for k in KINDS)
          + f"{'req recall':>12}{'precision':>11}{'FPR':>9}{'false/day':>11}")
    for row in rows:
        cols = "".join(f"{row['episodes'][k]:>6.1f}/{len(ctx.episodes[k]):<5}" for k in KINDS)
        print(f"{row['case']:<24}{cols}{row['recall']:>12.3f}{row['precision']:>11.3f}"
              f"{row['fpr']:>9.4f}{row['false_per_day']:>11.1f}")

    results_path.write_text(json.dumps(
        {"frozen": frozen, "behavioral": behavioral, "a1": a1, "degradation": rows}, indent=1),
        encoding="utf-8")
    print(f"\nResults saved to {results_path}")


if __name__ == "__main__":
    if len(sys.argv) != 3 or sys.argv[1] not in ("select", "test"):
        sys.exit(__doc__)
    (run_select if sys.argv[1] == "select" else run_test)(sys.argv[2])