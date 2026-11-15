"""Show the false alerts of the leading B2 configuration.
Usage (from the repo root): python -m evaluation.inspect_alerts datasets\\dev
"""
import sys
from collections import Counter

from detector.behavioral import ConsecutiveIdsRule
from detector.engine import run_rules
from evaluation.dataset import load_dataset
from evaluation.metrics import classify

ds = load_dataset(sys.argv[1])
alerts = run_rules(ds.events, [ConsecutiveIdsRule(14400, 10, 1800)])
by_scenario = Counter()
shown = 0
for alert in alerts:
    is_true, _, scenario = classify(alert, ds.truth)
    if is_true:
        continue
    by_scenario[scenario] += 1
    if scenario != "admin_export" and shown < 15:
        rows = Counter(ds.truth[r].scenario for r in alert.request_ids)
        print(alert.time.isoformat(), "user", alert.user_id, alert.details, dict(rows))
        shown += 1
print("false alerts by scenario:", dict(by_scenario))