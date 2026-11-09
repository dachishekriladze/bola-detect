from collections import Counter

KINDS = ("sequential", "slow", "uuid", "write")


def episodes_by_kind(truth):
    result = {kind: set() for kind in KINDS}
    for t in truth.values():
        if t.episode:
            result[t.episode.rsplit("-", 1)[0]].add(t.episode)
    return result


def score_alerts(alerts, truth):
    """Attribute alerts to episodes.

    An alert is a true positive when at least half of its supporting requests are attack
    requests. It detects only the episode that contributes most of those requests, so a
    stray request of another episode on the same account does not count as a detection.
    """
    true_alerts = 0
    false_by_scenario = Counter()
    detected = set()
    for alert in alerts:
        rows = [truth[r] for r in alert.request_ids]
        if not rows:
            continue
        attack_rows = [t for t in rows if t.label == "attack"]
        if 2 * len(attack_rows) >= len(rows):
            true_alerts += 1
            detected.add(Counter(t.episode for t in attack_rows).most_common(1)[0][0])
        else:
            false_by_scenario[Counter(t.scenario for t in rows).most_common(1)[0][0]] += 1
    return {
        "alerts": len(alerts),
        "true_alerts": true_alerts,
        "false_by_scenario": dict(sorted(false_by_scenario.items())),
        "detected": detected,
    }