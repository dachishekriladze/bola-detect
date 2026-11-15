from collections import Counter

KINDS = ("sequential", "slow", "uuid", "write")


def episodes_by_kind(truth):
    result = {kind: set() for kind in KINDS}
    for t in truth.values():
        if t.episode:
            result[t.episode.rsplit("-", 1)[0]].add(t.episode)
    return result


def classify(alert, truth):
    """Return (is_true, episode, scenario) for one alert.

    An alert is a true positive when at least half of its evidence requests are attack
    requests. It detects only the episode that contributes most of that evidence.
    """
    rows = [truth[r] for r in alert.request_ids]
    attack_rows = [t for t in rows if t.label == "attack"]
    if rows and 2 * len(attack_rows) >= len(rows):
        return True, Counter(t.episode for t in attack_rows).most_common(1)[0][0], None
    scenario = Counter(t.scenario for t in rows).most_common(1)[0][0] if rows else "none"
    return False, None, scenario


def score_alerts(alerts, truth, incident_gap_seconds=3600):
    """Score alerts per alert and per incident.

    Alerts of the same rule and user whose times are at most incident_gap_seconds apart
    are merged into one incident, so a long episode that alerts repeatedly counts once.
    An incident is true when any of its alerts is true.
    """
    classified, detected = [], set()
    for alert in alerts:
        is_true, episode, scenario = classify(alert, truth)
        classified.append((alert, is_true, scenario))
        if is_true:
            detected.add(episode)

    incidents, open_incident = [], {}
    for alert, is_true, scenario in sorted(classified, key=lambda item: item[0].time):
        key = (alert.rule, alert.user_id)
        incident = open_incident.get(key)
        if incident and (alert.time - incident["last"]).total_seconds() <= incident_gap_seconds:
            incident["last"] = alert.time
            incident["true"] = incident["true"] or is_true
            if scenario and not incident["scenario"]:
                incident["scenario"] = scenario
        else:
            incident = {"last": alert.time, "true": is_true, "scenario": scenario}
            incidents.append(incident)
            open_incident[key] = incident

    false_incidents = [i for i in incidents if not i["true"]]
    return {
        "alerts": len(alerts),
        "incidents": len(incidents),
        "true_incidents": len(incidents) - len(false_incidents),
        "false_by_scenario": dict(sorted(Counter(i["scenario"] for i in false_incidents).items())),
        "detected": detected,
    }