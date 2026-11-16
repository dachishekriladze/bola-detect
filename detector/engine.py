def run_rules(events, rules):
    alerts = []
    for event in sorted(events, key=lambda e: e.timestamp):
        for rule in rules:
            alerts.extend(rule.process(event))
    return alerts