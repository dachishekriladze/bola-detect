def run_rules(events, rules):
    """Feed events to every rule in timestamp order and collect the alerts.
    Rules only ever see the event's own timestamp, never the computer's clock."""
    alerts = []
    for event in sorted(events, key=lambda e: e.timestamp):
        for rule in rules:
            alerts.extend(rule.process(event))
    return alerts