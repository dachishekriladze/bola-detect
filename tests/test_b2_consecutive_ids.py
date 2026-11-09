from datetime import datetime, timedelta, timezone

from detector.behavioral import ConsecutiveIdsRule
from detector.models import LogEvent

T0 = datetime(2026, 11, 1, 8, 0, tzinfo=timezone.utc)


def ev(i, seconds, object_id, user=1, object_type="invoice"):
    return LogEvent(
        request_id=f"r{i}-u{user}",
        timestamp=T0 + timedelta(seconds=seconds),
        user_id=user,
        method="GET",
        path=f"/{object_type}s/{object_id}",
        object_type=object_type,
        object_id=str(object_id),
        status_code=200,
        source_ip="10.0.0.1",
    )


def run(rule, events):
    alerts = []
    for event in events:
        alerts.extend(rule.process(event))
    return alerts


def test_consecutive_run_alerts():
    rule = ConsecutiveIdsRule(window_seconds=3600, min_run=10)
    alerts = run(rule, [ev(i, i * 60, 100 + i) for i in range(10)])
    assert len(alerts) == 1
    assert len(alerts[0].request_ids) == 10


def test_ids_with_a_gap_between_them_do_not_alert():
    rule = ConsecutiveIdsRule(window_seconds=3600, min_run=10)
    assert run(rule, [ev(i, i * 60, i * 5) for i in range(30)]) == []  # step 5, like interleaved owners


def test_slow_run_needs_a_long_enough_window():
    events = [ev(i, i * 1800, 100 + i) for i in range(12)]  # one request every 30 minutes
    assert len(run(ConsecutiveIdsRule(window_seconds=8 * 3600, min_run=10), events)) == 1
    assert run(ConsecutiveIdsRule(window_seconds=3600, min_run=10), events) == []


def test_other_requests_in_between_do_not_break_the_run():
    rule = ConsecutiveIdsRule(window_seconds=3600, min_run=10)
    events = []
    for k in range(10):
        events.append(ev(k, 2 * k, 100 + k))              # the enumeration
        events.append(ev(1000 + k, 2 * k + 1, 5 * (k + 1)))  # the user's own normal requests
    assert len(run(rule, events)) == 1


def test_users_are_counted_separately():
    rule = ConsecutiveIdsRule(window_seconds=3600, min_run=10)
    events = [ev(i, i, 100 + i, user=1 + i % 2) for i in range(30)]  # each user gets every second id
    assert run(rule, events) == []


def test_uuid_object_ids_are_ignored():
    rule = ConsecutiveIdsRule(window_seconds=3600, min_run=10)
    events = [ev(i, i, f"3f2a9c1e-{i:04d}-4000-8000-000000000000") for i in range(30)]
    assert run(rule, events) == []


def test_one_alert_per_run():
    rule = ConsecutiveIdsRule(window_seconds=3600, min_run=10)
    assert len(run(rule, [ev(i, i, 100 + i) for i in range(40)])) == 1