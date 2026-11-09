from datetime import datetime, timedelta, timezone

from detector.behavioral import DistinctObjectsRule
from detector.models import LogEvent

T0 = datetime(2026, 11, 1, 8, 0, tzinfo=timezone.utc)


def ev(i, seconds, user=1, object_id="auto", object_type="invoice"):
    oid = str(i) if object_id == "auto" else object_id
    return LogEvent(
        request_id=f"r{i}-u{user}",
        timestamp=T0 + timedelta(seconds=seconds),
        user_id=user,
        method="GET",
        path=f"/{object_type}s/{oid}" if oid else f"/{object_type}s",
        object_type=object_type,
        object_id=oid,
        status_code=200,
        source_ip="10.0.0.1",
    )


def run(rule, events):
    alerts = []
    for event in events:
        alerts.extend(rule.process(event))
    return alerts


def test_fast_enumeration_alerts_once():
    rule = DistinctObjectsRule(window_seconds=60, threshold=20)
    alerts = run(rule, [ev(i, i) for i in range(40)])  # one request per second
    assert len(alerts) == 1
    assert alerts[0].user_id == 1
    assert len(alerts[0].request_ids) >= 20


def test_slow_activity_does_not_alert():
    rule = DistinctObjectsRule(window_seconds=60, threshold=20)
    assert run(rule, [ev(i, i * 600) for i in range(40)]) == []  # every 10 minutes


def test_repeating_one_object_does_not_alert():
    rule = DistinctObjectsRule(window_seconds=60, threshold=20)
    assert run(rule, [ev(i, i, object_id="7") for i in range(100)]) == []


def test_users_are_counted_separately():
    rule = DistinctObjectsRule(window_seconds=60, threshold=20)
    events = [ev(i, i, user=1 + i % 2) for i in range(30)]  # 15 distinct ids per user
    assert run(rule, events) == []


def test_object_types_are_counted_separately():
    rule = DistinctObjectsRule(window_seconds=60, threshold=20)
    events = [ev(i, i, object_type="invoice" if i % 2 else "order") for i in range(30)]
    assert run(rule, events) == []


def test_second_burst_after_quiet_period_alerts_again():
    rule = DistinctObjectsRule(window_seconds=60, threshold=20)
    first = [ev(i, i) for i in range(30)]
    second = [ev(100 + i, 3600 + i) for i in range(30)]  # one hour later
    assert len(run(rule, first + second)) == 2


def test_requests_without_object_id_are_ignored():
    rule = DistinctObjectsRule(window_seconds=60, threshold=20)
    assert run(rule, [ev(i, i, object_id=None) for i in range(50)]) == []