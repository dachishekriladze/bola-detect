from datetime import datetime, timedelta, timezone

from detector.behavioral import FailedRequestsRule, RequestRateRule
from detector.models import LogEvent

T0 = datetime(2026, 11, 1, 8, 0, tzinfo=timezone.utc)


def ev(i, seconds, user=1, status=200):
    return LogEvent(
        request_id=f"r{i}-u{user}",
        timestamp=T0 + timedelta(seconds=seconds),
        user_id=user,
        method="GET",
        path=f"/invoices/{i}",
        object_type="invoice",
        object_id=str(i),
        status_code=status,
        source_ip="10.0.0.1",
    )


def run(rule, events):
    alerts = []
    for event in events:
        alerts.extend(rule.process(event))
    return alerts


def test_rate_burst_alerts_once():
    alerts = run(RequestRateRule(60, 30), [ev(i, i) for i in range(40)])
    assert len(alerts) == 1
    assert len(alerts[0].request_ids) == 30


def test_normal_pace_does_not_trigger_the_rate_rule():
    assert run(RequestRateRule(60, 30), [ev(i, i * 60) for i in range(100)]) == []


def test_rate_is_counted_per_user():
    events = [ev(i, i, user=1 + i % 2) for i in range(40)]  # 20 requests each
    assert run(RequestRateRule(60, 30), events) == []


def test_rate_rule_ignores_requests_without_user():
    events = [ev(i, i) for i in range(40)]
    anonymous = [LogEvent(e.request_id, e.timestamp, None, e.method, e.path, e.object_type,
                          e.object_id, e.status_code, e.source_ip) for e in events]
    assert run(RequestRateRule(60, 30), anonymous) == []


def test_second_rate_burst_after_quiet_period_alerts_again():
    first = [ev(i, i) for i in range(30)]
    second = [ev(100 + i, 3600 + i) for i in range(30)]
    assert len(run(RequestRateRule(60, 30), first + second)) == 2


def test_many_failures_alert_once():
    alerts = run(FailedRequestsRule(3600, 5), [ev(i, i, status=404) for i in range(20)])
    assert len(alerts) == 1
    assert len(alerts[0].request_ids) == 5


def test_successful_requests_do_not_count_as_failures():
    assert run(FailedRequestsRule(3600, 5), [ev(i, i, status=200) for i in range(50)]) == []


def test_failures_spread_over_time_do_not_alert():
    assert run(FailedRequestsRule(3600, 5), [ev(i, i * 1200, status=404) for i in range(20)]) == []


def test_failures_are_counted_per_user():
    events = [ev(i, i, user=1 + i % 2, status=403) for i in range(8)]  # 4 each
    assert run(FailedRequestsRule(3600, 5), events) == []