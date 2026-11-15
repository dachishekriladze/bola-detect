from datetime import datetime, timedelta, timezone

from detector.authorization import UnauthorizedAccessRule
from detector.models import LogEvent
from detector.policy import Policy

T0 = datetime(2026, 11, 1, 8, 0, tzinfo=timezone.utc)
POLICY = Policy(
    owners={("invoice", "1"): 1, ("invoice", "2"): 2, ("invoice", "3"): 2, ("document", "d1"): 2},
    admins=frozenset({9}),
    users=frozenset({1, 2}),
)


def ev(i, seconds, user, object_id, object_type="invoice", status=200):
    return LogEvent(
        request_id=f"r{i}",
        timestamp=T0 + timedelta(seconds=seconds),
        user_id=user,
        method="GET",
        path=f"/{object_type}s/{object_id}" if object_id else f"/{object_type}s",
        object_type=object_type,
        object_id=object_id,
        status_code=status,
        source_ip="10.0.0.1",
    )


def run(rule, events):
    alerts = []
    for event in events:
        alerts.extend(rule.process(event))
    return alerts


def test_own_object_does_not_alert():
    assert run(UnauthorizedAccessRule(POLICY), [ev(0, 0, user=1, object_id="1")]) == []


def test_other_users_object_alerts_as_confirmed():
    alerts = run(UnauthorizedAccessRule(POLICY), [ev(0, 0, user=1, object_id="2")])
    assert len(alerts) == 1
    assert alerts[0].severity == "confirmed"
    assert alerts[0].request_ids == ("r0",)


def test_failed_access_alerts_as_attempted():
    alerts = run(UnauthorizedAccessRule(POLICY), [ev(0, 0, user=1, object_id="2", status=403)])
    assert len(alerts) == 1
    assert alerts[0].severity == "attempted"


def test_admin_is_allowed():
    assert run(UnauthorizedAccessRule(POLICY), [ev(0, 0, user=9, object_id="2")]) == []


def test_unknown_objects_are_ignored():
    assert run(UnauthorizedAccessRule(POLICY), [ev(0, 0, user=1, object_id="4821", status=404)]) == []


def test_requests_without_object_id_are_ignored():
    assert run(UnauthorizedAccessRule(POLICY), [ev(0, 0, user=1, object_id=None)]) == []


def test_one_alert_per_burst_then_again_after_quiet_period():
    rule = UnauthorizedAccessRule(POLICY, quiet_seconds=1800)
    burst = [ev(i, i, user=1, object_id="2" if i % 2 else "3") for i in range(20)]
    later = [ev(100, 7200, user=1, object_id="2")]
    assert len(run(rule, burst)) == 1
    assert len(run(UnauthorizedAccessRule(POLICY, quiet_seconds=1800), burst + later)) == 2


def test_min_violations_needs_several_requests():
    rule = UnauthorizedAccessRule(POLICY, min_violations=3)
    events = [ev(0, 0, 1, "2"), ev(1, 1, 1, "3"), ev(2, 2, 1, "2")]
    assert run(rule, events[:2]) == []
    assert len(run(UnauthorizedAccessRule(POLICY, min_violations=3), events)) == 1


def test_missing_ownership_data_hides_violations():
    degraded = POLICY.without_objects(1.0)
    assert run(UnauthorizedAccessRule(degraded), [ev(0, 0, user=1, object_id="2")]) == []


def test_wrong_ownership_data_creates_false_violations():
    degraded = POLICY.with_wrong_owners(1.0)  # every owner replaced by another regular user
    alerts = run(UnauthorizedAccessRule(degraded), [ev(0, 0, user=1, object_id="1")])
    assert len(alerts) == 1  # user 1 reads their own invoice, but the data says it is user 2's