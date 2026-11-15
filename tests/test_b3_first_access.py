from datetime import datetime, timedelta, timezone

from detector.behavioral import FirstAccessRule
from dataclasses import replace
from detector.models import LogEvent

T0 = datetime(2026, 11, 1, 8, 0, tzinfo=timezone.utc)
AFTER_WARMUP = 90000  # seconds; the warm-up in these tests is 86400


def ev(i, seconds, object_id, user=1, object_type="invoice"):
    oid = None if object_id is None else str(object_id)
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


def make_rule(**changes):
    params = dict(window_seconds=3600, threshold=5, warmup_seconds=86400, quiet_seconds=1800)
    params.update(changes)
    return FirstAccessRule(**params)


def test_first_time_accesses_during_warmup_do_not_alert():
    assert run(make_rule(), [ev(i, i, 100 + i) for i in range(30)]) == []


def test_first_time_accesses_after_warmup_alert_once():
    events = [ev(0, 0, 1)]  # the user's first event starts the warm-up
    events += [ev(10 + i, AFTER_WARMUP + i, 100 + i) for i in range(8)]
    alerts = run(make_rule(), events)
    assert len(alerts) == 1
    assert len(alerts[0].request_ids) == 5


def test_objects_seen_during_warmup_are_not_new_later():
    events = [ev(i, i, i) for i in range(10)]                          # learned during warm-up
    events += [ev(100 + i, AFTER_WARMUP + i, i) for i in range(10)]    # read again later
    assert run(make_rule(), events) == []


def test_first_time_accesses_spread_over_hours_do_not_alert():
    events = [ev(0, 0, 1)]
    events += [ev(10 + i, AFTER_WARMUP + i * 7200, 100 + i) for i in range(10)]  # one every 2 hours
    assert run(make_rule(), events) == []


def test_users_are_counted_separately():
    events = [ev(0, 0, 1, user=1), ev(1, 0, 1, user=2)]
    events += [ev(10 + i, AFTER_WARMUP + i, 100 + i, user=1 + i % 2) for i in range(8)]  # 4 each
    assert run(make_rule(), events) == []


def test_object_types_are_counted_separately():
    events = [ev(0, 0, 1)]
    events += [ev(10 + i, AFTER_WARMUP + i, 100 + i,
                  object_type="invoice" if i % 2 else "order") for i in range(8)]
    assert run(make_rule(), events) == []


def test_requests_without_object_id_are_ignored():
    events = [ev(0, 0, 1)] + [ev(10 + i, AFTER_WARMUP + i, None) for i in range(50)]
    assert run(make_rule(), events) == []


def test_second_burst_after_quiet_period_alerts_again():
    events = [ev(0, 0, 1)]
    events += [ev(10 + i, AFTER_WARMUP + i, 100 + i) for i in range(5)]
    events += [ev(50 + i, AFTER_WARMUP + 7200 + i, 200 + i) for i in range(5)]
    assert len(run(make_rule(), events)) == 2

def test_failed_requests_do_not_count_as_first_time_accesses():
    events = [ev(0, 0, 1)]
    events += [replace(ev(10 + i, AFTER_WARMUP + i, 100 + i), status_code=404) for i in range(10)]
    assert run(make_rule(), events) == []