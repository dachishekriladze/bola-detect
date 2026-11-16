from datetime import datetime, timedelta, timezone

import pytest

from detector.authorization import UnauthorizedAccessRule
from detector.behavioral import (ConsecutiveIdsRule, DistinctObjectsRule, FailedRequestsRule,
                                 FirstAccessRule, RequestRateRule)
from detector.factory import make_rule
from detector.live import LiveDetector, parse_line
from detector.models import LogEvent
from detector.policy import Policy

T0 = datetime(2026, 11, 1, 8, 0, tzinfo=timezone.utc)

LINE = ('{"timestamp":"2026-11-01T08:00:00+00:00","request_id":"abc","user_id":1,"method":"GET",'
        '"path":"/invoices/7","object_type":"invoice","object_id":"7","status_code":200,'
        '"source_ip":"10.0.0.1","duration_ms":3.2}')


def ev(i, seconds, user=1, object_id=None, object_type="invoice", status=200):
    oid = str(i) if object_id is None else object_id
    return LogEvent(
        request_id=f"r{i}",
        timestamp=T0 + timedelta(seconds=seconds),
        user_id=user,
        method="GET",
        path=f"/{object_type}s/{oid}",
        object_type=object_type,
        object_id=oid,
        status_code=status,
        source_ip="10.0.0.1",
    )


def test_factory_builds_each_rule_family():
    cases = [
        ({"rule": "B1", "window": 60, "threshold": 40}, DistinctObjectsRule),
        ({"rule": "B2", "window": 28800, "run": 5, "quiet": "window"}, ConsecutiveIdsRule),
        ({"rule": "B3", "window": 3600, "threshold": 3}, FirstAccessRule),
        ({"rule": "B4", "window": 60, "threshold": 10}, RequestRateRule),
        ({"rule": "B5", "window": 3600, "threshold": 5}, FailedRequestsRule),
    ]
    for cfg, cls in cases:
        assert isinstance(make_rule(cfg), cls)


def test_factory_quiet_window_means_the_window_length():
    rule = make_rule({"rule": "B2", "window": 28800, "run": 5, "quiet": "window"})
    assert rule.quiet == rule.window
    explicit = make_rule({"rule": "B2", "window": 28800, "run": 5, "quiet": 1800})
    assert explicit.quiet.total_seconds() == 1800


def test_factory_rejects_unknown_rules():
    with pytest.raises(ValueError):
        make_rule({"rule": "B9"})


def test_parse_line_reads_a_log_line():
    event = parse_line(LINE)
    assert event.request_id == "abc"
    assert event.object_id == "7"
    assert event.status_code == 200


def test_parse_line_ignores_garbage():
    assert parse_line("not json") is None
    assert parse_line('{"timestamp": "broken"}') is None


def test_live_detector_emits_a_record_with_evidence():
    detector = LiveDetector([DistinctObjectsRule(60, 5)], names={1: "alice"})
    records = []
    for i in range(5):
        records.extend(detector.process(ev(i, i)))
    assert len(records) == 1
    record = records[0]
    assert record["rule"] == "B1_distinct_objects"
    assert record["user"] == "alice"
    assert record["severity"] == "suspicious"
    assert record["evidence_count"] == 5
    assert [e["request_id"] for e in record["evidence"]] == ["r0", "r1", "r2", "r3", "r4"]


def test_live_detector_marks_unauthorized_access_as_confirmed():
    policy = Policy(owners={("invoice", "2"): 2}, admins=frozenset(), users=frozenset({1, 2}))
    detector = LiveDetector([UnauthorizedAccessRule(policy)], names={1: "alice", 2: "bob"})
    records = detector.process(ev(2, 0, user=1, object_id="2"))
    assert len(records) == 1
    assert records[0]["severity"] == "confirmed"
    assert records[0]["user"] == "alice"


def test_live_detector_keeps_only_a_bounded_number_of_events():
    detector = LiveDetector([], names={}, keep=3)
    for i in range(10):
        detector.process(ev(i, i))
    assert len(detector._events) == 3