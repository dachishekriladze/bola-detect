import argparse
import json
import time
from collections import deque
from datetime import datetime, timezone
from pathlib import Path

from detector.authorization import UnauthorizedAccessRule
from detector.factory import make_rule
from detector.models import LogEvent
from detector.policy import Policy


def parse_line(line):
    try:
        raw = json.loads(line)
        return LogEvent(
            request_id=raw["request_id"],
            timestamp=datetime.fromisoformat(raw["timestamp"]),
            user_id=raw["user_id"],
            method=raw["method"],
            path=raw["path"],
            object_type=raw["object_type"],
            object_id=raw["object_id"],
            status_code=raw["status_code"],
            source_ip=raw["source_ip"],
        )
    except (json.JSONDecodeError, KeyError, ValueError):
        return None


class LiveDetector:
    EVIDENCE_LIMIT = 50

    def __init__(self, rules, names, keep=20000):
        self.rules = rules
        self.names = names
        self.keep = keep
        self._events = {}
        self._order = deque()

    def process(self, event):
        self._events[event.request_id] = event
        self._order.append(event.request_id)
        if len(self._order) > self.keep:
            self._events.pop(self._order.popleft(), None)
        records = []
        for rule in self.rules:
            for alert in rule.process(event):
                records.append(self._record(alert))
        return records

    def _record(self, alert):
        evidence = []
        for request_id in alert.request_ids[: self.EVIDENCE_LIMIT]:
            e = self._events.get(request_id)
            if e is not None:
                evidence.append({
                    "request_id": e.request_id,
                    "timestamp": e.timestamp.isoformat(),
                    "user_id": e.user_id,
                    "method": e.method,
                    "path": e.path,
                    "status_code": e.status_code,
                    "source_ip": e.source_ip,
                })
        return {
            "rule": alert.rule,
            "severity": alert.severity,
            "user_id": alert.user_id,
            "user": self.names.get(alert.user_id, str(alert.user_id)),
            "time": alert.time.isoformat(),
            "first_event_time": alert.first_event_time.isoformat(),
            "detected_at": datetime.now(timezone.utc).isoformat(),
            "details": alert.details,
            "evidence_count": len(alert.request_ids),
            "evidence": evidence,
        }


def build_rules(config_path, policy):
    frozen = json.loads(Path(config_path).read_text(encoding="utf-8"))
    rules = [make_rule(cfg) for cfg in frozen.values()]
    rules.append(UnauthorizedAccessRule(policy))
    return rules


def follow_lines(path, from_start=False, poll=0.3):
    path = Path(path)
    while not path.exists():
        time.sleep(poll)
    with open(path, encoding="utf-8") as f:
        if not from_start:
            f.seek(0, 2)
        pending = ""
        while True:
            chunk = f.readline()
            if not chunk:
                time.sleep(poll)
                continue
            pending += chunk
            if pending.endswith("\n"):
                yield pending
                pending = ""


def replay_events(path):
    events = []
    with open(path, encoding="utf-8") as f:
        for line in f:
            event = parse_line(line)
            if event is not None:
                events.append(event)
    events.sort(key=lambda e: e.timestamp)
    return events


def events(args):
    if args.replay:
        yield from replay_events(args.source)
    else:
        for line in follow_lines(args.source, args.from_start):
            event = parse_line(line)
            if event is not None:
                yield event


def main():
    parser = argparse.ArgumentParser(description="Live IDOR/BOLA detector")
    parser.add_argument("--ownership", required=True, help="ownership export of the running lab")
    parser.add_argument("--source", default="logs/app.jsonl")
    parser.add_argument("--config", default="evaluation/frozen_config.json")
    parser.add_argument("--alerts-out", default="logs/alerts.jsonl")
    parser.add_argument("--replay", action="store_true",
                        help="read the whole source sorted by time instead of following it")
    parser.add_argument("--delay", type=float, default=0.0,
                        help="seconds between events (animates a replay)")
    parser.add_argument("--from-start", action="store_true",
                        help="when following, also process lines that already exist")
    parser.add_argument("--reset", action="store_true", help="empty the alerts file first")
    args = parser.parse_args()

    ownership = json.loads(Path(args.ownership).read_text(encoding="utf-8"))
    policy = Policy.from_ownership(ownership)
    names = {u["id"]: name for name, u in ownership["users"].items()}
    detector = LiveDetector(build_rules(args.config, policy), names)

    out = Path(args.alerts_out)
    out.parent.mkdir(parents=True, exist_ok=True)
    if args.reset or not out.exists():
        out.write_text("", encoding="utf-8")

    print(f"Detector running with {len(detector.rules)} rules. Alerts go to {out}. Ctrl+C stops it.")
    count = 0
    try:
        for event in events(args):
            for record in detector.process(event):
                with open(out, "a", encoding="utf-8") as f:
                    f.write(json.dumps(record, separators=(",", ":")) + "\n")
                print(f"[{record['detected_at'][11:19]}] {record['rule']:<24} "
                      f"{record['severity']:<10} user {record['user']}: {record['details']}")
            count += 1
            if args.delay:
                time.sleep(args.delay)
    except KeyboardInterrupt:
        pass
    print(f"Stopped after {count} events.")


if __name__ == "__main__":
    main()