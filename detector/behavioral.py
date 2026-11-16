from collections import Counter, defaultdict, deque
from datetime import timedelta

from detector.models import Alert, LogEvent


class DistinctObjectsRule:

    name = "B1_distinct_objects"

    def __init__(self, window_seconds=60, threshold=20):
        self.window = timedelta(seconds=window_seconds)
        self.threshold = threshold
        self._recent = defaultdict(deque)
        self._quiet_until = {}

    def process(self, event: LogEvent):
        if event.user_id is None or event.object_id is None:
            return []
        key = (event.user_id, event.object_type)
        recent = self._recent[key]
        recent.append((event.timestamp, event.object_id, event.request_id))
        while recent and event.timestamp - recent[0][0] > self.window:
            recent.popleft()

        distinct = {object_id for _, object_id, _ in recent}
        quiet_until = self._quiet_until.get(key)
        if len(distinct) >= self.threshold and (quiet_until is None or event.timestamp >= quiet_until):
            self._quiet_until[key] = event.timestamp + self.window
            supporting, seen = [], set()
            for _, object_id, request_id in recent:
                if object_id not in seen:
                    seen.add(object_id)
                    supporting.append(request_id)
            return [Alert(
                rule=self.name,
                user_id=event.user_id,
                first_event_time=recent[0][0],
                time=event.timestamp,
                request_ids=tuple(supporting),
                details=(f"{len(distinct)} distinct {event.object_type} ids "
                         f"within {self.window.total_seconds():.0f}s"),
            )]
        return []


class ConsecutiveIdsRule:

    name = "B2_consecutive_ids"

    def __init__(self, window_seconds=14400, min_run=10, quiet_seconds=None):
        self.window = timedelta(seconds=window_seconds)
        self.quiet = timedelta(seconds=quiet_seconds if quiet_seconds is not None else window_seconds)
        self.min_run = min_run
        self._recent = defaultdict(deque)
        self._counts = defaultdict(Counter)
        self._quiet_until = {}

    def process(self, event: LogEvent):
        if event.user_id is None or event.object_id is None or not event.object_id.isdigit():
            return []
        key = (event.user_id, event.object_type)
        object_id = int(event.object_id)
        recent, counts = self._recent[key], self._counts[key]
        recent.append((event.timestamp, object_id, event.request_id))
        counts[object_id] += 1
        while recent and event.timestamp - recent[0][0] > self.window:
            _, old_id, _ = recent.popleft()
            counts[old_id] -= 1
            if counts[old_id] == 0:
                del counts[old_id]

        low = high = object_id
        while low - 1 in counts:
            low -= 1
        while high + 1 in counts:
            high += 1
        run = high - low + 1

        quiet_until = self._quiet_until.get(key)
        if run >= self.min_run and (quiet_until is None or event.timestamp >= quiet_until):
            self._quiet_until[key] = event.timestamp + self.quiet
            supporting, seen = [], set()
            for _, i, r in recent:
                if low <= i <= high and i not in seen:
                    seen.add(i)
                    supporting.append(r)
            return [Alert(
                rule=self.name,
                user_id=event.user_id,
                first_event_time=recent[0][0],
                time=event.timestamp,
                request_ids=tuple(supporting),
                details=(f"{run} consecutive {event.object_type} ids ({low}-{high}) "
                         f"within {self.window.total_seconds() / 3600:.1f}h"),
            )]
        return []

class FirstAccessRule:

    name = "B3_first_access"

    def __init__(self, window_seconds=3600, threshold=5, warmup_seconds=86400, quiet_seconds=1800):
        self.window = timedelta(seconds=window_seconds)
        self.threshold = threshold
        self.warmup = timedelta(seconds=warmup_seconds)
        self.quiet = timedelta(seconds=quiet_seconds)
        self._started = {}
        self._seen = defaultdict(set)
        self._new = defaultdict(deque)
        self._quiet_until = {}

    def process(self, event: LogEvent):
        if event.user_id is None:
            return []
        user = event.user_id
        self._started.setdefault(user, event.timestamp)
        if event.object_id is None:
            return []
        if not event.succeeded:
            return []
        obj = (event.object_type, event.object_id)
        if obj in self._seen[user]:
            return []
        self._seen[user].add(obj)
        if event.timestamp - self._started[user] < self.warmup:
            return []

        key = (user, event.object_type)
        new = self._new[key]
        new.append((event.timestamp, event.object_id, event.request_id))
        while new and event.timestamp - new[0][0] > self.window:
            new.popleft()

        quiet_until = self._quiet_until.get(key)
        if len(new) >= self.threshold and (quiet_until is None or event.timestamp >= quiet_until):
            self._quiet_until[key] = event.timestamp + self.quiet
            return [Alert(
                rule=self.name,
                user_id=user,
                first_event_time=new[0][0],
                time=event.timestamp,
                request_ids=tuple(request_id for _, _, request_id in new),
                details=(f"{len(new)} first-time {event.object_type} accesses "
                         f"within {self.window.total_seconds() / 3600:.1f}h"),
            )]
        return []
class RequestRateRule:

    name = "B4_request_rate"

    def __init__(self, window_seconds=60, threshold=30, quiet_seconds=None):
        self.window = timedelta(seconds=window_seconds)
        self.threshold = threshold
        self.quiet = timedelta(seconds=quiet_seconds if quiet_seconds is not None else window_seconds)
        self._recent = defaultdict(deque)
        self._quiet_until = {}

    def process(self, event: LogEvent):
        if event.user_id is None:
            return []
        recent = self._recent[event.user_id]
        recent.append((event.timestamp, event.request_id))
        while recent and event.timestamp - recent[0][0] > self.window:
            recent.popleft()
        quiet_until = self._quiet_until.get(event.user_id)
        if len(recent) >= self.threshold and (quiet_until is None or event.timestamp >= quiet_until):
            self._quiet_until[event.user_id] = event.timestamp + self.quiet
            return [Alert(
                rule=self.name,
                user_id=event.user_id,
                first_event_time=recent[0][0],
                time=event.timestamp,
                request_ids=tuple(request_id for _, request_id in recent),
                details=f"{len(recent)} requests within {self.window.total_seconds():.0f}s",
            )]
        return []


class FailedRequestsRule:

    name = "B5_failed_requests"

    def __init__(self, window_seconds=3600, threshold=5, quiet_seconds=None):
        self.window = timedelta(seconds=window_seconds)
        self.threshold = threshold
        self.quiet = timedelta(seconds=quiet_seconds if quiet_seconds is not None else window_seconds)
        self._failed = defaultdict(deque)
        self._quiet_until = {}

    def process(self, event: LogEvent):
        if event.user_id is None or not 400 <= event.status_code < 500:
            return []
        failed = self._failed[event.user_id]
        failed.append((event.timestamp, event.request_id))
        while failed and event.timestamp - failed[0][0] > self.window:
            failed.popleft()
        quiet_until = self._quiet_until.get(event.user_id)
        if len(failed) >= self.threshold and (quiet_until is None or event.timestamp >= quiet_until):
            self._quiet_until[event.user_id] = event.timestamp + self.quiet
            return [Alert(
                rule=self.name,
                user_id=event.user_id,
                first_event_time=failed[0][0],
                time=event.timestamp,
                request_ids=tuple(request_id for _, request_id in failed),
                details=f"{len(failed)} failed requests within {self.window.total_seconds() / 60:.0f} min",
            )]
        return []