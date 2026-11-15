from collections import Counter, defaultdict, deque
from datetime import timedelta

from detector.models import Alert, LogEvent


class DistinctObjectsRule:
    """B1: one user touches many distinct objects of one type within a short window.

    One alert per burst: after alerting, the same (user, object type) stays quiet
    for one window length. The alert's evidence is the first request per distinct object.
    """

    name = "B1_distinct_objects"

    def __init__(self, window_seconds=60, threshold=20):
        self.window = timedelta(seconds=window_seconds)
        self.threshold = threshold
        self._recent = defaultdict(deque)  # (user, type) -> deque of (time, object_id, request_id)
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
    """B2: one user touched a run of consecutive numeric object IDs within a window.

    Other requests in between do not break the run, so slow enumeration is visible
    when the window is long enough. UUIDs are not numeric and are ignored.

    After an alert the same (user, object type) stays quiet for quiet_seconds
    (default: one window length). The alert's evidence is the first request per ID in the run.
    """

    name = "B2_consecutive_ids"

    def __init__(self, window_seconds=14400, min_run=10, quiet_seconds=None):
        self.window = timedelta(seconds=window_seconds)
        self.quiet = timedelta(seconds=quiet_seconds if quiet_seconds is not None else window_seconds)
        self.min_run = min_run
        self._recent = defaultdict(deque)    # (user, type) -> deque of (time, id, request_id)
        self._counts = defaultdict(Counter)  # (user, type) -> ids currently in the window
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