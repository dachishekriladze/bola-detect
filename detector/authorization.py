from collections import defaultdict, deque
from datetime import timedelta

from detector.models import Alert, LogEvent
from detector.policy import Policy


class UnauthorizedAccessRule:
    """A1: a user touched an object that belongs to someone else (and is not an admin).

    Uses the ownership data in the policy as an independent second check. The alert is
    'confirmed' when a violating request succeeded (2xx), otherwise 'attempted'.
    Objects unknown to the policy are ignored. One alert per user per quiet period.
    """

    name = "A1_unauthorized_access"

    def __init__(self, policy: Policy, window_seconds=3600, min_violations=1, quiet_seconds=1800):
        self.policy = policy
        self.window = timedelta(seconds=window_seconds)
        self.min_violations = min_violations
        self.quiet = timedelta(seconds=quiet_seconds)
        self._recent = defaultdict(deque)  # user -> deque of (time, request_id, succeeded)
        self._quiet_until = {}

    def process(self, event: LogEvent):
        if event.user_id is None or event.object_id is None:
            return []
        owner = self.policy.owner_of(event.object_type, event.object_id)
        if owner is None or event.user_id == owner or self.policy.is_admin(event.user_id):
            return []

        recent = self._recent[event.user_id]
        recent.append((event.timestamp, event.request_id, event.succeeded))
        while recent and event.timestamp - recent[0][0] > self.window:
            recent.popleft()

        quiet_until = self._quiet_until.get(event.user_id)
        if len(recent) >= self.min_violations and (quiet_until is None or event.timestamp >= quiet_until):
            self._quiet_until[event.user_id] = event.timestamp + self.quiet
            confirmed = any(ok for _, _, ok in recent)
            severity = "confirmed" if confirmed else "attempted"
            return [Alert(
                rule=self.name,
                user_id=event.user_id,
                first_event_time=recent[0][0],
                time=event.timestamp,
                request_ids=tuple(request_id for _, request_id, _ in recent),
                details=f"{len(recent)} requests to objects owned by other users ({severity})",
                severity=severity,
            )]
        return []