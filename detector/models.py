from dataclasses import dataclass
from datetime import datetime


@dataclass(frozen=True)
class LogEvent:
    """Exactly what the application logged. The only input a detector may see."""
    request_id: str
    timestamp: datetime
    user_id: int | None
    method: str
    path: str
    object_type: str | None
    object_id: str | None
    status_code: int
    source_ip: str | None

    @property
    def succeeded(self) -> bool:
        return 200 <= self.status_code < 300


@dataclass(frozen=True)
class Alert:
    rule: str
    user_id: int
    first_event_time: datetime
    time: datetime
    request_ids: tuple
    details: str