"""When each office is scanned: once a day at the end of its business day, in its own time zone.

EventBridge Scheduler starts the worker every hour; the worker collects only the offices that are
due. An office is due when its last successful run started before the most recent local
collection time (default 18:00). A new office is due at once, so onboarding can be validated the
same day. A failed run is retried on the next hourly ticks, at most MAX_RETRIES times a day.
Daylight-saving changes are handled by zoneinfo.
"""

from datetime import UTC, datetime, time, timedelta
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError, available_timezones

DEFAULT_TZ = "America/New_York"  # Georgia
DEFAULT_AT = time(18, 0)
MAX_RETRIES = 3

# Offered in the portal; any IANA name is accepted.
COMMON_ZONES = [
    "America/New_York",
    "America/Chicago",
    "America/Denver",
    "America/Phoenix",
    "America/Los_Angeles",
    "America/Anchorage",
    "Pacific/Honolulu",
    "Europe/London",
    "Asia/Kolkata",
    "Asia/Singapore",
    "Australia/Sydney",
    "UTC",
]


def valid_zone(name: str) -> bool:
    if name not in available_timezones():
        return False
    try:
        ZoneInfo(name)
    except ZoneInfoNotFoundError:
        return False
    return True


def last_due(now: datetime, tz: str, at: time) -> datetime:
    """The most recent scheduled collection moment at or before now, in UTC."""
    z = ZoneInfo(tz)
    local = now.astimezone(z)
    slot = datetime.combine(local.date(), at, tzinfo=z)
    if slot > local:
        slot = datetime.combine(local.date() - timedelta(days=1), at, tzinfo=z)
    return slot.astimezone(UTC)


def next_run(now: datetime, tz: str, at: time) -> datetime:
    """The next scheduled collection moment after now, in UTC."""
    z = ZoneInfo(tz)
    local = now.astimezone(z)
    slot = datetime.combine(local.date(), at, tzinfo=z)
    if slot <= local:
        slot = datetime.combine(local.date() + timedelta(days=1), at, tzinfo=z)
    return slot.astimezone(UTC)


def is_due(now: datetime, tz: str, at: time, last_ok: datetime | None, failures_since_due: int) -> bool:
    if failures_since_due >= MAX_RETRIES:
        return False
    return last_ok is None or last_ok < last_due(now, tz, at)
