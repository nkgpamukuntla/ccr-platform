"""Daily scans at the end of each office's business day, in its own time zone."""

from datetime import UTC, datetime, time

from app.schedule import is_due, last_due, next_run, valid_zone

NY = "America/New_York"
SIX_PM = time(18, 0)


def utc(*a: int) -> datetime:
    return datetime(*a, tzinfo=UTC)


def test_eastern_six_pm_in_utc_follows_daylight_saving() -> None:
    # 28 Oct 2026 is EDT (UTC-4): 18:00 local = 22:00 UTC. 10 Nov 2026 is EST (UTC-5): 23:00 UTC.
    assert next_run(utc(2026, 10, 28, 12), NY, SIX_PM) == utc(2026, 10, 28, 22)
    assert next_run(utc(2026, 11, 10, 12), NY, SIX_PM) == utc(2026, 11, 10, 23)


def test_last_due_is_today_after_six_and_yesterday_before() -> None:
    assert last_due(utc(2026, 10, 28, 23), NY, SIX_PM) == utc(2026, 10, 28, 22)
    assert last_due(utc(2026, 10, 28, 15), NY, SIX_PM) == utc(2026, 10, 27, 22)


def test_due_once_per_day() -> None:
    before_six = utc(2026, 10, 28, 21, 5)
    after_six = utc(2026, 10, 28, 22, 5)
    ran_yesterday = utc(2026, 10, 27, 22, 5)
    assert not is_due(before_six, NY, SIX_PM, ran_yesterday, 0)  # yesterday's scan still current
    assert is_due(after_six, NY, SIX_PM, ran_yesterday, 0)  # today's slot has passed
    assert not is_due(utc(2026, 10, 28, 23, 5), NY, SIX_PM, after_six, 0)  # already ran today


def test_new_office_is_due_at_once_and_failures_retry_a_few_times() -> None:
    now = utc(2026, 10, 28, 14)
    assert is_due(now, NY, SIX_PM, None, 0)
    assert is_due(now, NY, SIX_PM, None, 2)
    assert not is_due(now, NY, SIX_PM, None, 3)


def test_other_zones_and_custom_time() -> None:
    # A D-Biz office in Singapore (UTC+8, no DST) scanning at 19:00 local = 11:00 UTC.
    assert next_run(utc(2026, 10, 28, 3), "Asia/Singapore", time(19, 0)) == utc(2026, 10, 28, 11)
    assert next_run(utc(2026, 10, 28, 3), "Asia/Kolkata", SIX_PM) == utc(2026, 10, 28, 12, 30)
    assert valid_zone("America/Chicago") and not valid_zone("Mars/Olympus") and not valid_zone("EST5EDT ")
