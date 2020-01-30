from datetime import datetime, timezone, timedelta

import pytest

from cborx.util import datetime_from_enhanced_RFC3339_text as text_to_datetime


def tz(seconds):
    return timezone(timedelta(seconds=seconds))


@pytest.mark.parametrize("text, expected", [
    ('2005-01-05T22:30:00Z', datetime(2005, 1, 5, 22, 30, 0, 0, timezone.utc)),
    ('2008-02-29T01:02:03.04Z', datetime(2008, 2, 29, 1, 2, 3, 40_000, timezone.utc)),
    ('2008-02-29T01:02:03.04+00:00', datetime(2008, 2, 29, 1, 2, 3, 40_000, timezone.utc)),
    ('2008-02-29T01:02:03.04-00:00', datetime(2008, 2, 29, 1, 2, 3, 40_000, timezone.utc)),
    ('2008-02-29T01:02:03.1234567-00:00', datetime(2008, 2, 29, 1, 2, 3, 123_457, timezone.utc)),
    ('2008-02-29T01:02:03+01:00', datetime(2008, 2, 29, 1, 2, 3, 0, tz(3600))),
    ('2008-02-29T01:02:03+00:01', datetime(2008, 2, 29, 1, 2, 3, 0, tz(60))),
    ('2008-02-29T01:02:03-01:00', datetime(2008, 2, 29, 1, 2, 3, 0, tz(-3600))),
    ('2008-02-29T01:02:03-00:01', datetime(2008, 2, 29, 1, 2, 3, 0, tz(-60))),
])
def test_text_to_datetime(text, expected):
    assert text_to_datetime(text) == expected


@pytest.mark.parametrize("text", [
    '2005-01',
    '2005-01-05T',
    '2005-01-05t22:30:00Z',
    '2005-01-05T22:30:00z',
    '2005-01-05T22:30:60Z',
    '2005-01-05T22:60:00Z',
    '2005-01-05T24:00:00Z',
    '2005-04-31T22:00:00Z',
    '2005-02-29T22:00:00Z',
    '2008-02-29T01:02:03.04-0:00',
    '2008-02-29T01:02:03.04-00:0',
    '2008-02-29T1:02:03Z',
    '2008-02-29T01:2:03Z',
    '2008-02-29T01:02:3Z',
    '2008-2-29T01:02:03Z',
    '2008-02-2T01:02:03Z',
    '2008-02-29T01:02:03-00:01K',
    'K2008-02-29T01:02:03-00:01',
    '2008-02-29ZT01:02:03-00:01',
])
def test_bad_text_to_datetime(text):
    with pytest.raises(ValueError):
        text_to_datetime(text)
