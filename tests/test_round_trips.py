import math
import re
from datetime import date, datetime, timezone, timedelta
from decimal import Decimal
from ipaddress import IPv4Address, IPv6Address, IPv4Network, IPv6Network
from fractions import Fraction
from uuid import UUID

import pytest

from cborx import *


@pytest.mark.parametrize("value", (
    0,
    -1,
    1,
    23,
    24,
    65535,
    65563,
    -65536,
    687612381,
    18446744073709551615,
    -18446744073709551616,
    b'',
    b'foo bar baz',
    b'the quick brown fox jumped over the lazy dog',
    '',
    'foo bar baz',
    '二兎を追う者は一兎をも得ず',
    [],
    [1, 2],
    [1, [2], 3, [[4, 5, 6]]],
    {},
    {1: 2},
    {'a': 'b', b'a': b'b'},
    {(1, 2): [3, 4]},
    {(1, (2, 3)): [4, 5]},
    FrozenDict( [(1, {3: 5})] ),
    FrozenDict( [(FrozenDict(a=(1, 2)), 3)] ),
    {FrozenDict(a='b'): 5},
    CBORSimple(0),
    CBORSimple(19),
    CBORSimple(32),
    CBORSimple(255),
    True,
    False,
    None,
    Undefined,
    [True, False, None, Undefined],
    1.0,
    1.1,
    math.inf,
    -math.inf,
    date(2004, 1, 29),
    datetime(2004, 1, 29, 1, 2, 3, 46, timezone.utc),
    datetime(1904, 1, 29, 1, 2, 3, 46, timezone(timedelta(seconds=60))),
    datetime(2004, 1, 29, 1, 2, 3, 46, timezone(timedelta(seconds=-60))),
    CBORTag(100, 'foo'),
    1_000_000_000_000_000_000_000_000_000,
    -1_000_000_000_000_000_000_000_000_000,
    Decimal('123.456'),
    Decimal('-67239582.9826398'),
    Decimal(math.inf),
    Decimal(-math.inf),
    Fraction(3, 8),
    Fraction(-1, 5),
    Fraction(61, -3),
    Fraction(-16, -9),
    # Frations explicitly admit bignums
    Fraction(1, 12345678901234567890123456789012345678901234567890123456789012345678901234567890),
    re.compile('.[0-9]+'),
    re.compile('.\\.\\\'\"'),
    UUID(hex='5eaffac8b51e480581277fdcc7842faf'),
    set([ 1, 2, "3", b'4', (5, 6), False, None, Undefined, True]),
    {frozenset([ 1, 2 ]): set([ 3, 4])},
    IPv4Address('192.10.10.1'),
    IPv6Address('32:193:56:77::2'),
    IPv4Network('0.0.0.0/0'),
    IPv4Network('192.168.0.100/24', strict=False),
    IPv6Network('2001:db8:85a3:0:0:8a2e::/96', strict=False),
))
def test_round_trip(value):
    encoding = dumps(value)
    result = loads(encoding)
    assert result == value


@pytest.mark.parametrize("value", [
    datetime(2004, 1, 29, 1, 2, 3, 46, timezone.utc),
    datetime(2004, 1, 29, 1, 2, 3, 46, timezone(timedelta(seconds=60))),
])
def test_timestamp_text_round_trip(value):
    encoding = dumps(value, datetime_style=CBORDateTimeStyle.ISO_WITH_Z)
    result = loads(encoding)
    assert result == value


def test_nan():
    assert math.isnan(loads(dumps(math.nan)))
