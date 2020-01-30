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
    FrozenDict( [(1, {3: 5})] ),
    {FrozenDict(a='b'): 5},
))
def test_encode_int(value):
    encoding = CBOREncoder().encode(value)
    result = loads(encoding)
    assert result == value
