import pytest

from cborx import *
from io import BytesIO


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
))
def test_encode_int(value):
    encoding = CBOREncoder().encode(value)
    read = BytesIO(encoding).read
    result = loads(read)
    assert result == value
