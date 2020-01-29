import pytest

from cborx import *
from io import BytesIO


@pytest.mark.parametrize("value, encoding", (
    (0, '00'),
    (1, '01'),
    (10, '0a'),
    (23, '17'),
    (24, '1818'),
    (25, '1819'),
    (100, '1864'),
    (1000, '1903e8'),
    (1000000, '1a000f4240'),
    (1000000000000, '1b000000e8d4a51000'),
    (18446744073709551615, '1bffffffffffffffff'),
    (-18446744073709551616, '3bffffffffffffffff'),
    (-1, '20'),
    (-10, '29'),
    (-100, '3863'),
    (-1000, '3903e7'),
))
def test_decode_int(value, encoding):
    read = BytesIO(bytes.fromhex(encoding)).read
    result = loads(read)
    assert result == value


@pytest.mark.parametrize("value, encoding", (
    ('', '40'),
    ('01020304', '4401020304'),
    ('01' * 23, '57' + '01' * 23),
    ('01' * 24, '5818' + '01' * 24),
))
def test_decode_bytes(value, encoding):
    read = BytesIO(bytes.fromhex(encoding)).read
    result = loads(read)
    assert result == bytes.fromhex(value)


@pytest.mark.parametrize("value, encoding", (
    ('', '60'),
    ('a', '6161'),
    ('IETF', '6449455446'),
    ('"\\', '62225c'),
    ('\u00fc', '62c3bc'),
    ('\u6c34', '63e6b0b4'),
    ('\ud800\udd51'.encode('utf-16', 'surrogatepass').decode('utf-16'), '64f0908591'),
))
def test_decode_string(value, encoding):
    read = BytesIO(bytes.fromhex(encoding)).read
    result = loads(read)
    assert result == value
