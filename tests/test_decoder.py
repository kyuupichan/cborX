import pytest

from cborx import *


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
    result = loads(bytes.fromhex(encoding))
    assert result == value


@pytest.mark.parametrize("value, encoding", (
    ('', '40'),
    ('01020304', '4401020304'),
    ('01' * 23, '57' + '01' * 23),
    ('01' * 24, '5818' + '01' * 24),
))
def test_decode_byte_string(value, encoding):
    result = loads(bytes.fromhex(encoding))
    assert result == bytes.fromhex(value)


def test_decode_indefinite_length_byte_string():
    parts = [b'the ', b'quick ', b'brown ', b'', b'fox jumped']
    encoding = CBOREncoder().encode(CBORILByteString(iter(parts)))
    result = loads(encoding)
    assert result == b''.join(parts)


@pytest.mark.parametrize("encoding, expected", (
    # ['the ', 'quick ', 'brown ', '', 'fox jumped']
    ('7f647468652066717569636b206662726f776e20606a666f78206a756d706564ff',
     'the quick brown fox jumped'),
    # ['the'] encoded non-minimally
    ('7f 7803 746865ff', 'the'),
    ('7f 790003 746865ff', 'the'),
    ('7f 7a00000003 746865ff', 'the'),
    ('7f 7b0000000000000003 746865ff', 'the'),
))
def test_decode_indefinite_length_text_string(encoding, expected):
    result = loads(bytes.fromhex(encoding))
    assert result == expected


def test_decode_indefinite_length_text_string_split_utf8():
    with pytest.raises(UnicodeDecodeError):
        loads(bytes.fromhex('7f 61e3 628182 ff'))


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
    result = loads(bytes.fromhex(encoding))
    assert result == value


def test_loads_bytearray():
    assert loads(bytearray(bytes.fromhex('6449455446'))) == 'IETF'


def test_loads_memoryview():
    assert loads(memoryview(bytes.fromhex('6449455446'))) == 'IETF'


@pytest.mark.parametrize("encoding", [
    'ff',
    '8301ff03',
], ids = [
    'lone break',
    'definite length list',
])
def test_misplaced_break(encoding):
    with pytest.raises(CBORDecodingError, match='0xff'):
        loads(bytes.fromhex(encoding))


@pytest.mark.parametrize("encoding", [
    '7f01ff',      # _ 1
    '7f616101ff',  # _ 'a' 1
    '7f20ff',      # _ -1
    '7f40ff',      # _ b''
    '7f7cff',      # _ reserved
    '7f7dff',      # _ reserved
    '7f7eff',      # _ reserved
    '7f7fff',      # _ IL string
    '7f80ff',      # _ []
    '7fa0ff',      # _ []
    '7fc0ff',      # _ Tag0
    '7fe0ff',      # _ Simple(0)
], ids = [
    '1',
    'a 1',
    '-1',
    "b''",
    'reserved 1',
    'reserved 2',
    'reserved 3',
    'IL string',
    '[]',
    '{}',
    'tag-0',
    'simple-0',
])
def test_bad_il_teststring(encoding):
    with pytest.raises(CBORDecodingError, match='invalid in indefinite-length'):
        loads(bytes.fromhex(encoding))
