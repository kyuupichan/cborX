import math
from array import array
from collections import namedtuple, defaultdict, Counter, OrderedDict
from datetime import datetime, timedelta, timezone, date
from decimal import Decimal
from fractions import Fraction
from ipaddress import IPv4Address, IPv6Address, IPv4Network, IPv6Network
from uuid import UUID
import re

import pytest

from cborx import *
from cborx.packing import pack_byte, pack_be_uint16, pack_be_uint32


@pytest.mark.parametrize("value, encoding", (
    (0, bytes.fromhex('00')),
    (1, bytes.fromhex('01')),
    (10, bytes.fromhex('0a')),
    (23, bytes.fromhex('17')),
    (24, bytes.fromhex('1818')),
    (25, bytes.fromhex('1819')),
    (100, bytes.fromhex('1864')),
    (1000, bytes.fromhex('1903e8')),
    (1000000, bytes.fromhex('1a000f4240')),
    (1000000000000, bytes.fromhex('1b000000e8d4a51000')),
    (18446744073709551615, bytes.fromhex('1bffffffffffffffff')),
    (18446744073709551616, bytes.fromhex('c249010000000000000000')),
    (-18446744073709551616, bytes.fromhex('3bffffffffffffffff')),
    (-18446744073709551617, bytes.fromhex('c349010000000000000000')),
    (-1, bytes.fromhex('20')),
    (-10, bytes.fromhex('29')),
    (-100, bytes.fromhex('3863')),
    (-1000, bytes.fromhex('3903e7')),
))
def test_encode_int(value, encoding):
    e = CBOREncoder()
    assert e.encode(value) == encoding


@pytest.mark.parametrize("value, encoding", (
    (bytes.fromhex(''), bytes.fromhex('40')),
    (bytes.fromhex('01020304'), bytes.fromhex('4401020304')),
    (bytes.fromhex('01' * 23), bytes.fromhex('57' + '01' * 23)),
    (bytes.fromhex('01' * 24), bytes.fromhex('5818' + '01' * 24)),
))
def test_encode_bytes(value, encoding):
    e = CBOREncoder()
    assert e.encode(value) == encoding
    assert e.encode(bytearray(value)) == encoding
    assert e.encode(memoryview(value)) == encoding


@pytest.mark.parametrize("value, encoding", (
    ('', bytes.fromhex('60')),
    ('a', bytes.fromhex('6161')),
    ('IETF', bytes.fromhex('6449455446')),
    ('"\\', bytes.fromhex('62225c')),
    ('\u00fc', bytes.fromhex('62c3bc')),
    ('\u6c34', bytes.fromhex('63e6b0b4')),
    ('\ud800\udd51'.encode('utf-16', 'surrogatepass').decode('utf-16'),
     bytes.fromhex('64f0908591')),
))
def test_encode_string(value, encoding):
    e = CBOREncoder()
    assert e.encode(value) == encoding


@pytest.mark.parametrize("value, encoding", (
    ([], bytes.fromhex('80')),
    (tuple(), bytes.fromhex('80')),
    ([1, 2, 3], bytes.fromhex('83010203')),
    (tuple([1, 2, 3]), bytes.fromhex('83010203')),
    ([1, tuple([2, 3]), [4, 5]], bytes.fromhex('8301820203820405')),
    (list(range(1, 26)),
     bytes.fromhex('98190102030405060708090a0b0c0d0e0f101112131415161718181819')),
    (["a", {"b": "c"}], bytes.fromhex('826161a161626163')),
))
def test_encode_list(value, encoding):
    e = CBOREncoder()
    assert e.encode(value) == encoding


@pytest.mark.parametrize("value, encoding", (
    ({}, bytes.fromhex('a0')),
    ({1: 2, 3:4}, bytes.fromhex('a201020304')),
    ({"a": "A", "b": "B", "c": "C", "d": "D", "e": "E"},
     bytes.fromhex('a56161614161626142616361436164614461656145')),
))
def test_encode_dict(value, encoding):
    e = CBOREncoder()
    assert e.encode(value) == encoding


@pytest.mark.parametrize("value, encoding", (
    (False, b'\xf4'),
    (True, b'\xf5'),
    (None, b'\xf6'),
    (0.0, bytes.fromhex('f90000')),
    (-0.0, bytes.fromhex('f98000')),
    (1.0, bytes.fromhex('f93c00')),
    (1.1, bytes.fromhex('fb3ff199999999999a')),
    (1.5, bytes.fromhex('f93e00')),
    (65504.0, bytes.fromhex('f97bff')),
    (100000.0, bytes.fromhex('fa47c35000')),
    (3.4028234663852886e+38, bytes.fromhex('fa7f7fffff')),
    (1.0e+300, bytes.fromhex('fb7e37e43c8800759c')),
    (5.960464477539063e-8, bytes.fromhex('f90001')),
    (0.00006103515625, bytes.fromhex('f90400')),
    (-4.0, bytes.fromhex('f9c400')),
    (-4.1, bytes.fromhex('fbc010666666666666')),
    (math.inf, bytes.fromhex('f97c00')),
    (math.nan, bytes.fromhex('f97e00')),
    (-math.inf, bytes.fromhex('f9fc00')),
))
def test_encode_simple(value, encoding):
    e = CBOREncoder()
    assert e.encode(value) == encoding


def _indefinite_empty():
    yield from ()


def _indefinite_bytes():
    yield bytes(range(1, 3))
    yield bytearray(range(3, 6))
    yield memoryview(bytes(range(6, 8)))


def _indefinite_string():
    yield 'strea'
    yield 'ming'


def _indefinite_dict():
    yield 1, 'a'
    yield b'foo', 3


@pytest.mark.parametrize("value, encoding", (
    (CBORILByteString(iter(())), bytes.fromhex('5fff')),
    (CBORILByteString(_indefinite_bytes()), bytes.fromhex('5f42010243030405420607ff')),
    (CBORILTextString(iter(())), bytes.fromhex('7fff')),
    (CBORILTextString(_indefinite_string()), bytes.fromhex('7f657374726561646d696e67ff')),
    (CBORILList(iter(())), bytes.fromhex('9fff')),
    (CBORILList(iter((1, [2, 3], CBORILList(iter([4, 5]))))),
     bytes.fromhex('9f018202039f0405ffff')),
    (CBORILList(iter([1, [2, 3], [4, 5]])),
     bytes.fromhex('9f01820203820405ff')),
    ([1, [2, 3], CBORILList(iter([4,5]))],
     bytes.fromhex('83018202039f0405ff')),
    ([1, CBORILList(iter([2, 3])), [4, 5]],
     bytes.fromhex('83019f0203ff820405')),
    (CBORILList(range(1, 26)),
     bytes.fromhex('9f0102030405060708090a0b0c0d0e0f101112131415161718181819ff')),
    (CBORILDict(iter(())), bytes.fromhex('bfff')),
    (CBORILDict(iter([('a', 1), ('b', CBORILList(iter([2, 3])))])),
     bytes.fromhex('bf61610161629f0203ffff')),
    (CBORILDict(_indefinite_dict()),
     bytes.fromhex('bf01616143666f6f03ff')),
    (["a", CBORILDict(iter([('b', 'c')]))],
     bytes.fromhex('826161bf61626163ff')),
    (CBORILDict(iter([('Fun', True), ('Amt', -2)])),
     bytes.fromhex('bf6346756ef563416d7421ff')),
    (CBORUndefined(), b'\xf7'),
))
def test_encode_indefinite_length(value, encoding):
    o = CBOREncoderOptions(deterministic=False, sort_method=CBORSortMethod.UNSORTED)
    e = CBOREncoder(options=o)
    assert e.encode(value) == encoding


def test_undefined_singleton():
    assert CBORUndefined() is CBORUndefined()


def test_namedtuple():
    nt = namedtuple('nt', 'a b c')
    value = nt(1, 'bar', [1, 2])
    e = CBOREncoder()
    assert e.encode(value) == e.encode(tuple(value))


def test_defaultdict():
    d = defaultdict(list)
    d['foo'].append(4)
    d['foo'].append(3)
    d[2].append(1)
    e = CBOREncoder()
    assert e.encode(d) == e.encode({'foo': [3, 4], 2: [1]})


def test_counter():
    c = Counter(cats=4, dogs=8, bats=12)
    e = CBOREncoder()
    assert e.encode(c) == e.encode({'bats': 12, 'cats': 4, 'dogs': 8})


@pytest.mark.parametrize('sort_method, deterministic', [
    (CBORSortMethod.UNSORTED, False),
    (CBORSortMethod.LEXICOGRAPHIC, False),
    (CBORSortMethod.LEXICOGRAPHIC, True),
    (CBORSortMethod.LENGTH_FIRST, False),
    (CBORSortMethod.LENGTH_FIRST, True),
])
def test_ordered_dict(sort_method, deterministic):
    o = CBOREncoderOptions(sort_method=sort_method, deterministic=deterministic)
    e = CBOREncoder(o)
    c = OrderedDict()
    c['dogs'] = 8
    c['bats'] = 12
    c['cats'] = 4
    e = CBOREncoder()
    assert e.encode(c) == b'\xd9\x01\x10\xa3ddogs\x08dbats\x0cdcats\x04'


# Tests from https://github.com/agronholm/cbor2/
@pytest.mark.parametrize('value, style, expected', [
    (datetime(2013, 3, 21, 20, 4, 0, tzinfo=timezone.utc), CBORDateTimeStyle.ISO_WITH_Z,
     'c074323031332d30332d32315432303a30343a30305a'),
    (datetime(2013, 3, 21, 20, 4, 0, 380841, tzinfo=timezone.utc), CBORDateTimeStyle.ISO_WITH_Z,
     'c0781b323031332d30332d32315432303a30343a30302e3338303834315a'),
    (datetime(2013, 3, 21, 22, 4, 0, tzinfo=timezone(timedelta(hours=2))),
     CBORDateTimeStyle.ISO_WITH_Z,
     'c07819323031332d30332d32315432323a30343a30302b30323a3030'),
    (datetime(2013, 3, 21, 20, 4, 0, tzinfo=timezone.utc), CBORDateTimeStyle.ISO_WITHOUT_Z,
     'c07819323031332d30332d32315432303a30343a30302b30303a3030'),
    (datetime(2013, 3, 21, 20, 4, 0, 380841, tzinfo=timezone.utc), CBORDateTimeStyle.ISO_WITHOUT_Z,
     'c07820323031332d30332d32315432303a30343a30302e3338303834312b30303a3030'),
    (datetime(2013, 3, 21, 22, 4, 0, tzinfo=timezone(timedelta(hours=2))),
     CBORDateTimeStyle.ISO_WITHOUT_Z,
     'c07819323031332d30332d32315432323a30343a30302b30323a3030'),
    (datetime(2013, 3, 21, 20, 4, 0, tzinfo=timezone.utc), CBORDateTimeStyle.TIMESTAMP,
     'c11a514b67b0'),
    (datetime(2013, 3, 21, 20, 4, 0, 123456, tzinfo=timezone.utc), CBORDateTimeStyle.TIMESTAMP,
     'c1fb41d452d9ec07e6b4'),
    (datetime(2013, 3, 21, 22, 4, 0, tzinfo=timezone(timedelta(hours=2))),
     CBORDateTimeStyle.TIMESTAMP, 'c11a514b67b0')
], ids=[
    'datetimeZ/utc',
    'datetimeZ+micro/utc',
    'datetimeZ/eet',
    'datetime/utc',
    'datetime+micro/utc',
    'datetime/eet',
    'timestamp/utc',
    'timestamp+micro/utc',
    'timestamp/eet'
])
def test_datetime_explicit_tzinfo(value, style, expected):
    e = CBOREncoder(options=CBOREncoderOptions(datetime_style=style))
    result = e.encode(value)
    assert result == bytes.fromhex(expected)


@pytest.mark.parametrize('value, style, expected', [
    (datetime(2013, 3, 21, 20, 4, 0), CBORDateTimeStyle.ISO_WITH_Z,
     'c074323031332d30332d32315432303a30343a30305a'),
], ids=[
    'naive',
])
def test_datetime_enoder_tzinfo(value, style, expected):
    e = CBOREncoder(options=CBOREncoderOptions(datetime_style=style))
    with pytest.raises(CBOREncodingError):
        e.encode(value)
    e = CBOREncoder(options=CBOREncoderOptions(datetime_style=style, tzinfo=timezone.utc))
    result = e.encode(value)
    assert result == bytes.fromhex(expected)


@pytest.mark.parametrize('value, expected', [
    (date(2013, 3, 21), 'c06a323031332d30332d3231'),
    (date(1900, 2, 28), 'c06a313930302d30322d3238'),
])
def test_date(value, expected):
    e = CBOREncoder()
    result = e.encode(value)
    assert result == bytes.fromhex(expected)


@pytest.mark.parametrize('value, expected', [
    (Decimal('0'), 'c4820000'),
    (Decimal('0.0'), 'c4822000'),
    (Decimal('-0'), 'c4820000'),
    (Decimal('-0.0'), 'c4822000'),
    (Decimal('-1.15'), 'c482213872'),
    (Decimal('273.15'), 'c48221196ab3'),
    (Decimal('14.123'), 'c4822219372b'),
    (Decimal('-14.123'), 'c4822239372a'),
    (Decimal('235.7649538178625382398569286398758758232'),
     'c4823824c25106edb2c8ce1a9626c19c3a9efaf6b22758'),
    (Decimal('inf'), 'f97c00'),
    (Decimal('nan'), 'f97e00'),
    (Decimal('-inf'),'f9fc00'),
])
def test_date(value, expected):
    e = CBOREncoder()
    result = e.encode(value)
    assert result == bytes.fromhex(expected)


@pytest.mark.parametrize('value, expected', [
    (re.compile('[0-9]+"'), 'd823675b302d395d2b22'),
    (re.compile('hello (world)'), 'd8236d68656c6c6f2028776f726c6429'),
    (UUID(hex='5eaffac8b51e480581277fdcc7842faf'), 'd825505eaffac8b51e480581277fdcc7842faf'),
    (Fraction(2, 5), 'd81e820205'),
    (Fraction(-3, 5), 'd81e822205'),
    (Fraction(-8, -14), 'd81e820407'),
    (IPv4Address('192.168.1.5'), 'd9010444c0a80105'),
    (IPv4Address('192.10.10.1'), 'd9010444c00a0a01'),
    (IPv6Address('32:193:56:77::2'), 'd901045000320193005600770000000000000002'),
    (IPv6Address('2001:db8:85a3::8a2e:370:7334'), 'd901045020010db885a3000000008a2e03707334'),
    (IPv4Network('0.0.0.0/0'), 'd90105a1440000000000'),
    (IPv4Network('192.168.0.100/24', strict=False), 'd90105a144c0a800001818'),
    (IPv6Network('2001:db8:85a3:0:0:8a2e::/96', strict=False),
     'd90105a15020010db885a3000000008a2e000000001860'),
], ids = [
    'regex 1', 'regex 2',
    'UUID',
    'Fraction 1', 'Fraction 2', 'Fraction 3',
    'IPv4 1', 'IPv4 2', 'IPv6 1', 'IPv6 2', 'IPv4 Network 1', 'IPv4 Network 2', 'IPv6 Network',
])
def test_encodings(value, expected):
    e = CBOREncoder()
    result = e.encode(value).hex()
    assert result == expected


@pytest.mark.parametrize('value, sort_method, expected', [
    ({1, 2, 3}, CBORSortMethod.LEXICOGRAPHIC, 'd9010283010203'),
    ({1, 2, 3}, CBORSortMethod.LENGTH_FIRST, 'd9010283010203'),
    ({"abcd", 2, (5, 7)}, CBORSortMethod.LEXICOGRAPHIC, 'd90102 83 02 6461626364 820507'),
    ({"abcd", 2, (5, 7)}, CBORSortMethod.LENGTH_FIRST, 'd90102 83 02 820507 6461626364'),
    (frozenset((1, 2, 3)), CBORSortMethod.LEXICOGRAPHIC, 'd90102 83 010203'),
], ids = [
    'set 1LX', 'set 1LF', 'set 2LX', 'set 2LF', 'frozenset'
])
def test_set(value, sort_method, expected):
    o = CBOREncoderOptions(sort_method=sort_method, deterministic=False)
    e = CBOREncoder(o)
    result = e.encode(value)
    assert result == bytes.fromhex(expected)


def test_default_enconder_options():
    options = CBOREncoderOptions()
    assert options.datetime_style == CBORDateTimeStyle.TIMESTAMP
    assert options.tzinfo is None


@pytest.mark.parametrize('value, expected', [
    (array('b', [-1, 1]), 'd84842ff01'),
    (array('B', [3, 1]), 'd840420301'),
    (array('h', [-400, 400]), 'd84d4470fe9001'),
    (array('H', [1, 400]), 'd8454401009001'),
    (array('i', [-70000, 400]), 'd84e4890eefeff90010000'),
    (array('I', [1, 70000]), 'd846480100000070110100'),
    (array('q', [-1, 1]), 'd84f50ffffffffffffffff0100000000000000'),
    (array('Q', [1, 37]), 'd8475001000000000000002500000000000000'),
    (array('f', [-1.5, 3.25]), 'd855480000c0bf00005040'),
    (array('d', [-1.5, 3.25]), 'd85650000000000000f8bf0000000000000a40'),
], ids = [
    'b array', 'B array',
    'h array', 'H array',
    'i array', 'I array',
    'q array', 'Q array',
    'f array', 'd array',
])
def test_encodings(value, expected):
    e = CBOREncoder()
    result = e.encode(value).hex()
    assert result == expected


def test_array_fail():
    a = array('u', ['a'])
    e = CBOREncoder()
    with pytest.raises(CBOREncodingError):
        e.encode(a)


@pytest.mark.parametrize('value, expected', [
    (CBORSimple(0), 'e0'),
    (CBORSimple(22), 'f6'),
    (CBORSimple(23), 'f7'),
    (CBORSimple(31), 'ff'),
    (CBORSimple(32), 'f820'),
    (CBORSimple(255), 'f8ff'),
])
def test_simple(value, expected):
    e = CBOREncoder()
    result = e.encode(value).hex()
    assert result == expected

@pytest.mark.parametrize('value', [
    -1, 24, 25, 26, 27, 28, 29, 30, 256,
])
def test_simple_fail(value):
    with pytest.raises(ValueError):
        CBORSimple(value)


def test_deterministic():
    o = CBOREncoderOptions(deterministic=True)
    e = CBOREncoder(o)
    for n in range(0, 24):
        assert e.encode(n) == pack_byte(n)
    for n in range(-23, 0):
        assert e.encode(n) == pack_byte(0x20 + (-1 - n))
    for n in range(24, 256):
        assert e.encode(n) == b'\x18' + pack_byte(n)
    for n in range(-256, -24):
        assert e.encode(n) == b'\x38' + pack_byte(-1 - n)
    assert e.encode(256) == b'\x19' + pack_be_uint16(256)
    assert e.encode(65535) == b'\x19' + pack_be_uint16(65535)
    assert e.encode(-257) == b'\x39' + pack_be_uint16(256)
    assert e.encode(-65536) == b'\x39' + pack_be_uint16(65535)
    assert e.encode(65536) == b'\x1a' + pack_be_uint32(65536)
    assert e.encode(4294967295) == b'\x1a' + pack_be_uint32(4294967295)
    assert e.encode(-65537) == b'\x3a' + pack_be_uint32(65536)
    assert e.encode(-4294967296) == b'\x3a' + pack_be_uint32(4294967295)
    assert e.encode(1.5) == bytes.fromhex('f93e00')
    assert e.encode(1000000.5) == bytes.fromhex('fa49742408')


@pytest.mark.parametrize('value', [
    (2, 3, 4),
    (b'foo', b' ', b'bar'),
    ('foo', ' ', 'bar'),
    (('foo', 2), ('bar', -15)),
])
def test_deterministic_IL(value):
    o = CBOREncoderOptions(deterministic=True)
    e = CBOREncoder(o)
    if all(isinstance(item, bytes) for item in value):
        assert e.encode(CBORILByteString(iter(value))) == e.encode(b''.join(value))
    elif all(isinstance(item, str) for item in value):
        assert e.encode(CBORILTextString(iter(value))) == e.encode(''.join(value))
    elif all(isinstance(item, tuple) for item in value):
        assert e.encode(CBORILDict(iter(value))) == e.encode(
            {key: kvalue for key, kvalue in value})
    else:
        assert e.encode(CBORILList(iter(value))) == e.encode(value)


@pytest.mark.parametrize('method, value', [
    (CBORSortMethod.UNSORTED, '88626161617a1864812020811864f40a'),
    (CBORSortMethod.LEXICOGRAPHIC, '880a186420617a6261618118648120f4'),
    (CBORSortMethod.LENGTH_FIRST, '880a20f41864617a8120626161811864'),
])
def test_sorting(method, value):
    items = ['aa', 'z', 100, [-1], -1, [100], False, 10]
    o = CBOREncoderOptions(sort_method=method, deterministic=False)
    e = CBOREncoder(o)
    result = e.encode(items)
    assert result == bytes.fromhex(value)


@pytest.mark.parametrize('float_style, expected', [
    (CBORFloatStyle.SHORTEST, '85f93e00f97c00f97e00f9fc00fb4021cccccccccccd'),
    (CBORFloatStyle.DOUBLE, '85fb3ff8000000000000fb4021cccccccccccdfb7ff000'
     '0000000000fb7ff8000000000000fbfff0000000000000'),
])
def test_float_style(float_style, expected):
    items = [8.9, 1.5, math.inf, -math.inf, math.nan]
    o = CBOREncoderOptions(float_style=float_style)
    e = CBOREncoder(o)
    result = e.encode(items).hex()
    assert result == expected
