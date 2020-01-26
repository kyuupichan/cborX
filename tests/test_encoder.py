import math

import pytest

from cborx import *


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
    (IndefiniteLengthByteString(iter(())), bytes.fromhex('5fff')),
    (IndefiniteLengthByteString(_indefinite_bytes()), bytes.fromhex('5f42010243030405420607ff')),
    (IndefiniteLengthTextString(iter(())), bytes.fromhex('7fff')),
    (IndefiniteLengthTextString(_indefinite_string()), bytes.fromhex('7f657374726561646d696e67ff')),
    (IndefiniteLengthList(iter(())), bytes.fromhex('9fff')),
    (IndefiniteLengthList(iter((1, [2, 3], IndefiniteLengthList(iter([4, 5]))))),
     bytes.fromhex('9f018202039f0405ffff')),
    (IndefiniteLengthList(iter([1, [2, 3], [4, 5]])),
     bytes.fromhex('9f01820203820405ff')),
    ([1, [2, 3], IndefiniteLengthList(iter([4,5]))],
     bytes.fromhex('83018202039f0405ff')),
    ([1, IndefiniteLengthList(iter([2, 3])), [4, 5]],
     bytes.fromhex('83019f0203ff820405')),
    (IndefiniteLengthList(range(1, 26)),
     bytes.fromhex('9f0102030405060708090a0b0c0d0e0f101112131415161718181819ff')),
    (IndefiniteLengthDict(iter(())), bytes.fromhex('bfff')),
    (IndefiniteLengthDict(iter([('a', 1), ('b', IndefiniteLengthList(iter([2, 3])))])),
     bytes.fromhex('bf61610161629f0203ffff')),
    (IndefiniteLengthDict(_indefinite_dict()),
     bytes.fromhex('bf01616143666f6f03ff')),
    (["a", IndefiniteLengthDict(iter([('b', 'c')]))],
     bytes.fromhex('826161bf61626163ff')),
    (IndefiniteLengthDict(iter([('Fun', True), ('Amt', -2)])),
     bytes.fromhex('bf6346756ef563416d7421ff')),
))
def test_encode_indefinite_length(value, encoding):
    e = CBOREncoder()
    assert e.encode(value) == encoding
