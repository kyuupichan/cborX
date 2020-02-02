from decimal import Decimal

import pytest

from cborx import *


def test_FrozenDict():
    a = FrozenDict(([1, 2], [3, 4]))
    assert a[1] == 2
    assert a[3] == 4
    assert len(a) == 2
    assert 1 in a
    assert not 2 in a
    assert 3 in a
    assert list(a) == [1, 3]
    assert list(a.keys()) == [1, 3]
    assert list(a.values()) == [2, 4]
    assert list(a.items()) == [(1, 2), (3, 4)]
    assert repr(a) == '''<FrozenDict {1: 2, 3: 4}>'''

    b = FrozenDict(([1, 2], [3, 4]))
    assert a == b

    b = dict(([1, 2], [3, 4]))
    assert a == b


def test_FrozenOrderedDict():
    a = FrozenOrderedDict(([1, 2], [3, 4]))
    assert a[1] == 2
    assert a[3] == 4
    assert len(a) == 2
    assert 1 in a
    assert not 2 in a
    assert 3 in a
    assert list(a) == [1, 3]
    assert list(a.keys()) == [1, 3]
    assert list(a.values()) == [2, 4]
    assert list(a.items()) == [(1, 2), (3, 4)]

    b = FrozenOrderedDict(([1, 2], [3, 4]))
    assert a == b
    b = FrozenDict(([1, 2], [3, 4]))
    assert a == b

    b = dict(([1, 2], [3, 4]))
    assert a == b

    a = FrozenOrderedDict([('b', 1), ('a', 2)])
    assert list(a.keys()) == ['b', 'a']


def test_CBORTag():
    a = CBORTag(1, 'foo')
    b = CBORTag(2, 'bar')
    c = CBORTag(1, 'foo')

    assert a < b
    assert a <= b
    assert b > a
    assert b >= a
    assert a == a
    assert c == a
    assert b != a
    assert c != b

    assert repr(a) == "CBORTag(tag=1, value='foo')"

    with pytest.raises(TypeError, match='must be an integer'):
        CBORTag(2.0, 'foo')

    with pytest.raises(ValueError):
        CBORTag(-1, 'foo')

    with pytest.raises(ValueError):
        CBORTag(1 << 64, 'foo')


def test_Undefined():
    assert repr(Undefined) == 'Undefined'


def test_BigFloat():
    a = BigFloat(2, 3)
    b = BigFloat(2, 3)
    c = BigFloat(3, -6)

    assert a == b
    assert a != c
    assert repr(a) == 'BigFloat(mantissa=2, exponent=3)'

    with pytest.raises(TypeError):
        a < b

    assert a.to_decimal() == Decimal(16)
    assert c.to_decimal() == Decimal(0.046875)


@pytest.mark.parametrize("value", [0, 1, 15, 19, 32, 128, 255])
def test_simple(value):
    assert CBORSimple(value) == CBORSimple(value)


@pytest.mark.parametrize("value", [-1, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31])
def test_simple_value(value):
    with pytest.raises(ValueError, match='out of range'):
        CBORSimple(value)


@pytest.mark.parametrize("value", [1.0, '', b''])
def test_simple_type(value):
    with pytest.raises(TypeError, match='must be an integer'):
        CBORSimple(value)


def test_CBORSimple():
    a = CBORSimple(3)
    b = CBORSimple(4)
    c = CBORSimple(3)

    assert not a is c
    assert a < b
    assert a <= b
    assert b > a
    assert b >= a
    assert a == a
    assert c == a
    assert b != a
    assert c != b

    assert repr(a) == "CBORSimple(value=3)"

    with pytest.raises(TypeError, match='must be an integer'):
        CBORSimple(3.0)

    for n in (-1, 256) + tuple(range(20, 32)):
        with pytest.raises(ValueError):
            CBORSimple(n)


def test_simple_equality():
    assert CBORSimple(0) == CBORSimple(0)
    assert CBORSimple(0) != CBORSimple(1)
