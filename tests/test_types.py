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

    b = FrozenDict(([1, 2], [3, 4]))
    assert a == b

    b = dict(([1, 2], [3, 4]))
    assert a == b


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


def test_simple_equality():
    assert CBORSimple(0) == CBORSimple(0)
    assert CBORSimple(0) != CBORSimple(1)
