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
