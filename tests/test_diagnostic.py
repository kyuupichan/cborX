import pytest

from cborx import *


tests = [
    ('00', '0'),
    ('1903e8', '1000'),
    ('38ff', '-256'),
    ('40', "h''"),
    ('4401020304', "h'01020304'"),
    ('5f ff', "(_ )"),
    ('5f 4474686520 46717569636b20 4662726f776e20 40 ff',
     "(_ h'74686520', h'717569636b20', h'62726f776e20', h'')"),
    ('60', '""'),
    ('7774686520717569636b2062726f776e20666f78206a756d', '"the quick brown fox jum"'),
    ('7f 6474686520 66717569636b20 6662726f776e20 60 6a666f78206a756d706564 ff',
     '(_ "the ", "quick ", "brown ", "", "fox jumped")'),
    ('80', '[]'),
    ('8301021821', '[1, 2, 33]'),
    ('830163666f6f83f940006362617280', '[1, "foo", [2.0, "bar", []]]'),
    ('a0', '{}'),
    ('a201020304', '{1: 2, 3: 4}'),
    ('a56161614161626142616361436164614461656145',
     '{"a": "A", "b": "B", "c": "C", "d": "D", "e": "E"}'),
    ('bfff', '{_ }'),
    ('bf61610161629f0203ffff', '{_ "a": 1, "b": [_ 2, 3]}'),
    ('bf0102ff', '{_ 1: 2}'),
    ('bf820102820304ff', '{_ (1, 2): [3, 4]}'),
    ('826161bf61626163ff', '["a", {_ "b": "c"}]'),
    ('bf6346756ef563416d7421ff', '{_ "Fun": true, "Amt": -2}'),
    ('c11a514b67b0', '1(1363896240)'),
    ('c1fb41d452d9ec200000', '1(1363896240.5)'),
    ('d74401020304', "23(h'01020304')"),
    ('d818456449455446', "24(h'6449455446')"),
    ('d82076687474703a2f2f7777772e6578616d706c652e636f6d', '32("http://www.example.com")'),
    ('e0', 'simple(0)'),
    ('f3', 'simple(19)'),
    ('85f5f4eff7f6', '[true, false, simple(15), undefined, null]'),
    ('f97c00', 'Infinity'),
    ('f9fc00', '-Infinity'),
    ('f97e00', 'NaN'),
]

@pytest.mark.parametrize("encoding, expected",
                         [(test[0], test[1]) for test in tests],
                         ids=[test[0] for test in tests])
def test_diagnostic(encoding, expected):
    sequence = streams_sequence(bytes.fromhex(encoding))
    result = ''.join(diagnostic_form(sequence))
    assert result == expected
