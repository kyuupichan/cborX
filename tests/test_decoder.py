from collections import OrderedDict
from io import BytesIO
import math
import re

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
    (18446744073709551616, 'c249010000000000000000'),
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


@pytest.mark.parametrize("encoding, expected", (
    # [b'the ', b'quick ', b'brown ', b'', b'fox jumped']
    ('5f 4474686520 46717569636b20 4662726f776e20 40 4a666f78206a756d706564 ff',
     b'the quick brown fox jumped'),
    # [b'the'] encoded non-minimally
    ('5f 5803 746865ff', b'the'),
    ('5f 590003 746865ff', b'the'),
    ('5f 5a00000003 746865ff', b'the'),
    ('5f 5b0000000000000003 746865ff', b'the'),
))
def test_decode_indefinite_length_byte_string(encoding, expected):
    result = loads(bytes.fromhex(encoding))
    assert result == expected


@pytest.mark.parametrize("encoding, expected", (
    # ['the ', 'quick ', 'brown ', '', 'fox jumped']
    ('7f 6474686520 66717569636b20 6662726f776e20 60 6a666f78206a756d706564 ff',
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
    with pytest.raises(StringEncodingError):
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
def test_decode_text_string(value, encoding):
    result = loads(bytes.fromhex(encoding))
    assert result == value


@pytest.mark.parametrize("value, encoding", (
    ([], '80'),
    ([1, 2, 33], '8301021821'),
    ([[[1], 2, 3], 4, 5], '8383810102030405'),
))
def test_decode_list(value, encoding):
    result = loads(bytes.fromhex(encoding))
    assert result == value


@pytest.mark.parametrize("value, expected", (
    (CBORILList(iter(())), []),
    (CBORILList(iter((1, [2, 3], CBORILList(iter([4, 5]))))), [1, [2, 3], [4, 5]]),
    ([1, CBORILList(iter([2, 3])), [4, 5]], [1, [2, 3], [4, 5]]),
))
def test_decode_indefinite_length_list(value, expected):
    encoding = dumps(value, sort_method=CBORSortMethod.UNSORTED, realize_il=False)
    result = loads(encoding)
    assert result == expected


@pytest.mark.parametrize("value, expected", (
    (CBORILDict(iter(())), {}),
    (CBORILDict(iter( [(1, 2)] )), {1 : 2}),
    (CBORILDict(iter( [((1, 2), (3, 4))])), {(1, 2): [3, 4]}),
))
def test_decode_indefinite_length_dict(value, expected):
    encoding = dumps(value, sort_method=CBORSortMethod.UNSORTED, realize_il=False)
    result = loads(encoding)
    assert result == expected


@pytest.mark.parametrize("encoding, expected", [
    ('e0', CBORSimple(0)),
    ('f3', CBORSimple(19)),
    ('f4', False),
    ('f5', True),
    ('f6', None),
    ('f7', Undefined),
    ('f820', CBORSimple(32)),
    ('f8ff', CBORSimple(255)),
    ('fb4021cccccccccccd', 8.9),
    ('f93e00', 1.5),
    ('f97c00', math.inf),
    ('f9fc00', -math.inf),
    ('fa3fc00000', 1.5),
    ('fa7f800000', math.inf),
    ('faff800000', -math.inf),
    ('fb3ff8000000000000', 1.5),
    ('fb7ff0000000000000', math.inf),
    ('fbfff0000000000000', -math.inf),
])
def test_decode_simple(encoding, expected):
    result = loads(bytes.fromhex(encoding))
    assert result == expected


@pytest.mark.parametrize("encoding", ['f97e00', 'fa7fc00000', 'fb7ff8000000000000'])
def test_decode_nan(encoding):
    assert math.isnan(loads(bytes.fromhex(encoding)))


@pytest.mark.parametrize("encoding", [
    'ff',
    '8301ff03',
    'a1ff',
    'a100ff',
    'bf00ff',
], ids = [
    'lone break',
    'definite length list',
    'definite map key',
    'definite map value',
    'indefinite map value',
])
def test_misplaced_break(encoding):
    with pytest.raises(MisplacedBreakError):
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
def test_bad_il_text_string(encoding):
    with pytest.raises(BadInitialByteError, match='bad initial byte 0x'):
        loads(bytes.fromhex(encoding))


@pytest.mark.parametrize("encoding, match", [
    ('a201020102', '1 duplicate keys: 1'),   # { 1:2, 1:2}
    ('a501020203020406020102', '2 duplicate keys: '),   # { 1:2, 2:3, 2: 4, 6: 2, 1: 2}
    ('bf6161010000616102ff', " duplicate keys: 'a'"),   # {_ 'a': 1, 0:0, 'a': 2 }
])
def test_duplicate_keys(encoding, match):
    with pytest.raises(DuplicateKeyError, match=match):
        loads(bytes.fromhex(encoding))


def test_duplicate_keys_int_vs_bignum():
    '''Test we get a DuplicateKeyError if and only if we collapse bignums.'''
    # dumps({BigNum(0): 0, 0:0}).hex()
    encoding = 'a20000c24000'
    assert loads(bytes.fromhex(encoding), retain_bignums=True) == {BigNum(0): 0, 0:0}
    with pytest.raises(DuplicateKeyError):
        loads(bytes.fromhex(encoding), retain_bignums=False)


@pytest.mark.parametrize("encoding", [
    '5f01ff',      # _ 1
    '5f616101ff',  # _ 'a' 1
    '5f20ff',      # _ -1
    '5f60ff',      # _ ''
    '5f5cff',      # _ reserved
    '5f5dff',      # _ reserved
    '5f5eff',      # _ reserved
    '5f5fff',      # _ IL byte string
    '5f80ff',      # _ []
    '5fa0ff',      # _ []
    '5fc0ff',      # _ Tag0
    '5fe0ff',      # _ Simple(0)
], ids = [
    '1',
    'a 1',
    '-1',
    "''",
    'reserved 1',
    'reserved 2',
    'reserved 3',
    'IL byte string',
    '[]',
    '{}',
    'tag-0',
    'simple-0',
])
def test_bad_il_byte_string(encoding):
    with pytest.raises(BadInitialByteError, match='in indefinite-length byte string'):
        loads(bytes.fromhex(encoding))


@pytest.mark.parametrize("encoding", [
    '1c', '1d', '1e', '1f',
    '3c', '3d', '3e', '3f',
    '5c', '5d', '5e',
    '7c', '7d', '7e',
    '9c', '9d', '9e',
    'bc', 'bd', 'be',
    # 'dc', 'dd', 'de', 'df',
    'fc', 'fd', 'fe',
])
def test_unassigned(encoding):
    with pytest.raises(BadInitialByteError, match='bad initial byte 0x'):
        loads(bytes.fromhex(encoding))


@pytest.mark.parametrize("encoding", [
    '18', '1900', '1a000000', '1b00000000000000',  # length truncated
    '38', '3900', '3a000000', '3b00000000000000',  # length truncated
    '58', '5900', '5a000000', '5b00000000000000',  # length truncated
    '5801', '590001', '5a00000001', '5b0000000000000001',  # payload truncated
    '5f',   # missing byte string
    '78', '7900', '7a000000', '7b00000000000000',  # length truncated
    '7801', '790001', '7a00000001', '7b0000000000000001',  # payload truncated
    '7f',   # missing text string
    '98', '9900', '9a000000', '9b00000000000000',
    '9801', '990001', '9a00000001', '9b0000000000000001',  # missing item
    '9f',   # missing item
    'b8', 'b900', 'ba000000', 'bb00000000000000',
    'b801', 'b90001', 'ba00000001', 'bb0000000000000001',  # missing key-value pair
    'b80100', 'b9000100', 'ba0000000100', 'bb000000000000000100',  # missing value
    'bf',   'bf00',
    'f8',  # missing payload
])
def test_truncated(encoding):
    with pytest.raises(UnexpectedEOFError, match='need '):
        loads(bytes.fromhex(encoding))


@pytest.mark.parametrize("encoding, match", [
    ('c06161', 'invalid date and time text'),
    ('d81d05', 'non-existent shared reference'),
    ('d90102d81c81d81d00', 'non-existent shared reference'),
    ('d9010443c00a0a', 'invalid IP address'),
    ('d81e820100', 'rational has zero denominator'),
    ('d90105a24400000000000000', 'IP network must be encoded as a single-entry map'),
    ('d90105a1440000000020', 'invalid IP network'),
])
def test_tagged_value_error(encoding, match):
    with pytest.raises(TagValueError, match=match):
        loads(bytes.fromhex(encoding))


@pytest.mark.parametrize("encoding, match", [
    ('c000', 'date and time is not text'),
    ('c140', 'timestamp is not a plain integer or float'),
    ('c160', 'timestamp is not a plain integer or float'),
    # Bignum not permitted as timestamp
    ('c1c240', 'timestamp is not a plain integer or float'),
    ('c200', 'bignum payload must be a byte string'),
    ('c300', 'bignum payload must be a byte string'),
    ('c48102', 'decimal must be encoded'),
    ('c483020202', 'decimal must be encoded as'),
    ('c40000', 'decimal must be encoded as'),
    ('c4820040', 'decimal has an invalid mantissa'),
    ('c4824040', 'decimal has an invalid exponent b\'\''),
    ('c482c24001', 'decimal has an invalid exponent BigNum\\(value=0\\)'),
    ('c58102', 'bigfloat must be encoded'),
    ('c583020202', 'bigfloat must be encoded as'),
    ('c50000', 'bigfloat must be encoded as'),
    ('c5820040', 'bigfloat has an invalid mantissa'),
    ('c5824040', 'bigfloat has an invalid exponent b\'\''),
    ('c582c24000', 'bigfloat has an invalid exponent BigNum\\(value=0\\)'),
    ('d81e8102', 'rational must be encoded'),
    ('d81e83020202', 'rational must be encoded as'),
    ('d81e0000', 'rational must be encoded as'),
    ('d81e824040', 'rational must be encoded as'),
    ('d8234102', 'regexp must be encoded as a text string'),
    ('d82500', 'UUID must be encoded as a byte string'),
    ('d9010200', 'set must be encoded as a list'),
    ('d9010400', 'IP address must be encoded as a byte string'),
    ('d9010500',' IP network must be encoded as a map'),
    ('d90105a144c0a80064420102', 'invalid IP network'),
    ('d9011080', 'ordered map not encoded as a map'),
    ('d81d60', 'shared reference must be an integer'),
    ('d81d80', 'shared reference must be an integer'),
    ('d845820102', 'array must be encoded as a byte string'),
])
def test_tagged_type_error(encoding, match):
    with pytest.raises(TagTypeError, match=match):
        loads(bytes.fromhex(encoding))


def test_invalid_regexp():
    encoding = 'd823625b5d'
    with pytest.raises(re.error):
        loads(bytes.fromhex(encoding))


def test_unknown_tag():
    encoding = 'd9032063746167'  # Unknown tag 800 with payload text string "tag"
    value = loads(bytes.fromhex(encoding))
    assert value == CBORTag(800, 'tag')


def test_decode_set():
    encoding = 'd90102 80'
    # assert it's a set not a frozenset
    assert isinstance(loads(bytes.fromhex(encoding)), set)


def test_custom_tag_decoder():
    def tag_800_handler(decoder, tag_value):
        assert isinstance(decoder, CBORDecoder)
        assert tag_value == 800
        return decoder.decode_item()[-1]

    # dumps([CBORTag(800, 'tag'), CBORTag(800, 'tab')]).hex()
    encoding = '82d9032063746167d9032063746162'
    value = loads(bytes.fromhex(encoding), tag_decoders = {800: tag_800_handler})
    assert value == ['g', 'b']


def test_ordered_flag():
    od = OrderedDict(a={1: 2})
    encoding = dumps(od)
    result = loads(encoding)
    for item in result.values():
        assert not isinstance(item, OrderedDict)


def test_non_shared_strings():
    a = 'bar'
    pair = [a, a]
    encoding = dumps(pair)
    assert encoding.hex() == '826362617263626172'
    result = loads(encoding)
    assert result == pair
    assert result[0] is not result[1]


def test_shared_strings():
    a = 'bar'
    pair = [a, a]
    encoding = dumps(pair, shared_types={str})
    assert encoding.hex() == '82d81c63626172d81d00'
    result = loads(encoding)
    assert result == pair
    assert result[0] is result[1]


def test_shared_lists():
    a = [1, 2, "bar"]
    pair = [a, a, a]
    encoding = dumps(pair, shared_types={list})
    result = loads(encoding)
    assert result == pair
    assert result[0] is result[1] and result[1] is result[2]


def test_shared_ints():
    # Tests the clearing of _pending_id in decode_shared
    a = [1, [1, 2], 1]
    encoding = dumps(a, shared_types={int})
    result = loads(encoding)
    assert result == a


def test_shared_immutable():
    # Another testcase from cbor2
    # a = (1, 2, 3)
    # b = ((a, a), a)
    # A non-canonical encoding for set(b)
    encoding = bytes.fromhex('d90102d81c82d81c82d81c83010203d81d02d81d02')
    result = loads(encoding)
    assert isinstance(result, set)
    assert len(result) == 2
    a = [item for item in result if len(item) == 3][0]
    b = [item for item in result if len(item) == 2][0]
    assert a is b[0] and a is b[1]


def test_cyclic_list():
    a = [1, 2]
    a.append(a)
    encoding = dumps(a, shared_types={list})
    result = loads(encoding)
    assert len(result) == 3
    assert result[2] == result


def test_cyclic_il_list():
    # Tests encoding and decoding of a self-referencing indefinite-length list
    a = [1, 2]
    il_list = CBORILList(a)
    a.append(il_list)
    encoding = dumps(il_list, shared_types={CBORILList}, realize_il=False)
    result = loads(encoding)
    assert isinstance(result, list)
    assert len(result) == 3
    assert result[0] == 1
    assert result[1] == 2
    assert result[2] is result


def test_cyclic_dict():
    a = {1: 2}
    a[3] = a
    encoding = dumps(a, shared_types={dict})
    result = loads(encoding)
    assert len(result) == 2
    assert result[3] is result


def test_cyclic_ordered_dict():
    a = OrderedDict([(1,2)])
    a[3] = a
    encoding = dumps(a, shared_types={OrderedDict})
    result = loads(encoding)
    assert len(result) == 2
    assert result[3] is result


def test_cyclic_complex():
    a = [1, 2]
    b = {'a': [a]}
    a.append(b)
    encoding = dumps(a, shared_types={list})
    result = loads(encoding)
    assert len(result) == 3
    assert result[2]['a'][0] is result


@pytest.mark.parametrize("retain, cls", [
    (True, BigNum),
    (False, int),
])
def test_retain_bignums(retain, cls):
    value = loads(bytes.fromhex('c240'), retain_bignums=retain)
    assert isinstance(value, cls)


@pytest.mark.parametrize("encoding", ['f800', 'f81f'])
def test_invalid_simple(encoding):
    with pytest.raises(BadSimpleError, match='simple value 0x'):
        loads(bytes.fromhex(encoding))


def my_simple_value(value):
    if value == 2:
        return Ellipsis
    if value == 44:
        return all
    return CBORSimple(value)


@pytest.mark.parametrize("value, result", [
    (0, CBORSimple(0)),
    (2, Ellipsis),
    (41, CBORSimple(41)),
    (44, all),
])
def test_simple_value(value, result):
    encoding = dumps(CBORSimple(value))
    assert loads(encoding, simple_value=my_simple_value) == result


@pytest.mark.parametrize("encoding, deterministic, match", [
    ('1817', DeterministicFlags.LENGTH, 'value 23 is not minimally encoded'),
    ('3817', DeterministicFlags.LENGTH, 'value -24 is not minimally encoded'),
    ('5817', DeterministicFlags.LENGTH, 'length 23 is not minimally encoded'),
    ('7817', DeterministicFlags.LENGTH, 'length 23 is not minimally encoded'),
    ('9817', DeterministicFlags.LENGTH, 'length 23 is not minimally encoded'),
    ('b817', DeterministicFlags.LENGTH, 'length 23 is not minimally encoded'),
    ('d817', DeterministicFlags.LENGTH, 'length 23 is not minimally encoded'),
    ('1a0000ffff', DeterministicFlags.LENGTH, 'value 65,535 is not minimally encoded'),
    ('3a0000ffff', DeterministicFlags.LENGTH, 'value -65,536 is not minimally encoded'),
    ('5a0000ffff', DeterministicFlags.LENGTH, 'length 65,535 is not minimally encoded'),
    ('7a0000ffff', DeterministicFlags.LENGTH, 'length 65,535 is not minimally encoded'),
    ('9a0000ffff', DeterministicFlags.LENGTH, 'length 65,535 is not minimally encoded'),
    ('ba0000ffff', DeterministicFlags.LENGTH, 'length 65,535 is not minimally encoded'),
    ('da0000ffff', DeterministicFlags.LENGTH, 'length 65,535 is not minimally encoded'),
    ('1b00000000ffffffff', DeterministicFlags.LENGTH,
     'value 4,294,967,295 is not minimally encoded'),
    ('3b00000000ffffffff', DeterministicFlags.LENGTH,
     'value -4,294,967,296 is not minimally encoded'),
    ('5b0000000000000000', DeterministicFlags.LENGTH,
     'length 0 is not minimally encoded'),
    ('7b0000000000000000', DeterministicFlags.LENGTH,
     'length 0 is not minimally encoded'),
    ('9b0000000000000000', DeterministicFlags.LENGTH,
     'length 0 is not minimally encoded'),
    ('bb0000000000000000', DeterministicFlags.LENGTH,
     'length 0 is not minimally encoded'),
    ('db0000000000000000', DeterministicFlags.LENGTH,
     'length 0 is not minimally encoded'),
])
def test_non_deterministic(encoding, deterministic, match):
    with pytest.raises(DeterministicError, match=match):
        loads(bytes.fromhex(encoding), deterministic=deterministic)

@pytest.mark.parametrize("encoding, bad", [
    # This must raise a BadSimpleError as that is ill-formed, not just invalid
    ('f817', True),
    # These are floats
    ('fa0000ffff', False),
    ('fb0000000000000000', False),
])
def test_non_deterministic_simples(encoding, bad):
    if bad:
        with pytest.raises(BadSimpleError):
            loads(bytes.fromhex(encoding), deterministic=DeterministicFlags.LENGTH)
    else:
        loads(bytes.fromhex(encoding), deterministic=DeterministicFlags.LENGTH)


def test_check_eof_false():
    assert loads(bytes(2), check_eof=False) == 0


def test_check_eof_true():
    with pytest.raises(UnconsumedDataError):
        loads(bytes(2), check_eof=True)


@pytest.mark.parametrize("cls", [bytearray, memoryview])
def test_loads_special(cls):
    assert loads(cls(bytes.fromhex('6449455446'))) == 'IETF'


def test_load():
    value = BytesIO(bytes.fromhex('6449455446'))
    assert load(value) == 'IETF'
