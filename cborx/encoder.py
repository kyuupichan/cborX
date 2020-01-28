# Copyright (c) 2020, Neil Booth
#
# All rights reserved.
#
# The MIT License (MIT)
#
# Permission is hereby granted, free of charge, to any person obtaining
# a copy of this software and associated documentation files (the
# "Software"), to deal in the Software without restriction, including
# without limitation the rights to use, copy, modify, merge, publish,
# distribute, sublicense, and/or sell copies of the Software, and to
# permit persons to whom the Software is furnished to do so, subject to
# the following conditions:
#
# The above copyright notice and this permission notice shall be
# included in all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
# EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
# MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
# NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
# LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
# OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
# WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

'''CBOR encoding.'''

import re
from array import array
from collections import OrderedDict
from datetime import datetime, date
from decimal import Decimal
from enum import IntEnum
from fractions import Fraction
from functools import partial
from ipaddress import IPv4Address, IPv6Address, IPv4Network, IPv6Network
from uuid import UUID

from cborx.packing import (
    pack_byte, pack_be_uint16, pack_be_uint32, pack_be_uint64,
    pack_be_float2, pack_be_float4, pack_be_float8, unpack_be_float2, unpack_be_float4
)
from cborx.types import CBORTag, CBOREncodingError, CBORSimple

# TODO:
#
# - canonical encoding
# - recursive objects
# - semantic tagging to force e.g. a particular float representation
# - embedded CBOR data item
# - streaming API

bjoin = b''.join


class CBORDateTimeStyle(IntEnum):
    TIMESTAMP = 0
    ISO_WITH_Z = 1
    ISO_WITHOUT_Z = 2


class CBORFloatStyle(IntEnum):
    SHORTEST = 0
    DOUBLE = 1


class CBORSortMethod(IntEnum):
    LEXICOGRAPHIC = 0      # draft-ietf-cbor-7049bis-12
    LENGTH_FIRST = 1       # RFC 7049
    UNSORTED = 2


def sorted_pairs(pairs_gen, method):
    '''Return an iterable sorting the pairs according to method.'''
    if method == CBORSortMethod.LEXICOGRAPHIC:
        return sorted(pairs_gen)
    elif method == CBORSortMethod.LENGTH_FIRST:
        return sorted(pairs_gen, key=lambda k, v: (len(k), k))
    else:
        return pairs_gen


def sorted_items(encoded_items_gen, method):
    '''Return an iterable sorting the items according to method.'''
    if method == CBORSortMethod.LEXICOGRAPHIC:
        return sorted(encoded_items_gen)
    elif method == CBORSortMethod.LENGTH_FIRST:
        return sorted(encoded_items_gen, key=lambda item: (len(item), item))
    else:
        return encoded_items_gen


class CBOREncoderOptions:
    '''Controls encoder behaviour.'''

    def __init__(self, tzinfo=None, datetime_style=CBORDateTimeStyle.TIMESTAMP,
                 float_style = CBORFloatStyle.SHORTEST, sort_method=CBORSortMethod.LEXICOGRAPHIC,
                 float_integer_identity=False, realize_il=True, deterministic=True):
        self.tzinfo = tzinfo
        self.datetime_style = datetime_style
        self.float_style = float_style
        self.sort_method = sort_method
        # In Python bignums and integers are always identical
        self.float_integer_identity = float_integer_identity
        self.realize_il = realize_il
        self.deterministic = deterministic
        if deterministic and sort_method == CBORSortMethod.UNSORTED:
            raise ValueError('deterministic encoding requires a sorting method')


default_encoder_options = CBOREncoderOptions()


class CBOREncoder:

    def __init__(self, options=default_encoder_options):
        assert isinstance(default_encoder_options, CBOREncoderOptions)
        self._parts_generators = {}
        self._options = options

    def _lookup_encoder(self, value):
        vtype = type(value)
        gen_text = default_generators.get(vtype)
        if gen_text:
            generator = getattr(self, gen_text)
        else:
            generator = getattr(vtype, '__cbor_parts__', None)
            if generator:
                generator = partial(generator, encoder=self)
            else:
                for kind, gen_text in default_generators.items():
                    if isinstance(value, kind):
                        generator = getattr(self, gen_text)
                        break
                else:
                    raise CBOREncodingError(f'do not know how to encode object of type {vtype}')
        self._parts_generators[vtype] = generator
        return generator

    @staticmethod
    def length_parts(length, major):
        assert length >= 0
        if length < 24:
            yield pack_byte(major + length)
        elif length < 256:
            yield pack_byte(major + 24)
            yield pack_byte(length)
        elif length < 65536:
            yield pack_byte(major + 25)
            yield pack_be_uint16(length)
        elif length < 4294967296:
            yield pack_byte(major + 26)
            yield pack_be_uint32(length)
        elif length < 18446744073709551616:
            yield pack_byte(major + 27)
            yield pack_be_uint64(length)
        else:
            raise OverflowError

    def int_parts(self, value):
        assert isinstance(value, int)
        if value < 0:
            value = -1 - value
            major = 0x20
        else:
            major = 0x00
        try:
            yield from self.length_parts(value, major)
        except OverflowError:
            bignum_encoding = value.to_bytes((value.bit_length() + 7) // 8, 'big')
            yield b'\xc3' if major else b'\xc2'
            yield from self.byte_string_parts(bignum_encoding)

    def byte_string_parts(self, value):
        assert isinstance(value, (bytes, bytearray, memoryview))
        yield from self.length_parts(len(value), 0x40)
        yield value

    def text_string_parts(self, value):
        assert isinstance(value, str)
        value_utf8 = value.encode()
        yield from self.length_parts(len(value_utf8), 0x60)
        yield value_utf8

    def ordered_list_parts(self, value):
        assert isinstance(value, (tuple, list))
        yield from self.length_parts(len(value), 0x80)
        generate_parts = self.generate_parts
        yield from (bjoin(generate_parts(item)) for item in value)

    def sorted_list_parts(self, value):
        assert isinstance(value, (tuple, list))
        yield from self.length_parts(len(value), 0x80)
        generate_parts = self.generate_parts
        encoded_items_gen = (bjoin(generate_parts(item)) for item in value)
        yield from sorted_items(encoded_items_gen, self._options.sort_method)

    def _sorted_dict_parts(self, kv_pairs, sort_method):
        generate_parts = self.generate_parts
        pairs_gen = ((bjoin(generate_parts(key)), value) for key, value in kv_pairs)
        yield from self.length_parts(len(kv_pairs), 0xa0)
        for encoded_key, value in sorted_pairs(pairs_gen, sort_method):
            yield encoded_key
            yield from generate_parts(value)

    def dict_parts(self, value):
        assert isinstance(value, dict)
        yield from self._sorted_dict_parts(value.items(), self._options.sort_method)

    def ordered_dict_parts(self, value):
        assert isinstance(value, OrderedDict)
        # see https://github.com/Sekenre/cbor-ordered-map-spec/blob/master/CBOR_Ordered_Map.md
        yield from self.tag_parts(272)
        yield from self._sorted_dict_parts(value.items(), CBORSortMethod.UNSORTED)

    def set_parts(self, value):
        assert isinstance(value, (set, frozenset))
        yield from self.tag_parts(258)
        yield from self.sorted_list_parts(tuple(value))

    def bool_parts(self, value):
        assert isinstance(value, bool)
        yield b'\xf5' if value else b'\xf4'

    def None_parts(self, value):
        assert value is None
        yield b'\xf6'

    def float_parts(self, value):
        '''Encodes special values as 2-byte floats, and finite numbers in minimal encoding.'''
        assert isinstance(value, float)
        if value == value:
            try:
                pack4 = pack_be_float4(value)
                value4, = unpack_be_float4(pack4)
                if value4 != value:
                    raise OverflowError
            except OverflowError:
                yield b'\xfb' + pack_be_float8(value)
            else:
                try:
                    pack2 = pack_be_float2(value)
                    value2, = unpack_be_float2(pack2)
                    if value2 != value:
                        raise OverflowError
                    yield b'\xf9' + pack2
                except OverflowError:
                    yield b'\xfa' + pack4
        else:
            yield b'\xf9\x7e\x00'

    def tag_parts(self, value):
        assert isinstance(value, int)
        assert 0 <= value < 65536
        yield from self.length_parts(value, 0xc0)

    def datetime_parts(self, value):
        assert isinstance(value, datetime)
        options = self._options
        if not value.tzinfo:
            if options.tzinfo:
                value = value.replace(tzinfo=options.tzinfo)
            else:
                raise CBOREncodingError('specify tzinfo option to encode a datetime '
                                        'without tzinfo')
        if options.datetime_style == CBORDateTimeStyle.TIMESTAMP:
            yield from self.tag_parts(1)
            value = value.timestamp()
            int_value = int(value)
            if int_value == value:
                yield from self.int_parts(int_value)
            else:
                yield from self.float_parts(value)
        else:
            text = value.isoformat()
            if options.datetime_style == CBORDateTimeStyle.ISO_WITH_Z:
                text = text.replace('+00:00', 'Z')
            yield from self.tag_parts(0)
            yield from self.text_string_parts(text)

    def date_parts(self, value):
        assert isinstance(value, date)
        yield from self.tag_parts(0)
        yield from self.text_string_parts(value.isoformat())

    def decimal_parts(self, value):
        assert isinstance(value, Decimal)
        dt = value.as_tuple()
        # Is this decimal finite?
        if isinstance(dt.exponent, int):
            mantissa = int(''.join(str(digit) for digit in dt.digits))
            if dt.sign:
                mantissa = -mantissa
            yield from self.tag_parts(4)
            yield from self.ordered_list_parts((dt.exponent, mantissa))
        else:
            yield from self.float_parts(float(value))

    def fraction_parts(self, value):
        assert isinstance(value, Fraction)
        yield from self.tag_parts(30)
        yield from self.ordered_list_parts((value.numerator, value.denominator))

    def regexp_parts(self, value):
        assert isinstance(value, regexp_type)
        yield from self.tag_parts(35)
        yield from self.text_string_parts(value.pattern)

    def uuid_parts(self, value):
        assert isinstance(value, UUID)
        yield from self.tag_parts(37)
        yield from self.byte_string_parts(value.bytes)

    def ip_address_parts(self, value):
        assert isinstance(value, (IPv4Address, IPv6Address))
        yield from self.tag_parts(260)
        yield from self.byte_string_parts(value.packed)

    def ip_network_parts(self, value):
        assert isinstance(value, (IPv4Network, IPv6Network))
        yield from self.tag_parts(261)
        # For some daft reason a one-element dictionary was chosen over a pair
        pairs = [(value.network_address.packed, value.prefixlen)]
        yield from self._sorted_dict_parts(pairs)

    def array_parts(self, value):
        assert isinstance(value, array)
        tag = array_typecode_tags.get(value.typecode)
        if not tag:
            raise CBOREncodingError(f'cannot encode arrays with typecode {value.typecode}')
        yield from self.tag_parts(tag)
        yield from self.byte_string_parts(value.tobytes())

    def generate_parts(self, value):
        parts_gen = self._parts_generators.get(type(value)) or self._lookup_encoder(value)
        yield from parts_gen(value)

    # Main external APIs

    def encode(self, value):
        return b''.join(self.generate_parts(value))


def _typecode_tag(typecode):
    if typecode == 'f':
        return 81 if array('f', [1]).tobytes() == pack_be_float4(1) else 85
    if typecode == 'd':
        return 82 if array('d', [1]).tobytes() == pack_be_float8(1) else 86
    a = array(typecode, [1])
    return (
        63 + a.itemsize.bit_length() +
        (4 if (a.tobytes()[0] == 1 and a.itemsize > 1) else 0) +
        (8 if typecode.lower() == typecode else 0)
    )

regexp_type = type(re.compile(''))

array_typecode_tags = {typecode: _typecode_tag(typecode) for typecode in 'bBhHiIlLqQfd'}

default_generators = {
    int: 'int_parts',
    (bytes, bytearray, memoryview): 'byte_string_parts',
    str: 'text_string_parts',
    (tuple, list): 'sorted_list_parts',
    dict: 'dict_parts',
    bool: 'bool_parts',
    type(None): 'None_parts',
    float: 'float_parts',
    (set, frozenset): 'set_parts',
    OrderedDict: 'ordered_dict_parts',
    array: 'array_parts',
    datetime: 'datetime_parts',
    date: 'date_parts',
    Decimal: 'decimal_parts',
    regexp_type: 'regexp_parts',
    UUID: 'uuid_parts',
    Fraction: 'fraction_parts',
    (IPv4Address, IPv6Address): 'ip_address_parts',
    (IPv4Network, IPv6Network): 'ip_network_parts',
}
