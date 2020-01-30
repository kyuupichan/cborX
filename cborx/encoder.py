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

import itertools
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
    pack_byte, pack_be_float2, pack_be_float4, pack_be_float8, unpack_be_float2, unpack_be_float4
)
from cborx.types import CBORTag, CBOREncodingError, CBORSimple, encode_length, bjoin, sjoin

# TODO:
#
# - encoder customization
# - embedded CBOR data item
# - streaming API


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
        return sorted(pairs_gen, key=lambda pair: (len(pair[0]), pair[0]))
    else:
        return pairs_gen


def sorted_items(encoded_items_gen, method):
    '''Return an iterable sorting the items according to method.'''
    if method == CBORSortMethod.LEXICOGRAPHIC:
        return sorted(encoded_items_gen)
    elif method == CBORSortMethod.LENGTH_FIRST:
        return sorted(encoded_items_gen, key=lambda item: (len(item), item))
    else:
        return list(encoded_items_gen)


class CBOREncoder:

    SHARED_TYPES = {tuple, list, dict, OrderedDict}

    def __init__(self, *, tzinfo=None, datetime_style=CBORDateTimeStyle.TIMESTAMP,
                 float_style = CBORFloatStyle.SHORTEST, sort_method=CBORSortMethod.LEXICOGRAPHIC,
                 realize_il=True, shared_types=(), deterministic=False):
        if deterministic:
            if sort_method == CBORSortMethod.UNSORTED:
                raise ValueError('a deterministic encoder requires sorting')
            realize_il = True
        # Note: in Python bignums and integers are indistinguishable
        self.tzinfo = tzinfo
        self.datetime_style = datetime_style
        self.float_style = float_style
        self.sort_method = sort_method
        self.realize_il = realize_il
        self.shared_types = shared_types
        # Implementation details
        self._encode_funcs = {}
        self._shared_id = itertools.count()
        self._shared_ids = {}

    def _encode_shared(self, encode_func, value):
        value_id = id(value)
        value_ref = self._shared_ids.get(value_id)
        if value_ref is None:
            self._shared_ids[value_id] = next(self._shared_id)
            return self.encode_tag(28) + encode_func(value)
        else:
            return self.encode_tag(29) + self.encode_int(value_ref)

    def _encode_func(self, vtype):
        used_type = vtype
        func_text = default_encode_funcs.get(vtype)
        if func_text:
            encode_func = getattr(self, func_text)
        else:
            encode_func = getattr(vtype, '__encode_cbor__', None)
            if encode_func:
                encode_func = partial(encode_func, encoder=self)
            else:
                # Check for subclasses
                for kind, func_text in default_encode_funcs.items():
                    if issubclass(vtype, kind):
                        used_type = kind
                        encode_func = getattr(self, func_text)
                        break
                else:
                    raise CBOREncodingError(f'do not know how to encode object of type {vtype}')
        if used_type in self.shared_types:
            encode_func = partial(self._encode_shared, encode_func)
        self._encode_funcs[vtype] = encode_func
        return encode_func

    def encode_int(self, value):
        assert isinstance(value, int)
        try:
            if value < 0:
                prefix = b'\xc3'
                value = -1 - value
                return encode_length(value, 0x20)
            else:
                prefix = b'\xc2'
                return encode_length(value, 0x00)
        except OverflowError:
            bignum_encoding = value.to_bytes((value.bit_length() + 7) // 8, 'big')
            return prefix + self.encode_byte_string(bignum_encoding)

    def encode_byte_string(self, value):
        return encode_length(len(value), 0x40) + value

    def encode_text_string(self, value):
        value_utf8 = value.encode()
        return encode_length(len(value_utf8), 0x60) + value_utf8

    def encode_ordered_list(self, value):
        encode_item = self.encode_item
        return encode_length(len(value), 0x80) + bjoin(encode_item(item) for item in value)

    def encode_sorted_list(self, value):
        length = encode_length(len(value), 0x80)
        encode_item = self.encode_item
        encoded_items_gen = (encode_item(item) for item in value)
        return length + bjoin(sorted_items(encoded_items_gen, self.sort_method))

    def encode_sorted_dict(self, kv_pairs, sort_method):
        encode_item = self.encode_item
        pairs_gen = ((encode_item(key), value) for key, value in kv_pairs)
        length = encode_length(len(kv_pairs), 0xa0)
        return length + bjoin(encoded_key + encode_item(value)
                              for encoded_key, value in sorted_pairs(pairs_gen, sort_method))

    def encode_dict(self, value):
        return self.encode_sorted_dict(value.items(), self.sort_method)

    def encode_ordered_dict(self, value):
        # see https://github.com/Sekenre/cbor-ordered-map-spec/blob/master/CBOR_Ordered_Map.md
        return self.encode_tag(272) + self.encode_sorted_dict(value.items(),
                                                              CBORSortMethod.UNSORTED)

    def encode_set(self, value):
        return self.encode_tag(258) + self.encode_sorted_list(tuple(value))

    def encode_bool(self, value):
        return b'\xf5' if value else b'\xf4'

    def encode_None(self, value):
        return b'\xf6'

    def encode_float(self, value):
        '''Encodes special values as 2-byte floats, and finite numbers in minimal encoding.'''
        if self.float_style == CBORFloatStyle.SHORTEST:
            return self.encode_shortest_float(value)
        else:
            return self.encode_double_float(value)

    def encode_double_float(self, value):
        return b'\xfb' + pack_be_float8(value)

    def encode_shortest_float(self, value):
        if value == value:
            try:
                pack4 = pack_be_float4(value)
                value4, = unpack_be_float4(pack4)
                if value4 != value:
                    raise OverflowError
            except OverflowError:
                return b'\xfb' + pack_be_float8(value)
            else:
                try:
                    pack2 = pack_be_float2(value)
                    value2, = unpack_be_float2(pack2)
                    if value2 != value:
                        raise OverflowError
                    return b'\xf9' + pack2
                except OverflowError:
                    return b'\xfa' + pack4
        else:
            return b'\xf9\x7e\x00'

    def encode_tag(self, value):
        assert isinstance(value, int)
        assert 0 <= value < 65536
        return encode_length(value, 0xc0)

    def encode_datetime(self, value):
        assert isinstance(value, datetime)
        if not value.tzinfo:
            if self.tzinfo:
                value = value.replace(tzinfo=self.tzinfo)
            else:
                raise CBOREncodingError('specify tzinfo option to encode a datetime '
                                        'without tzinfo')
        if self.datetime_style == CBORDateTimeStyle.TIMESTAMP:
            tag = self.encode_tag(1)
            value = value.timestamp()
            int_value = int(value)
            if int_value == value:
                return tag + self.encode_int(int_value)
            else:
                return tag + self.encode_float(value)
        else:
            text = value.isoformat()
            if self.datetime_style == CBORDateTimeStyle.ISO_WITH_Z:
                text = text.replace('+00:00', 'Z')
            return self.encode_tag(0) + self.encode_text_string(text)

    def encode_date(self, value):
        assert isinstance(value, date)
        return self.encode_tag(0) + self.encode_text_string(value.isoformat())

    def encode_decimal(self, value):
        assert isinstance(value, Decimal)
        dt = value.as_tuple()
        # Is this decimal finite?
        if isinstance(dt.exponent, int):
            mantissa = int(sjoin(str(digit) for digit in dt.digits))
            if dt.sign:
                mantissa = -mantissa
            return self.encode_tag(4) + self.encode_ordered_list((dt.exponent, mantissa))
        else:
            return self.encode_float(float(value))

    def encode_fraction(self, value):
        assert isinstance(value, Fraction)
        return self.encode_tag(30) + self.encode_ordered_list((value.numerator, value.denominator))

    def encode_regexp(self, value):
        assert isinstance(value, regexp_type)
        return self.encode_tag(35) + self.encode_text_string(value.pattern)

    def encode_uuid(self, value):
        assert isinstance(value, UUID)
        return self.encode_tag(37) + self.encode_byte_string(value.bytes)

    def encode_ip_address(self, value):
        assert isinstance(value, (IPv4Address, IPv6Address))
        return self.encode_tag(260) + self.encode_byte_string(value.packed)

    def encode_ip_network(self, value):
        assert isinstance(value, (IPv4Network, IPv6Network))
        # For some daft reason a one-element dictionary was chosen over a pair
        pairs = [(value.network_address.packed, value.prefixlen)]
        return self.encode_tag(261) + self.encode_sorted_dict(pairs)

    def encode_array(self, value):
        assert isinstance(value, array)
        tag = array_typecode_tags.get(value.typecode)
        if not tag:
            raise CBOREncodingError(f'cannot encode arrays with typecode {value.typecode}')
        return self.encode_tag(tag) + self.encode_byte_string(value.tobytes())

    def encode_item(self, value):
        encode_func = self._encode_funcs.get(value.__class__) or self._encode_func(value.__class__)
        return encode_func(value)

    # External APIs

    def encode(self, value):
        try:
            return self.encode_item(value)
        except RecursionError:
            raise CBOREncodingError('self-referential object detected') from None


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

default_encode_funcs = {
    int: 'encode_int',
    bytes: 'encode_byte_string',
    bytearray: 'encode_byte_string',
    memoryview: 'encode_byte_string',
    str: 'encode_text_string',
    tuple: 'encode_ordered_list',
    list: 'encode_ordered_list',
    dict: 'encode_dict',
    bool: 'encode_bool',
    type(None): 'encode_None',
    float: 'encode_float',
    set: 'encode_set',
    frozenset: 'encode_set',
    OrderedDict: 'encode_ordered_dict',
    array: 'encode_array',
    datetime: 'encode_datetime',
    date: 'encode_date',
    Decimal: 'encode_decimal',
    regexp_type: 'encode_regexp',
    UUID: 'encode_uuid',
    Fraction: 'encode_fraction',
    IPv4Address: 'encode_ip_address',
    IPv6Address: 'encode_ip_address',
    IPv4Network: 'encode_ip_network',
    IPv6Network: 'encode_ip_network',
}


def dumps(obj, **kwargs):
    '''Serialize obj to a CBOR-formatted bytes object.

    kwargs: arguments to pass to CBOREncoder
    '''
    e = CBOREncoder(**kwargs)
    return e.encode(obj)


def dump(obj, fp, **kwargs):
    '''Serialize obj to fp (a .write() supporting file-like object).

    kwargs: arguments to pass to CBOREncoder
    '''
    fp.write(dumps(obj, **kwargs))
