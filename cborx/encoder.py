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

# TODO:
#
# - types:  set, frozenset, array.array, undefined, simple types etc.
# - recursive objects
# - semantic tagging to force e.g. a particular float representation


class CBORError(Exception):
    pass


class CBOREncodingError(CBORError):
    pass


class CBORDateTimeStyle(IntEnum):
    TIMESTAMP = 0
    ISO_WITH_Z = 1
    ISO_WITHOUT_Z = 2


class CBORTag:

    def __init__(self, tag, value):
        if not isinstance(tag, int):
            raise TypeError(f'tag {tag} must be an integer')
        if not 0 <= tag < 65536:
            raise ValueError(f'tag value {tag} out of range')
        self._tag = tag
        self._value = value

    def __eq__(self, other):
        return (isinstance(other, CBORTag)
                and self._tag == other._tag and self._value == other._value)

    def __cbor__(self, encoder):
        yield from _length_parts(self._tag, 0xc0)
        yield from encoder.generate_parts(self._value)


class UndefinedObject:

    __instance = None

    def __new__(cls, *args, **kwargs):
        if not cls.__instance:
            cls.__instance = super().__new__(cls, *args, **kwargs)
        return cls.__instance

    def __cbor__(self, encoder):
        yield b'\xf7'


class IndefiniteLengthObject:

    def __init__(self, generator):
        self.generator = generator


class IndefiniteLengthByteString(IndefiniteLengthObject):

    def __cbor__(self, encoder):
        yield b'\x5f'
        byte_string_parts = encoder.byte_string_parts
        for byte_string in self.generator:
            yield from byte_string_parts(byte_string)
        yield b'\xff'


class IndefiniteLengthTextString(IndefiniteLengthObject):

    def __cbor__(self, encoder):
        yield b'\x7f'
        text_string_parts = encoder.text_string_parts
        for text_string in self.generator:
            yield from text_string_parts(text_string)
        yield b'\xff'


class IndefiniteLengthList(IndefiniteLengthObject):

    def __cbor__(self, encoder):
        yield b'\x9f'
        generate_parts = encoder.generate_parts
        for item in self.generator:
            yield from generate_parts(item)
        yield b'\xff'


class IndefiniteLengthDict(IndefiniteLengthObject):

    def __cbor__(self, encoder):
        yield b'\xbf'
        generate_parts = encoder.generate_parts
        for key, kvalue in self.generator:
            yield from generate_parts(key)
            yield from generate_parts(kvalue)
        yield b'\xff'


def _length_parts(length, major):
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


class CBOREncoderOptions:
    '''Controls encoder behaviour.'''

    def __init__(self, tzinfo=None, datetime_style=CBORDateTimeStyle.TIMESTAMP):
        self.tzinfo = tzinfo
        self.datetime_style = datetime_style


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
            generator = getattr(vtype, '__cbor__', None)
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

    def int_parts(self, value):
        assert isinstance(value, int)
        if value < 0:
            value = -1 - value
            major = 0x20
        else:
            major = 0x00
        try:
            yield from _length_parts(value, major)
        except OverflowError:
            bignum_encoding = value.to_bytes((value.bit_length() + 7) // 8, 'big')
            yield b'\xc3' if major else b'\xc2'
            yield from self.byte_string_parts(bignum_encoding)

    def byte_string_parts(self, value):
        assert isinstance(value, (bytes, bytearray, memoryview))
        yield from _length_parts(len(value), 0x40)
        yield value

    def text_string_parts(self, value):
        assert isinstance(value, str)
        value_utf8 = value.encode()
        yield from _length_parts(len(value_utf8), 0x60)
        yield value_utf8

    def list_parts(self, value):
        assert isinstance(value, (tuple, list))
        yield from _length_parts(len(value), 0x80)
        generate_parts = self.generate_parts
        for item in value:
            yield from generate_parts(item)

    def dict_parts(self, value):
        assert isinstance(value, dict)
        yield from _length_parts(len(value), 0xa0)
        generate_parts = self.generate_parts
        for key, kvalue in value.items():
            yield from generate_parts(key)
            yield from generate_parts(kvalue)

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
        yield from _length_parts(value, 0xc0)

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
            yield from self.list_parts((dt.exponent, mantissa))
        else:
            yield from self.float_parts(float(value))

    def fraction_parts(self, value):
        assert isinstance(value, Fraction)
        yield from self.tag_parts(30)
        yield from self.list_parts((value.numerator, value.denominator))

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
        # For some daft reason a dictionary was chosen over a list
        yield from self.dict_parts({value.network_address.packed: value.prefixlen})

    def generate_parts(self, value):
        parts_gen = self._parts_generators.get(type(value)) or self._lookup_encoder(value)
        yield from parts_gen(value)

    # Main external APIs

    def encode(self, value):
        return b''.join(self.generate_parts(value))


regexp_type = type(re.compile(''))
default_generators = {
    int: 'int_parts',
    (bytes, bytearray, memoryview): 'byte_string_parts',
    str: 'text_string_parts',
    (tuple, list): 'list_parts',
    dict: 'dict_parts',
    bool: 'bool_parts',
    type(None): 'None_parts',
    float: 'float_parts',
    datetime: 'datetime_parts',
    date: 'date_parts',
    Decimal: 'decimal_parts',
    regexp_type: 'regexp_parts',
    UUID: 'uuid_parts',
    Fraction: 'fraction_parts',
    (IPv4Address, IPv6Address): 'ip_address_parts',
    (IPv4Network, IPv6Network): 'ip_network_parts',
}
