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

from math import isfinite, isnan, isinf

from cborx.packing import (
    pack_byte, pack_be_uint16, pack_be_uint32, pack_be_uint64,
    pack_be_float2, pack_be_float4, pack_be_float8, unpack_be_float2, unpack_be_float4
)

# TODO:
#
# - types  mmap, decimal, Collections items,
#          datetime, regexp, fractions, mime, uuid, ipv4, ipv6, ipv4network, ipv6network,
#          set, frozenset, array.array etc.
# - recursive objects


class CBORError(Exception):
    pass


class CBOREncodingError(CBORError):
    pass


class IndefiniteLengthObject:

    def __init__(self, generator):
        self.generator = generator


class IndefiniteLengthByteString(IndefiniteLengthObject):
    pass


class IndefiniteLengthTextString(IndefiniteLengthObject):
    pass


class IndefiniteLengthList(IndefiniteLengthObject):
    pass


class IndefiniteLengthDict(IndefiniteLengthObject):
    pass


def _raise_unknown_type(value):
    raise CBOREncodingError(f'cannot encode object of type {type(value)}')


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


def _int_parts(value):
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
        yield from _byte_string_parts(bignum_encoding)


def _byte_string_parts(value):
    assert isinstance(value, (bytes, bytearray, memoryview))
    yield from _length_parts(len(value), 0x40)
    yield value


def _indefinite_length_byte_string_parts(value):
    assert isinstance(value, IndefiniteLengthByteString)
    yield b'\x5f'
    for byte_string in value.generator:
        yield from _byte_string_parts(byte_string)
    yield b'\xff'


def _text_string_parts(value):
    assert isinstance(value, str)
    value_utf8 = value.encode()
    yield from _length_parts(len(value_utf8), 0x60)
    yield value_utf8


def _indefinite_length_text_string_parts(value):
    assert isinstance(value, IndefiniteLengthTextString)
    yield b'\x7f'
    for text_string in value.generator:
        yield from _text_string_parts(text_string)
    yield b'\xff'


def _list_parts(value, encode_to_parts):
    assert isinstance(value, (tuple, list))
    yield from _length_parts(len(value), 0x80)
    for item in value:
        yield from encode_to_parts(item)


def _indefinite_length_list_parts(value, encode_to_parts):
    assert isinstance(value, IndefiniteLengthList)
    yield b'\x9f'
    for item in value.generator:
        yield from encode_to_parts(item)
    yield b'\xff'


def _dict_parts(value, encode_to_parts):
    assert isinstance(value, dict)
    yield from _length_parts(len(value), 0xa0)
    for key, kvalue in value.items():
        yield from encode_to_parts(key)
        yield from encode_to_parts(kvalue)


def _indefinite_length_dict_parts(value, encode_to_parts):
    assert isinstance(value, IndefiniteLengthDict)
    yield b'\xbf'
    for key, kvalue in value.generator:
        yield from encode_to_parts(key)
        yield from encode_to_parts(kvalue)
    yield b'\xff'


def _bool_parts(value):
    assert isinstance(value, bool)
    yield b'\xf5' if value else b'\xf4'


def _None_parts(value):
    assert value is None
    yield b'\xf6'


def _float_parts(value):
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


class CBOREncoder:

    def __init__(self):
        self._encoder_map = {}
        for lhs, encoder in _encoder_map_compact.items():
            if isinstance(encoder, str):
                encoder = getattr(self, encoder)
            for kind in (lhs if isinstance(lhs, tuple) else [lhs]):
                self._encoder_map[kind] = encoder

    def _list_parts(self, value):
        yield from _list_parts(value, self.encode_to_parts)

    def _dict_parts(self, value):
        yield from _dict_parts(value, self.encode_to_parts)

    def _indefinite_length_list_parts(self, value):
        yield from _indefinite_length_list_parts(value, self.encode_to_parts)

    def _indefinite_length_dict_parts(self, value):
        yield from _indefinite_length_dict_parts(value, self.encode_to_parts)

    def _lookup_encoder(self, value):
        # Handle inheritance
        for kind, encoder in _encoder_map_compact.items():
            if isinstance(value, kind):
                self._encoder_map[type(value)] = encoder
                return encoder
        return None

    def encode_to_parts(self, value):
        # Fast track standard types
        encoder = (
            self._encoder_map.get(type(value))
            or self._lookup_encoder(value)
            # FIXME: admit type-specific encoding via an attribute
            or _raise_unknown_type(value)
        )
        yield from encoder(value)

    def encode(self, value):
        return b''.join(self.encode_to_parts(value))


_encoder_map_compact = {
    int: _int_parts,
    (bytes, bytearray, memoryview): _byte_string_parts,
    str: _text_string_parts,
    (tuple, list): '_list_parts',
    dict: '_dict_parts',
    bool: _bool_parts,
    type(None): _None_parts,
    float: _float_parts,
    IndefiniteLengthByteString: _indefinite_length_byte_string_parts,
    IndefiniteLengthTextString: _indefinite_length_text_string_parts,
    IndefiniteLengthList: '_indefinite_length_list_parts',
    IndefiniteLengthDict: '_indefinite_length_dict_parts',
}
