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

from cborx.packing import (
    pack_byte, pack_be_uint16, pack_be_uint32, pack_be_uint64,
    pack_be_float2, pack_be_float4, pack_be_float8, unpack_be_float2, unpack_be_float4
)

# TODO:
#
# - types  mmap, decimal, Collections items,
#          datetime, regexp, fractions, mime, uuid, ipv4, ipv6, ipv4network, ipv6network,
#          set, frozenset, array.array, undefined, simple types etc.
# - recursive objects
# - semantic tagging to force e.g. a particular float representation


class CBORError(Exception):
    pass


class CBOREncodingError(CBORError):
    pass


class CBORTag:

    def __init__(self, tag, value):
        if not isinstance(tag, int):
            raise TypeError(f'tag {tag} must be an integer')
        self._tag = tag
        self._value = value

    def __eq__(self, other):
        return (
            isinstance(other, CBORTag)
            and self._tag == other._tag
            and self._value == other._value
        )

    def __cbor__(self, generate_parts):
        yield from _length_parts(self._tag, 0xc0)
        yield from generate_parts(self._value)


class UndefinedObject:

    __instance = None

    def __new__(cls, *args, **kwargs):
        if not cls.__instance:
            cls.__instance = super().__new__(cls, *args, **kwargs)
        return cls.__instance

    def __cbor__(self, _generate_parts):
        yield b'\xf7'


class IndefiniteLengthObject:

    def __init__(self, generator):
        self.generator = generator


class IndefiniteLengthByteString(IndefiniteLengthObject):

    def __cbor__(self, generate_parts):
        yield b'\x5f'
        for byte_string in self.generator:
            yield from _byte_string_parts(byte_string, generate_parts)
        yield b'\xff'


class IndefiniteLengthTextString(IndefiniteLengthObject):

    def __cbor__(self, generate_parts):
        yield b'\x7f'
        for text_string in self.generator:
            yield from _text_string_parts(text_string, generate_parts)
        yield b'\xff'


class IndefiniteLengthList(IndefiniteLengthObject):

    def __cbor__(self, generate_parts):
        yield b'\x9f'
        generate_parts = generate_parts
        for item in self.generator:
            yield from generate_parts(item)
        yield b'\xff'


class IndefiniteLengthDict(IndefiniteLengthObject):

    def __cbor__(self, generate_parts):
        yield b'\xbf'
        generate_parts = generate_parts
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


def _int_parts(value, generate_parts):
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
        yield from _byte_string_parts(bignum_encoding, generate_parts)


def _byte_string_parts(value, _generate_parts):
    assert isinstance(value, (bytes, bytearray, memoryview))
    yield from _length_parts(len(value), 0x40)
    yield value


def _text_string_parts(value, _generate_parts):
    assert isinstance(value, str)
    value_utf8 = value.encode()
    yield from _length_parts(len(value_utf8), 0x60)
    yield value_utf8


def _list_parts(value, generate_parts):
    assert isinstance(value, (tuple, list))
    yield from _length_parts(len(value), 0x80)
    for item in value:
        yield from generate_parts(item)


def _dict_parts(value, generate_parts):
    assert isinstance(value, dict)
    yield from _length_parts(len(value), 0xa0)
    for key, kvalue in value.items():
        yield from generate_parts(key)
        yield from generate_parts(kvalue)


def _bool_parts(value, _generate_parts):
    assert isinstance(value, bool)
    yield b'\xf5' if value else b'\xf4'


def _None_parts(value, _generate_parts):
    assert value is None
    yield b'\xf6'


def _float_parts(value, _generate_parts):
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

    def _lookup_encoder(self, value):
        vtype = type(value)
        result = _encoder_map_compact.get(vtype)
        if not result:
            result = getattr(vtype, '__cbor__', None)
            if not result:
                for kind, generate_parts in _encoder_map_compact.items():
                    if isinstance(value, kind):
                        result = generate_parts
                if not result:
                    raise CBOREncodingError(f'cannot encode object of type {vtype}')
        self._encoder_map[vtype] = result
        return result

    def generate_parts(self, value):
        encoder = (
            self._encoder_map.get(type(value))
            or self._lookup_encoder(value)
        )
        yield from encoder(value, self.generate_parts)

    def encode(self, value):
        return b''.join(self.generate_parts(value))


_encoder_map_compact = {
    int: _int_parts,
    (bytes, bytearray, memoryview): _byte_string_parts,
    str: _text_string_parts,
    (tuple, list): _list_parts,
    dict: _dict_parts,
    bool: _bool_parts,
    type(None): _None_parts,
    float: _float_parts,
}
