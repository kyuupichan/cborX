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

from cborx.packing import pack_byte, pack_be_uint16, pack_be_uint32, pack_be_uint64


class CBORError(Exception):
    pass


class CBOREncodingError(CBORError, TypeError):
    pass


def _encode_length(length, major):
    assert 0 <= length < 18446744073709551616
    if length < 24:
        return pack_byte(major + length)
    elif length < 256:
        return pack_byte(major + 24) + pack_byte(length)
    elif length < 65536:
        return pack_byte(major + 25) + pack_be_uint16(length)
    elif length < 4294967296:
        return pack_byte(major + 26) + pack_be_uint32(length)
    else:
        return pack_byte(major + 27) + pack_be_uint64(length)


def _encode_byte_string(write, value):
    if not isinstance(value, (bytes, bytearray, memoryview)):
        raise CBOREncodingError(f'expected a byte string, not object of type {type(value)}')
    write(_encode_length(len(value), 0x40))
    write(value)


class CBORIndefiniteByteString:

    def __init__(self, write):
        self._write = write

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        if exc_type is None:
            self._write(b'\xff')

    def append(self, value):
        _encode_byte_string(self._write, value)


class CBOREncoder:

    def __init__(self, write):
        self._write = write

    def _encode_int(self, value):
        assert isinstance(value, int)
        if value < 0:
            value = -1 - value
            major = 0x20
        else:
            major = 0x00
        if value < 18446744073709551616:
            self._write(_encode_length(value, major))
        else:
            raise ValueError('bignums not supported')

    def _encode_byte_string(self, value):
        assert isinstance(value, (bytes, bytearray, memoryview))
        self._write(_encode_length(len(value), 2))
        self._write(value)

    def _encode_text_string(self, value):
        assert isinstance(value, str)
        value_utf8 = value.encode()
        self._write(_encode_length(len(value_utf8), 3))
        self._write(value_utf8)

    def _lookup_encoder(self, value):
        # Handle inheritance
        for kind, encoder in _encoding_table.items():
            if isinstance(value, kind):
                _encoding_table[type(value)] = encoder
                return encoder
        return None

    def indefinite_byte_string(self):
        return CBORIndefiniteByteString(self)

    def encode(self, value):
        # Fast track standard types
        encoder = (
            _encoding_table.get(type(value))
            or self._lookup_slow(value)
            # FIXME: admit type-specific encoding via an attribute
        )
        if encoder:
            encoder(self, value)
        else:
            raise CBOREncodingError(f'cannot encode object of type {type(value)}')


_encoding_table = {
    int: CBOREncoder._encode_int,
    bytes: CBOREncoder._encode_byte_string,
    bytearray: CBOREncoder._encode_byte_string,
    memoryview: CBOREncoder._encode_byte_string,
    str: CBOREncoder._encode_text_string,
    # TODO: mmap, float, decimal, bool, None, tuple, list, dict, Collections items,
    # datetime, regexp, fractions, mime, uuid, ipv4, ipv6, ipv4network, ipv6network,
    # set, frozenset, etc.
}
