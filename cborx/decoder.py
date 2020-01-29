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

'''CBOR decoding.'''


from cborx.packing import unpack_byte, unpack_be_uint16, unpack_be_uint32, unpack_be_uint64
from cborx.types import CBOREOFError


class CBORBreak(Exception):
    pass


uint_unpackers = [unpack_byte, unpack_be_uint16, unpack_be_uint32, unpack_be_uint64]


class CBORDecoder:

    def __init__(self, read):
        self._read = read
        # self._decode_funcs = {}
        self._major_decoders = {n: getattr(self, f'_decode_major_{n}') for n in range(2)}

    def _lookup_decoder(self, first_byte):
        decode_func = self._major_decoders[first_byte >> 5](first_byte & 0x1f)
        self._decode_funcs[first_byte] = decode_func
        return decode_func

    def _decode_major_0(self, first_byte):
        minor = first_byte & 0x1f
        if minor < 24:
            return minor
        size = minor - 24
        try:
            value, = uint_unpackers[size](self._read_safe(1 << size))
        except IndexError:
            raise CBORDecodingError(f'ill formed CBOR with initial byte {first_byte}') from None
        return value

    def _decode_major_1(self, first_byte):
        return -1 - self._decode_major_0(first_byte)

    def _read_safe(self, n):
        result = self._read(n)
        if len(result) == n:
            return result
        raise CBOREOFError(f'need {n:,d} bytes but only {len(result):,d} available')

    def _read_safe_from_generator(self, n):
        while True:
            if read_len >= n:
                return n_bytes_from_parts
            part = next(self._read)
            read_len += len(part)

    def decode_item(self):
        first_byte = ord(self._read_safe(1))
        return self._major_decoders[first_byte >> 5](first_byte)
        #decode_func = self._decode_funcs.get(first_byte) or self._lookup_decoder(first_byte)
        #return decode_func()


def loads(read, **kwargs):
    decoder = CBORDecoder(read, **kwargs)
    return decoder.decode_item()


def load_stream(bytes_gen, **kwargs):
    '''A generator of top-level decoded CBOR objects reading from a byte stream.

    The byte stream yields byte strings of arbitrary size.'''
    decoder = CBORDecoder(bytes_gen, **kwargs)
    try:
        decode_item = decoder.decode_item
        while True:
            yield decode_item()
    except CBOREOFError:
        pass


async def aload_stream(bytes_async_gen, **kwargs):
    '''An asynchronous generator of top-level decoded CBOR objects reading from a byte stream.

    The byte stream asynchronously yields byte strings of arbitrary size.
    '''
    decoder = CBORDecoder(bytes_async_gen, **kwargs)
    try:
        async_decode_item = decoder.async_decode_item
        while True:
            yield await async_decode_item()
    except CBOREOFError:
        pass
