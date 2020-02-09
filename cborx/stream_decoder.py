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

'''CBOR stream decoding.'''

__all__ = ('streams_sequence', )


import itertools
from io import BytesIO

from cborx.decoder import decode_text
from cborx.packing import uint_unpackers, be_float_unpackers
from cborx.types import (
    BadInitialByteError, MisplacedBreakError, BadSimpleError, UnexpectedEOFError,
    UnconsumedDataError,
    ContextILByteString, ContextILTextString, ContextILArray, ContextILMap,
    ContextArray, ContextMap, ContextTag, Break, CBORSimple
)


class CBORStreamDecoder:
    '''Decodes CBOR-encoded data'''

    def __init__(self, read, simple_value=None):
        self._read = read
        self._major_decoders = (
            self.decode_unsigned_int,
            self.decode_negative_int,
            self.decode_byte_string,
            self.decode_text_string,
            self.decode_array,
            self.decode_map,
            self.decode_tag,
            self.decode_simple
        )
        self._pending_id = None
        self._simple_value = simple_value or CBORSimple
        self._shared_id = itertools.count()
        self._shared_ids = {}
        self._flags = 0

    def read(self, n):
        result = self._read(n)
        if len(result) == n:
            return result
        raise UnexpectedEOFError(f'need {n:,d} bytes but only {len(result):,d} available')

    def decode_length(self, initial_byte):
        minor = initial_byte & 0x1f
        if minor < 24:
            return minor
        if minor < 28:
            kind = minor - 24
            length, = uint_unpackers[kind](self.read(1 << kind))
            return length
        if initial_byte in {0x5f, 0x7f, 0x9f, 0xbf}:
            return None
        raise BadInitialByteError(f'bad initial byte 0x{initial_byte:x}')

    def decode_unsigned_int(self, initial_byte):
        yield self.decode_length(initial_byte)

    def decode_negative_int(self, initial_byte):
        yield -1 - self.decode_length(initial_byte)

    def decode_byte_string(self, initial_byte):
        length = self.decode_length(initial_byte)
        read = self.read
        if length is None:
            yield ContextILByteString()
            decode_length = self.decode_length
            while True:
                initial_byte = ord(read(1))
                if 0x40 <= initial_byte < 0x5c:
                    yield read(decode_length(initial_byte))
                elif initial_byte == 0xff:
                    break
                else:
                    raise BadInitialByteError(f'bad initial byte 0x{initial_byte:x} in '
                                              f'indefinite-length byte string')
            yield Break
        else:
            yield read(length)

    def decode_text_string(self, initial_byte):
        length = self.decode_length(initial_byte)
        read = self.read
        if length is None:
            yield ContextILTextString()
            decode_length = self.decode_length
            while True:
                initial_byte = ord(read(1))
                if 0x60 <= initial_byte < 0x7c:
                    yield decode_text(read(decode_length(initial_byte)))
                elif initial_byte == 0xff:
                    break
                else:
                    raise BadInitialByteError(f'bad initial byte 0x{initial_byte:x} in '
                                              f'indefinite-length byte string')
            yield Break
        else:
            yield decode_text(self.read(length))

    def decode_array(self, initial_byte):
        length = self.decode_length(initial_byte)
        read = self.read
        major_decoders = self._major_decoders
        if length is None:
            yield ContextILArray()
            while True:
                initial_byte = ord(read(1))
                if initial_byte == 0xff:
                    break
                yield from major_decoders[initial_byte >> 5](initial_byte)
            yield Break
        else:
            yield ContextArray(length)
            for _ in range(length):
                initial_byte = ord(read(1))
                yield from major_decoders[initial_byte >> 5](initial_byte)

    def decode_map(self, initial_byte):
        length = self.decode_length(initial_byte)
        read = self.read
        major_decoders = self._major_decoders
        if length is None:
            yield ContextILMap()
            while True:
                initial_byte = ord(read(1))
                if initial_byte == 0xff:
                    break
                yield from major_decoders[initial_byte >> 5](initial_byte)
                initial_byte = ord(read(1))
                yield from major_decoders[initial_byte >> 5](initial_byte)
            yield Break
        else:
            yield ContextMap(length)
            for _ in range(length * 2):
                initial_byte = ord(read(1))
                yield from major_decoders[initial_byte >> 5](initial_byte)

    def decode_tag(self, initial_byte):
        value = self.decode_length(initial_byte)
        yield ContextTag(value)
        initial_byte = ord(self.read(1))
        yield from self._major_decoders[initial_byte >> 5](initial_byte)

    def decode_simple(self, initial_byte):
        # Pass initial_byte not length to detect ill-formed simples
        value = initial_byte & 0x1f
        if value < 20:
            yield self._simple_value(value)
        elif value < 24:
            yield CBORSimple.assigned_values[value]
        elif value == 24:
            value = ord(self.read(1))
            if value < 32:
                raise BadSimpleError(f'simple value 0x{value:x} encoded with extra byte')
            yield self._simple_value(value)
        elif value < 28:
            length = 1 << (value - 24)
            float_value, = be_float_unpackers[value - 25](self.read(length))
            yield float_value
        elif value == 31:
            raise MisplacedBreakError('break code outside indefinite-length object')
        else:
            raise BadInitialByteError(f'bad initial byte 0x{initial_byte:x}')

    # External API

    def stream_one(self, check_eof=True):
        initial_byte = ord(self.read(1))
        yield from self._major_decoders[initial_byte >> 5](initial_byte)
        if check_eof and self._read(1):
            raise UnconsumedDataError('not all input consumed')

    def stream_sequence(self):
        major_decoders = self._major_decoders
        read = self.read
        while True:
            try:
                initial_byte = ord(read(1))
            except UnexpectedEOFError:
                break
            yield from major_decoders[initial_byte >> 5](initial_byte)


def streams_sequence(raw, **kwargs):
    read = BytesIO(raw).read
    decoder = CBORStreamDecoder(read, **kwargs)
    yield from decoder.stream_sequence()
