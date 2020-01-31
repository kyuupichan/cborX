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

import re
from datetime import datetime, date, timezone, time, timedelta
from decimal import Decimal
from fractions import Fraction
from enum import IntEnum
from io import BytesIO
from uuid import UUID


from cborx.packing import (
    unpack_byte, unpack_be_uint16, unpack_be_uint32, unpack_be_uint64,
    unpack_be_float2, unpack_be_float4, unpack_be_float8,
)
from cborx.types import CBOREOFError, CBORDecodingError, FrozenDict, CBORSimple, CBORTag
from cborx.util import datetime_from_enhanced_RFC3339_text


# TODO:
# Handle non-minimal integer / length / float decodings
# Handle decoding value-shared encodings


class CBORFlags(IntEnum):
    IMMUTABLE = 1


uint_unpackers = [unpack_byte, unpack_be_uint16, unpack_be_uint32, unpack_be_uint64]
be_float_unpackers = [unpack_be_float2, unpack_be_float4, unpack_be_float8]
tag_decoders = {
    0: 'decode_datetime_text',
    1: 'decode_timestamp',
    2: 'decode_uint_bignum',
    3: 'decode_negative_bignum',
    4: 'decode_decimal',
    # 28: tagged shareable
    # 29: tagged shared
    30: 'decode_rational',
    35: 'decode_regexp',
    37: 'decode_uuid',
    # 258: set
    # 260: ip_address
    # 261: ip_network
    # 272: OrderedDict
}


class CBORDecoder:

    def __init__(self, read):
        self._read = read
        self._major_decoders = (
            self.decode_uint,
            self.decode_negative_int,
            self.decode_byte_string,
            self.decode_text_string,
            self.decode_list,
            self.decode_dict,
            self.decode_tag,
            self.decode_simple
        )

    def decode_length(self, first_byte):
        minor = first_byte & 0x1f
        if minor < 24:
            return minor
        if minor < 28:
            kind = minor - 24
            length, = uint_unpackers[kind](self.read(1 << kind))
            return length
        if first_byte in {0x5f, 0x7f, 0x9f, 0xbf}:
            return None
        raise CBORDecodingError(f'ill-formed CBOR object with initial byte 0x{first_byte:x}')

    def decode_uint(self, first_byte, _flags):
        return self.decode_length(first_byte)

    def decode_negative_int(self, first_byte, _flags):
        return -1 - self.decode_length(first_byte)

    def _byte_string_parts(self):
        while True:
            first_byte = ord(self.read(1))
            if 0x40 <= first_byte < 0x5c:
                yield self.decode_byte_string(first_byte, 0)
            elif first_byte == 0xff:
                break
            else:
                raise CBORDecodingError(f'CBOR object with initial byte {first_byte} '
                                        f'invalid in indefinite-length byte string')

    def decode_byte_string(self, first_byte, _flags):
        length = self.decode_length(first_byte)
        if length is None:
            return b''.join(self._byte_string_parts())
        return self.read(length)

    def _text_string_parts(self):
        while True:
            first_byte = ord(self.read(1))
            if 0x60 <= first_byte < 0x7c:
                yield self.decode_text_string(first_byte, 0)
            elif first_byte == 0xff:
                break
            else:
                raise CBORDecodingError(f'CBOR object with initial byte {first_byte} '
                                        f'invalid in indefinite-length text string')

    def decode_text_string(self, first_byte, _flags):
        length = self.decode_length(first_byte)
        if length is None:
            return ''.join(self._text_string_parts())
        utf8_bytes = self.read(length)
        return utf8_bytes.decode()

    def _list_parts(self, flags):
        read = self.read
        major_decoders = self._major_decoders
        while True:
            first_byte = ord(read(1))
            if first_byte == 0xff:
                break
            yield major_decoders[first_byte >> 5](first_byte, flags)

    def decode_list(self, first_byte, flags):
        length = self.decode_length(first_byte)
        cls = tuple if flags & CBORFlags.IMMUTABLE else list
        if length is None:
            return cls(self._list_parts(flags))
        decode_item = self.decode_item
        return cls(decode_item(flags) for _ in range(length))

    def _dict_parts(self, flags):
        read = self.read
        major_decoders = self._major_decoders
        while True:
            first_byte = ord(read(1))
            if first_byte == 0xff:
                break
            key = major_decoders[first_byte >> 5](first_byte, flags | CBORFlags.IMMUTABLE)
            first_byte = ord(read(1))
            value = major_decoders[first_byte >> 5](first_byte, flags)
            yield (key, value)

    def decode_dict(self, first_byte, flags):
        length = self.decode_length(first_byte)
        cls = FrozenDict if flags & CBORFlags.IMMUTABLE else dict
        if length is None:
            return cls(self._dict_parts(flags))
        decode_item = self.decode_item
        return cls((decode_item(flags | CBORFlags.IMMUTABLE), decode_item(flags))
                   for _ in range(length))

    def decode_tag(self, first_byte, flags):
        tag_value = self.decode_length(first_byte)
        decoder = tag_decoders.get(tag_value)
        if decoder is None:
            return self.on_unknown_tag(tag_value, flags)
        return getattr(self, decoder)(flags)

    def on_unknown_tag(self, tag_value, flags):
        return CBORTag(tag_value, self.decode_item(flags))

    def decode_simple(self, first_byte, flags):
        value = first_byte & 0x1f
        if value < 20 or value > 31:
            return CBORSimple(value)
        if value < 24:
            return CBORSimple.assigned_values[value]
        if value == 24:
            value = ord(self.read(1))
            if value < 32:
                raise CBORDecodingError(f'simple value {value} ecnoded with extension byte')
            return CBORSimple(value)
        if value < 28:
            value, = be_float_unpackers[value - 25](self.read(1 << (value - 24)))
            return value
        if value == 31:
            raise CBORDecodingError('CBOR break outside indefinite-length object')
        self.decode_length(first_byte)  # Raises as unassigned

    def decode_datetime_text(self, flags):
        text = self.decode_item(flags)
        if not isinstance(text, str):
            raise CBORDecodingError('tagged date and time is not text')
        try:
            return datetime_from_enhanced_RFC3339_text(text)
        except ValueError:
            raise CBORDecodingError(f'invalid date and time text: {text}')

    def decode_timestamp(self, flags):
        timestamp = self.decode_item(flags)
        # NOTE: this admits bignums which should perhaps be disallowed
        if not isinstance(timestamp, (int, float)):
            raise CBORDecodingError('tagged timestamp is not an integer or float')
        return datetime.fromtimestamp(timestamp, timezone.utc)

    def decode_uint_bignum(self, flags):
        bignum_encoding = self.decode_item(flags)
        if not isinstance(bignum_encoding, bytes):
            raise CBORDecodingError('bignum payload must be a byte string')
        return int.from_bytes(bignum_encoding, byteorder='big')

    def decode_negative_bignum(self, flags):
        return -1 - self.decode_uint_bignum(flags)

    def decode_decimal(self, flags):
        parts = self.decode_item(flags)
        # NOTE: should require the exponent cannot be a bignum
        if (not isinstance(parts, (list, tuple)) or
               len(parts) != 2 or not all(isinstance(part, int) for part in parts)):
            raise CBORDecodingError('a decimal must be encoded as a 2-integer list')
        exponent, mantissa = parts
        return Decimal(mantissa).scaleb(exponent)

    def decode_rational(self, flags):
        parts = self.decode_item(flags)
        if (not isinstance(parts, (list, tuple)) or
               len(parts) != 2 or not all(isinstance(part, int) for part in parts)):
            raise CBORDecodingError('a rational must be encoded as a 2-integer list')
        numerator, denominator = parts
        return Fraction(numerator, denominator)

    def decode_regexp(self, flags):
        pattern = self.decode_item(flags)
        if not isinstance(pattern, str):
            raise CBORDecodingError('a regexp must be encoded as a text string')
        return re.compile(pattern)

    def decode_uuid(self, flags):
        uuid = self.decode_item(flags)
        if not isinstance(uuid, bytes):
            raise CBORDecodingError('a UUID must be encoded as a byte string')
        return UUID(bytes=uuid)

    def read(self, n):
        result = self._read(n)
        if len(result) == n:
            return result
        raise CBOREOFError(f'need {n:,d} bytes but only {len(result):,d} available')

    def decode_item(self, flags):
        first_byte = ord(self.read(1))
        return self._major_decoders[first_byte >> 5](first_byte, flags)


def loads(binary, **kwargs):
    '''Deserialize a binary object (e.g. a bytes object, a bytearray object, a memoryview
    object) containing a CBOR document to a Python object.

    kwargs: arguments to pass to CBORDecoder
    '''
    decoder = CBORDecoder(BytesIO(binary).read, **kwargs)
    return decoder.decode_item(0)


def load(fp, **kwargs):
    '''Deserialize fp (a .read() supporting file-like object containing a CBOR document) to a
    Python object.

    kwargs: arguments to pass to CBORDecoder
    '''
    decoder = CBORDecoder(fp.read, **kwargs)
    return decoder.decode_item(0)
