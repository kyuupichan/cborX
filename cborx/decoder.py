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

import itertools
import re
from collections import OrderedDict
from collections.abc import Mapping, Sequence
from datetime import datetime, timezone
from decimal import Decimal
from fractions import Fraction
from enum import IntEnum
from io import BytesIO
from ipaddress import ip_address, ip_network
from uuid import UUID


from cborx.packing import (
    unpack_byte, unpack_be_uint16, unpack_be_uint32, unpack_be_uint64,
    unpack_be_float2, unpack_be_float4, unpack_be_float8,
)
from cborx.types import (
    CBOREOFError, CBORDecodingError, FrozenDict, FrozenOrderedDict, CBORSimple, CBORTag
)
from cborx.util import datetime_from_enhanced_RFC3339_text, bjoin, sjoin


# TODO:
# Handle non-minimal integer / length / float decodings
# Create some kind of incremental decoder


class CBORFlags(IntEnum):
    '''Flags affecting CBORDecoder'''
    IMMUTABLE = 1
    ORDERED = 2


uint_unpackers = [unpack_byte, unpack_be_uint16, unpack_be_uint32, unpack_be_uint64]
be_float_unpackers = [unpack_be_float2, unpack_be_float4, unpack_be_float8]
tag_decoders = {
    0: 'decode_datetime_text',
    1: 'decode_timestamp',
    2: 'decode_unsigned_bignum',
    3: 'decode_negative_bignum',
    4: 'decode_decimal',
    5: 'decode_bigfloat',
    28: 'decode_shared',
    29: 'decode_shared_ref',
    30: 'decode_rational',
    35: 'decode_regexp',
    37: 'decode_uuid',
    258: 'decode_set',
    260: 'decode_ip_address',
    261: 'decode_ip_network',
    272: 'decode_ordered_dict',
}


class CBORDecoder:
    '''Decodes CBOR-encoded data'''

    def __init__(self, read):
        self._read = read
        self._major_decoders = (
            self.decode_unsigned_int,
            self.decode_negative_int,
            self.decode_byte_string,
            self.decode_text_string,
            self.decode_list,
            self.decode_dict,
            self.decode_tag,
            self.decode_simple
        )
        self._pending_id = None
        self._shared_id = itertools.count()
        self._shared_ids = {}

    def _build_mutable(self, cls):
        if self._pending_id is None:
            return cls
        obj = cls()
        self._shared_ids[self._pending_id] = obj
        self._pending_id = None

        def build(*args):
            if isinstance(obj, dict):
                obj.update(*args)
            else:
                obj.extend(*args)
            return obj
        return build

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

    def decode_unsigned_int(self, first_byte, _flags):
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
            return bjoin(self._byte_string_parts())
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
            return sjoin(self._text_string_parts())
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
        cls = tuple if flags & CBORFlags.IMMUTABLE else self._build_mutable(list)
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
        if flags & CBORFlags.ORDERED:
            cls = (FrozenOrderedDict if flags & CBORFlags.IMMUTABLE
                   else self._build_mutable(OrderedDict))
            flags &= ~CBORFlags.ORDERED
        else:
            cls = FrozenDict if flags & CBORFlags.IMMUTABLE else self._build_mutable(dict)
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
        if value != 31:
            self.decode_length(first_byte)  # Raises as unassigned
        raise CBORDecodingError('CBOR break outside indefinite-length object')

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

    def decode_unsigned_bignum(self, flags):
        bignum_encoding = self.decode_item(flags)
        if not isinstance(bignum_encoding, bytes):
            raise CBORDecodingError('bignum payload must be a byte string')
        return int.from_bytes(bignum_encoding, byteorder='big')

    def decode_negative_bignum(self, flags):
        return -1 - self.decode_unsigned_bignum(flags)

    def _decode_exponent_mantissa(self, type_str):
        parts = self.decode_item(0)
        # FIXME: should require the exponent cannot be a bignum
        if (not isinstance(parts, Sequence) or
                len(parts) != 2 or not all(isinstance(part, int) for part in parts)):
            raise CBORDecodingError(f'a {type_str} must be encoded as a 2-integer list')
        return parts

    def decode_decimal(self, _flags):
        exponent, mantissa = self._decode_exponent_mantissa('decimal')
        return Decimal(mantissa).scaleb(exponent)

    def decode_bigfloat(self, _flags):
        exponent, mantissa = self._decode_exponent_mantissa('bigfloat')
        return Decimal(mantissa) * (2 ** exponent)

    def decode_rational(self, flags):
        parts = self.decode_item(flags)
        if (not isinstance(parts, Sequence) or
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

    def decode_set(self, flags):
        members = self.decode_item(flags | CBORFlags.IMMUTABLE)
        if not isinstance(members, Sequence):
            raise CBORDecodingError('a set must be encoded as a list')
        cls = frozenset if flags & CBORFlags.IMMUTABLE else set
        return cls(members)

    def decode_ip_address(self, flags):
        addr_bytes = self.decode_item(flags)
        if not isinstance(addr_bytes, bytes):
            raise CBORDecodingError('an IP address must be encoded as a byte string')
        try:
            return ip_address(addr_bytes)
        except ValueError:
            raise CBORDecodingError(f'invalid IP address: {addr_bytes}') from None

    def decode_ip_network(self, flags):
        # For some daft reason a one-element dictionary was chosen over a pair
        value = self.decode_item(flags)
        if not isinstance(value, Mapping) or len(value) != 1:
            raise CBORDecodingError('an IP network must be encoded as a single-entry map')
        for pair in value.items():
            try:
                return ip_network(pair, strict=False)
            except (ValueError, TypeError):
                raise CBORDecodingError(f'invalid IP network: {pair}') from None

    def decode_ordered_dict(self, flags):
        # see https://github.com/Sekenre/cbor-ordered-map-spec/blob/master/CBOR_Ordered_Map.md
        result = self.decode_item(flags | CBORFlags.ORDERED)
        if not isinstance(result, Mapping):
            raise CBORDecodingError('ordered map tag did not contain a map')
        return result

    def decode_shared(self, flags):
        shared_id = next(self._shared_id)
        self._pending_id = shared_id
        value = self.decode_item(flags)
        self._pending_id = None
        self._shared_ids[shared_id] = value
        return value

    def decode_shared_ref(self, flags):
        shared_id = self.decode_item(flags)
        try:
            return self._shared_ids[shared_id]
        except (TypeError, KeyError):
            raise CBORDecodingError(f'invalid shared reference {shared_id}')

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
