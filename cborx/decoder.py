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
from array import array
from collections import OrderedDict
from collections.abc import Mapping, Sequence
from contextlib import contextmanager
from datetime import datetime, timezone
from decimal import Decimal
from enum import IntEnum
from fractions import Fraction
from io import BytesIO
from ipaddress import ip_address, ip_network
from uuid import UUID


from cborx.packing import (
    unpack_byte, unpack_be_uint16, unpack_be_uint32, unpack_be_uint64,
    unpack_be_float2, unpack_be_float4, unpack_be_float8, pack_cbor_short_float,
)
from cborx.types import (
    BadInitialByteError, MisplacedBreakError, BadSimpleError, UnexpectedEOFError,
    UnconsumedDataError, TagTypeError, TagValueError, StringEncodingError, DuplicateKeyError,
    DeterministicError,
    FrozenDict, FrozenOrderedDict, CBORSimple, CBORTag, BigNum, BigFloat
)
from cborx.util import datetime_from_enhanced_RFC3339_text, bjoin, sjoin, tag_to_typecode_map


__all__ = ('load', 'loads', 'CBORDecoder', 'DeterministicFlags')


class DecoderFlags(IntEnum):
    '''Flags affecting CBORDecoder'''
    IMMUTABLE = 1
    ORDERED = 2
    RETAIN_BIGNUMS = 4


class DeterministicFlags(IntEnum):
    NONE       = 0x00
    LENGTH     = 0x01
    FLOAT      = 0x02
    REALIZE_IL = 0x04
    SORTING    = 0x08
    ALL        = 0xff


uint_unpackers = [unpack_byte, unpack_be_uint16, unpack_be_uint32, unpack_be_uint64]
uint_minima = [24, 1 << 8, 1 << 16, 1 << 32]
be_float_unpackers = [unpack_be_float2, unpack_be_float4, unpack_be_float8]
default_tag_decoders = {
    0: 'decode_datetime_text',
    1: 'decode_timestamp',
    2: 'decode_bignum',
    3: 'decode_bignum',
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
default_tag_decoders.update({tag: 'decode_array' for tag in tag_to_typecode_map})


class CBORDecoder:
    '''Decodes CBOR-encoded data'''

    def __init__(self, read, retain_bignums=False, tag_decoders=None, simple_value=None,
                 check_eof=True, deterministic=DeterministicFlags.NONE):
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
        self._flags = 0
        if retain_bignums:
            self._flags |= DecoderFlags.RETAIN_BIGNUMS
        self._custom_tag_decoders = tag_decoders or {}
        self._tag_decoders = {}
        self._simple_value = simple_value or CBORSimple
        self._check_eof = check_eof
        self._deterministic = deterministic

    @contextmanager
    def flags_set(self, mask):
        old_flags = self._flags
        self._flags |= mask
        yield
        self._flags = old_flags

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
            if self._deterministic & DeterministicFlags.LENGTH and length < uint_minima[kind]:
                if first_byte < 0x20:
                    raise DeterministicError(f'value {length:,d} is not minimally encoded')
                elif first_byte < 0x40:
                    raise DeterministicError(f'value {-1 - length:,d} is not minimally encoded')
                else:
                    raise DeterministicError(f'length {length:,d} is not minimally encoded')
            return length
        if first_byte in {0x5f, 0x7f, 0x9f, 0xbf}:
            return -1
        raise BadInitialByteError(f'bad initial byte 0x{first_byte:x}')

    def decode_unsigned_int(self, first_byte):
        return self.decode_length(first_byte)

    def decode_negative_int(self, first_byte):
        return -1 - self.decode_length(first_byte)

    def _byte_string_parts(self):
        while True:
            first_byte = ord(self.read(1))
            if 0x40 <= first_byte < 0x5c:
                yield self.decode_byte_string(first_byte)
            elif first_byte == 0xff:
                break
            else:
                raise BadInitialByteError(f'bad initial byte 0x{first_byte:x} in '
                                          f'indefinite-length byte string')

    def decode_byte_string(self, first_byte):
        length = self.decode_length(first_byte)
        if length == -1:
            return bjoin(self._byte_string_parts())
        return self.read(length)

    def _text_string_parts(self):
        while True:
            first_byte = ord(self.read(1))
            if 0x60 <= first_byte < 0x7c:
                yield self.decode_text_string(first_byte)
            elif first_byte == 0xff:
                break
            else:
                raise BadInitialByteError(f'bad initial byte 0x{first_byte:x} in '
                                          f'indefinite-length text string')

    def decode_text_string(self, first_byte):
        length = self.decode_length(first_byte)
        if length == -1:
            return sjoin(self._text_string_parts())
        utf8_bytes = self.read(length)
        try:
            return utf8_bytes.decode()
        except UnicodeDecodeError:
            raise StringEncodingError('invalid string encoding')

    def _list_parts(self):
        read = self.read
        major_decoders = self._major_decoders
        while True:
            first_byte = ord(read(1))
            if first_byte == 0xff:
                break
            yield major_decoders[first_byte >> 5](first_byte)

    def decode_list(self, first_byte):
        length = self.decode_length(first_byte)
        cls = tuple if self._flags & DecoderFlags.IMMUTABLE else self._build_mutable(list)
        if length == -1:
            return cls(self._list_parts())
        decode_item = self.decode_item
        return cls(decode_item() for _ in range(length))

    def _key_value_pairs(self, keys, length):
        read = self.read
        major_decoders = self._major_decoders
        keys_append = keys.append
        decode_item = self.decode_item
        while length:
            first_byte = ord(read(1))
            if first_byte == 0xff and length < 0:
                break
            with self.flags_set(DecoderFlags.IMMUTABLE):
                key = major_decoders[first_byte >> 5](first_byte)
            keys_append(key)
            yield key, decode_item()
            length -= 1

    def decode_dict(self, first_byte):
        length = self.decode_length(first_byte)
        if self._flags & DecoderFlags.ORDERED:
            cls = (FrozenOrderedDict if self._flags & DecoderFlags.IMMUTABLE
                   else self._build_mutable(OrderedDict))
            self._flags &= ~DecoderFlags.ORDERED
        else:
            cls = FrozenDict if self._flags & DecoderFlags.IMMUTABLE else self._build_mutable(dict)

        keys = []
        value = cls(self._key_value_pairs(keys, length))
        if len(value) != len(keys):
            seen = set()
            dups = [key for key in keys if key in seen or seen.add(key)]
            dups_str = ''.join(f'{key!r}' for key in dups)
            raise DuplicateKeyError(f'map has {len(dups):,d} duplicate keys: {dups_str}')

        return value

    def decode_tag(self, first_byte):
        tag_value = self.decode_length(first_byte)
        decoder = self._tag_decoders.get(tag_value)  # Cache
        if not decoder:
            decoder = self._custom_tag_decoders.get(tag_value)
            if not decoder:
                decoder_name = default_tag_decoders.get(tag_value)
                if decoder_name is None:
                    return CBORTag(tag_value, self.decode_item())
                decoder = getattr(self.__class__, decoder_name)
            self._tag_decoders[tag_value] = decoder
        return decoder(self, tag_value)

    def decode_simple(self, first_byte):
        value = first_byte & 0x1f
        if value < 20:
            return self._simple_value(value)
        if value < 24:
            return CBORSimple.assigned_values[value]
        if value == 24:
            value = ord(self.read(1))
            if value < 32:
                raise BadSimpleError(f'simple value 0x{value:x} encoded with extra byte')
            return self._simple_value(value)
        if value < 28:
            length = 1 << (value - 24)
            float_value, = be_float_unpackers[value - 25](self.read(length))
            if value > 25 and self._deterministic & DeterministicFlags.FLOAT:
                if length != len(pack_cbor_short_float(float_value)) - 1:
                    raise DeterministicError(f'float {float_value} is not minimally encoded')
            return float_value
        if value == 31:
            raise MisplacedBreakError('break stop code outside indefinite-length object')
        raise BadInitialByteError(f'bad initial byte 0x{first_byte:x}')

    def decode_datetime_text(self, _tag_value):
        text = self.decode_item()
        if not isinstance(text, str):
            raise TagTypeError('tagged date and time is not text')
        try:
            return datetime_from_enhanced_RFC3339_text(text)
        except ValueError:
            raise TagValueError(f'invalid date and time text {text!r}')

    def decode_timestamp(self, _tag_value):
        # Bignums are invalid as timestamps
        with self.flags_set(DecoderFlags.RETAIN_BIGNUMS):
            timestamp = self.decode_item()
        if not isinstance(timestamp, (int, float)):
            raise TagTypeError('tagged timestamp is not a plain integer or float')
        return datetime.fromtimestamp(timestamp, timezone.utc)

    def decode_bignum(self, tag_value):
        bignum_encoding = self.decode_item()
        if not isinstance(bignum_encoding, bytes):
            raise TagTypeError('bignum payload must be a byte string')
        value = int.from_bytes(bignum_encoding, byteorder='big')
        if tag_value == 0x03:
            value = -1 - value
        if self._flags & DecoderFlags.RETAIN_BIGNUMS:
            return BigNum(value)
        return value

    def _decode_mantissa_exponent(self, type_str):
        # Retain bignums to catch invalid exponent encodings
        with self.flags_set(DecoderFlags.RETAIN_BIGNUMS):
            parts = self.decode_item()
        if not isinstance(parts, Sequence) or len(parts) != 2:
            raise TagTypeError(f'{type_str} must be encoded as a list [exponent, mantissa]')
        exponent, mantissa = parts
        if not isinstance(exponent, int):  # Note: exponent bignum is invalid
            raise TagTypeError(f'{type_str} has an invalid exponent {exponent}')
        if isinstance(mantissa, BigNum):
            mantissa = mantissa.value
        elif not isinstance(mantissa, int):
            raise TagTypeError(f'{type_str} has an invalid mantissa {mantissa}')
        return mantissa, exponent

    def decode_decimal(self, _tag_value):
        mantissa, exponent = self._decode_mantissa_exponent('decimal')
        return Decimal(mantissa).scaleb(exponent)

    def decode_bigfloat(self, _tag_value):
        mantissa, exponent = self._decode_mantissa_exponent('bigfloat')
        return BigFloat(mantissa, exponent)

    def decode_rational(self, _tag_value):
        parts = self.decode_item()
        if (not isinstance(parts, Sequence) or
                len(parts) != 2 or not all(isinstance(part, int) for part in parts)):
            raise TagTypeError('a rational must be encoded as a 2-integer list')
        numerator, denominator = parts
        if denominator == 0:
            raise TagValueError('rational has zero denominator')
        return Fraction(numerator, denominator)

    def decode_array(self, tag_value):
        array_bytes = self.decode_item()
        if not isinstance(array_bytes, bytes):
            raise TagTypeError('an array must be encoded as a byte string')
        return array(tag_to_typecode_map[tag_value], array_bytes)

    def decode_regexp(self, _tag_value):
        pattern = self.decode_item()
        if not isinstance(pattern, str):
            raise TagTypeError('a regexp must be encoded as a text string')
        return re.compile(pattern)

    def decode_uuid(self, _tag_value):
        uuid = self.decode_item()
        if not isinstance(uuid, bytes):
            raise TagTypeError('a UUID must be encoded as a byte string')
        return UUID(bytes=uuid)

    def decode_set(self, _tag_value):
        with self.flags_set(DecoderFlags.IMMUTABLE):
            members = self.decode_item()
        if not isinstance(members, Sequence):
            raise TagTypeError('a set must be encoded as a list')
        cls = frozenset if self._flags & DecoderFlags.IMMUTABLE else set
        return cls(members)

    def decode_ip_address(self, _tag_value):
        addr_bytes = self.decode_item()
        if not isinstance(addr_bytes, bytes):
            raise TagTypeError('an IP address must be encoded as a byte string')
        try:
            return ip_address(addr_bytes)
        except ValueError:
            raise TagValueError(f'invalid IP address: {addr_bytes}') from None

    def decode_ip_network(self, _tag_value):
        # For some daft reason a one-element dictionary was chosen over a pair
        value = self.decode_item()
        if not isinstance(value, Mapping):
            raise TagTypeError('an IP network must be encoded as a map')
        if len(value) != 1:
            raise TagValueError('an IP network must be encoded as a single-entry map')
        for pair in value.items():
            if not (isinstance(pair[0], bytes) and isinstance(pair[1], int)):
                raise TagTypeError('invalid IP network encoding {pair!r}')
            try:
                return ip_network(pair, strict=False)
            except (ValueError, TypeError):  # library bug raises a TypeError in some cases
                raise TagValueError(f'invalid IP network {pair}') from None

    def decode_ordered_dict(self, _tag_value):
        # see https://github.com/Sekenre/cbor-ordered-map-spec/blob/master/CBOR_Ordered_Map.md
        self._flags |= DecoderFlags.ORDERED
        result = self.decode_item()
        if not isinstance(result, Mapping):
            raise TagTypeError('ordered map not encoded as a map')
        return result

    def decode_shared(self, _tag_value):
        shared_id = next(self._shared_id)
        self._pending_id = shared_id
        value = self.decode_item()
        self._pending_id = None
        self._shared_ids[shared_id] = value
        return value

    def decode_shared_ref(self, _tag_value):
        shared_id = self.decode_item()
        if not isinstance(shared_id, int):
            raise TagTypeError(f'shared reference must be an integer')
        try:
            return self._shared_ids[shared_id]
        except KeyError:
            raise TagValueError(f'non-existent shared reference {shared_id}') from None

    def read(self, n):
        result = self._read(n)
        if len(result) == n:
            return result
        raise UnexpectedEOFError(f'need {n:,d} bytes but only {len(result):,d} available')

    def decode_item(self):
        first_byte = ord(self.read(1))
        return self._major_decoders[first_byte >> 5](first_byte)

    def decode(self):
        result = self.decode_item()
        if self._check_eof and self._read(1):
            raise UnconsumedDataError('not all input consumed')

        return result


def loads(binary, **kwargs):
    '''Deserialize a binary object (e.g. a bytes object, a bytearray object, a memoryview
    object) containing a CBOR document to a Python object.

    kwargs: arguments to pass to CBORDecoder
    '''
    decoder = CBORDecoder(BytesIO(binary).read, **kwargs)
    return decoder.decode()


def load(fp, **kwargs):
    '''Deserialize fp (a .read() supporting file-like object containing a CBOR document) to a
    Python object.

    kwargs: arguments to pass to CBORDecoder
    '''
    decoder = CBORDecoder(fp.read, **kwargs)
    return decoder.decode()
