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

'''CBOR classes.'''

from collections import OrderedDict
from collections.abc import Mapping
from functools import total_ordering
from decimal import Decimal

import attr

from cborx.packing import pack_byte, pack_be_uint16, pack_be_uint32, pack_be_uint64
from cborx.util import bjoin, sjoin


class CBORError(Exception):
    '''Base exception of cborX library errors'''


class CBORDecodingError(CBORError):
    '''Base exception of cborX decoding errors'''


class CBOREncodingError(CBORError):
    '''Base exception of cborX encoding errors'''


class CBOREOFError(CBORDecodingError):
    '''Exception raised on premature end-of-data'''


@attr.s(slots=True, order=True, frozen=True)
class CBORTag:
    '''Represents a value wrapped by a CBOR tag'''

    tag = attr.ib()
    value = attr.ib()

    @tag.validator
    def _validate_tag(self, attribute, value):
        if not isinstance(value, int):
            raise TypeError(f'tag {value} must be an integer')
        if value < 0 or value > 18446744073709551615:
            raise ValueError(f'tag {value} out of range')

    def __encode_cbor__(self, encoder):
        return encode_length(self.tag, 0xc0) + encoder.encode_item(self.value)


class CBORUndefined:
    '''The class of the CBOR Undefined singleton'''

    def __encode_cbor__(self, encoder):
        return b'\xf7'

    def __repr__(self):
        return 'Undefined'


# A singleton
Undefined = CBORUndefined()


@attr.s(slots=True, order=True, frozen=True)
class CBORSimple:
    '''Represents a CBOR Simple object'''

    assigned_values = {
        20: False,
        21: True,
        22: None,
        23: Undefined,
    }

    value = attr.ib()

    @value.validator
    def _validate_value(self, attribute, value):
        if not isinstance(value, int):
            raise TypeError(f'simple value {value} must be an integer')
        if not ((0 <= value <= 19) or (32 <= value <= 255)):
            raise ValueError(f'simple value {value} out of range')

    def __encode_cbor__(self, encoder):
        if self.value <= 31:
            return pack_byte(0xe0 + self.value)

        return b'\xf8' + pack_byte(self.value)


class CBORILObject:
    '''Base class of indefinite-length objects'''

    def __init__(self, generator):
        self.generator = generator


class CBORILByteString(CBORILObject):
    '''A CBOR indefinite-length byte string'''

    def __encode_cbor__(self, encoder):
        encode_byte_string = encoder.encode_byte_string
        if encoder.realize_il:
            return encode_byte_string(bjoin(self.generator))

        parts = (encode_byte_string(byte_string) for byte_string in self.generator)
        return b'\x5f' + bjoin(parts) + b'\xff'


class CBORILTextString(CBORILObject):
    '''A CBOR indefinite-length text string'''

    def __encode_cbor__(self, encoder):
        encode_text_string = encoder.encode_text_string
        if encoder.realize_il:
            return encode_text_string(sjoin(self.generator))

        parts = (encode_text_string(text_string) for text_string in self.generator)
        return b'\x7f' + bjoin(parts) + b'\xff'


class CBORILList(CBORILObject):
    '''A CBOR indefinite-length list'''

    def __encode_cbor__(self, encoder):
        if encoder.realize_il:
            return encoder.encode_sorted_list(tuple(self.generator))

        encode_item = encoder.encode_item
        parts = (encode_item(item) for item in self.generator)
        return b'\x9f' + bjoin(parts) + b'\xff'


class CBORILDict(CBORILObject):
    '''A CBOR indefinite-length map'''

    def __encode_cbor__(self, encoder):
        if encoder.realize_il:
            return encoder.encode_sorted_dict(tuple(self.generator), encoder.sort_method)

        encode_item = encoder.encode_item
        parts = (encode_item(key) + encode_item(kvalue) for key, kvalue in self.generator)
        return b'\xbf' + bjoin(parts) + b'\xff'


@total_ordering
@attr.s(slots=True, frozen=True, eq=False, order=False)
class BigFloat:
    '''Represents a BigFloat.  Value is mantissa * pow(2, exponent).  There is
    no representation of infinities or NaNs, use float or Decimal for those.'''
    mantissa = attr.ib()
    exponent = attr.ib()

    def __eq__(self, other):
        return self.to_decimal() == other

    def __lt__(self, other):
        return self.to_decimal() < other

    def __encode_cbor__(self, encoder):
        return encoder._encode_exponent_mantissa(5, self.exponent, self.mantissa)

    def to_decimal(self):
        '''Convert to a Decimal object'''
        return Decimal(self.mantissa) * (Decimal(2) ** self.exponent)


class FrozenDict(Mapping):
    '''A frozen (immutable) dictionary'''

    dict_class = dict

    def __init__(self, *args, **kwargs):
        dct = self.dict_class(*args, **kwargs)
        self._dict = dct
        self.__contains__ = dct.__contains__
        self.keys = dct.keys
        self.values__ = dct.values
        self.items = dct.items
        self._hash = None

    def __getitem__(self, key):
        return self._dict.__getitem__(key)

    def __iter__(self):
        return iter(self._dict)

    def __len__(self):
        return len(self._dict)

    def __hash__(self):
        if self._hash is None:
            self._hash = hash((tuple(self), tuple(self.values())))
        return self._hash

    def __repr__(self):
        return f'<{self.__class__.__name__} {self._dict!r}>'


class FrozenOrderedDict(FrozenDict):
    '''A frozen (immuatable) ordered dictionary.'''

    dict_class = OrderedDict


def encode_length(length, major):
    '''Return the CBOR encoding of a length for the given (shifted) major value.'''
    if length < 24:
        return pack_byte(major + length)
    if length < 256:
        return pack_byte(major + 24) + pack_byte(length)
    if length < 65536:
        return pack_byte(major + 25) + pack_be_uint16(length)
    if length < 4294967296:
        return pack_byte(major + 26) + pack_be_uint32(length)
    if length < 18446744073709551616:
        return pack_byte(major + 27) + pack_be_uint64(length)
    raise OverflowError
