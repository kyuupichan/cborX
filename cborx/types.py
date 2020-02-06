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

from cborx.packing import pack_byte, pack_cbor_length
from cborx.util import bjoin, sjoin

__all__ = (
    'Undefined', 'CBORSimple', 'CBORTag',
    'FrozenDict', 'FrozenOrderedDict', 'BigFloat', 'BigNum',
    'CBORILObject', 'CBORILByteString', 'CBORILTextString', 'CBORILList', 'CBORILDict',
    'CBORError', 'EncodingError', 'DecodingError', 'IllFormedError', 'InvalidError',
    'BadInitialByteError', 'MisplacedBreakError', 'BadSimpleError', 'UnexpectedEOFError',
    'UnconsumedDataError', 'TagError', 'StringEncodingError',
    'DuplicateKeyError', 'DeterministicError',
)

# Exception class hierarchy:
#
# CBORError
#   EncodingError
#   DecodingError
#     IllFormedError
#       BadInitialByteError
#       MisplacedBreakError
#       BadSimpleError
#       UnexpectedEOFError
#       UnconsumedDataError
#     InvalidError
#       TagError
#       StringEncodingError
#       DuplicateKeyError
#       DeterministicError


class CBORError(Exception):
    '''Base exception of cborX library errors'''


class DecodingError(CBORError):
    '''Base exception of cborX decoding errors'''


class EncodingError(CBORError):
    '''Base exception of cborX encoding errors'''


class IllFormedError(DecodingError):
    '''Indicates ill-formed CBOR'''


class BadInitialByteError(IllFormedError):
    '''Indicates initial byte of an encoded object is bad'''
    # This is also used for indefinite-length byte and text strings whose next item is not
    # a definite-length string of the same type


class MisplacedBreakError(IllFormedError):
    '''Indicates a break was found outside an indefinite-length object'''


class BadSimpleError(IllFormedError):
    '''Indicates use of a simple value less than 32 encoded with an unnecessary extra byte'''


class UnexpectedEOFError(IllFormedError):
    '''Indicates premature end-of-data'''


class UnconsumedDataError(IllFormedError):
    '''Indicates data remains in the byte stream after decoding is complete'''


class InvalidError(DecodingError):
    '''Indicates CBOR that is well-formed but that violates a validity rule'''


class TagError(InvalidError):
    '''Indicates a tag's payload (or an element of it) has an invalid type or value'''


class StringEncodingError(InvalidError):
    '''Indicates a string which could not be decoded to UTF-8'''


class DuplicateKeyError(InvalidError):
    '''Indicates a duplicate key was found when decoding a map'''


class DeterministicError(InvalidError):
    '''Indicates the CBOR encoding was not deterministic'''


@attr.s(slots=True, order=True, frozen=True)
class CBORTag:
    '''Represents a value wrapped by a CBOR tag'''

    tag = attr.ib()
    value = attr.ib()

    @tag.validator
    def _validate_tag(self, _attribute, value):
        if not isinstance(value, int):
            raise TypeError(f'tag {value} must be an integer')
        if value < 0 or value > 18446744073709551615:
            raise ValueError(f'tag {value} out of range')

    def __encode_cbor__(self, encoder):
        return pack_cbor_length(self.tag, 0xc0) + encoder.encode_item(self.value)


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
    def _validate_value(self, _attribute, value):
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


@attr.s(slots=True, frozen=True)
class BigNum:
    '''Represents a bignum integer in the CBOR sense.

    A generic decoder must be able to distinguish a bignum from an integer of major type 0
    or 1.  The decoder by default will decode a bignum (tag 2 or 3) as am integer, but an
    option will force it to return it as a BigNum instance.

    The encoder, by default, will encode a BigNum as a CBOR BigNum even if it could be
    encoded as a major type 0 or 1 integer; an option can force it to encode it as a major
    type 0 or 1 integer if possible.

    At present a BigNum can only be compared to other BigNums; in particular it does not
    equal its integer value.
    '''
    value = attr.ib()

    @value.validator
    def _validate_value(self, _attribute, value):
        if not isinstance(value, int):
            raise TypeError(f'bignum value {value} must be an integer')

    def __encode_cbor__(self, encoder):
        return encoder.encode_bignum(self.value)


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
