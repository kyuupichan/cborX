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

import attr

from collections import OrderedDict
from collections.abc import Mapping
from decimal import Decimal

from cborx.packing import pack_byte, pack_be_uint16, pack_be_uint32, pack_be_uint64
from cborx.util import bjoin, sjoin


class CBORError(Exception):
    pass


class CBORDecodingError(CBORError):
    pass


class CBOREOFError(CBORDecodingError):
    pass


class CBOREncodingError(CBORError):
    pass


class CBORTag:

    def __init__(self, tag, value):
        if not isinstance(tag, int):
            raise TypeError(f'tag {tag} must be an integer')
        if not 0 <= tag < 65536:
            raise ValueError(f'tag value {tag} out of range')
        self._tag = tag
        self._value = value

    def __eq__(self, other):
        return (isinstance(other, CBORTag)
                and self._tag == other._tag and self._value == other._value)

    def __encode_cbor__(self, encoder):
        return encode_length(self._tag, 0xc0) + encoder.encode_item(self._value)


class CBORUndefined:

    def __encode_cbor__(self, encoder):
        return b'\xf7'


# A singleton
Undefined = CBORUndefined()


class CBORSimple:

    assigned_values = {
        20: False,
        21: True,
        22: None,
        23: Undefined,
    }

    def __init__(self, value):
        if not isinstance(value, int):
            raise TypeError(f'simple value {value} must be an integer')
        if not ((0 <= value <= 19) or (32 <= value <= 255)):
            raise ValueError(f'simple value {value} out of range')
        self._value = value

    def __eq__(self, other):
        return isinstance(other, CBORSimple) and self._value == other._value

    def __encode_cbor__(self, encoder):
        if self._value <= 31:
            return pack_byte(0xe0 + self._value)
        else:
            return b'\xf8' + pack_byte(self._value)


class CBORILObject:
    '''Base class of indefinite-length objects.'''

    def __init__(self, generator):
        self.generator = generator


class CBORILByteString(CBORILObject):

    def __encode_cbor__(self, encoder):
        encode_byte_string = encoder.encode_byte_string
        if encoder.realize_il:
            return encode_byte_string(bjoin(self.generator))
        else:
            parts = (encode_byte_string(byte_string) for byte_string in self.generator)
            return b'\x5f' + bjoin(parts) + b'\xff'


class CBORILTextString(CBORILObject):

    def __encode_cbor__(self, encoder):
        encode_text_string = encoder.encode_text_string
        if encoder.realize_il:
            return encode_text_string(sjoin(self.generator))
        else:
            parts = (encode_text_string(text_string) for text_string in self.generator)
            return b'\x7f' + bjoin(parts) + b'\xff'


class CBORILList(CBORILObject):

    def __encode_cbor__(self, encoder):
        if encoder.realize_il:
            return encoder.encode_sorted_list(tuple(self.generator))
        else:
            encode_item = encoder.encode_item
            parts = (encode_item(item) for item in self.generator)
            return b'\x9f' + bjoin(parts) + b'\xff'


class CBORILDict(CBORILObject):

    def __encode_cbor__(self, encoder):
        if encoder.realize_il:
            return encoder.encode_sorted_dict(tuple(self.generator), encoder.sort_method)
        else:
            encode_item = encoder.encode_item
            parts = (encode_item(key) + encode_item(kvalue) for key, kvalue in self.generator)
            return b'\xbf' + bjoin(parts) + b'\xff'


@attr.s(slots=True, frozen=True)
class BigFloat:
    '''Represents a BigFloat.  Value is mantissa * pow(2, exponent).  There is
    no representation of infinities or NaNs, use float or Decimal for those.'''
    mantissa = attr.ib()
    exponent = attr.ib()

    def __encode_cbor__(self, encoder):
        return encoder._encode_exponent_mantissa(5, self.exponent, self.mantissa)

    def to_decimal(self):
        return Decimal(self.mantissa) * (Decimal(2) ** self.exponent)


class FrozenDict(Mapping):

    dict_class = dict

    def __init__(self, *args, **kwargs):
        d = self.dict_class(*args, **kwargs)
        self._dict = d
        self.__contains__ == d.__contains__
        self.keys = d.keys
        self.values__ = d.values
        self.items = d.items
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
        return f'<{self.__class__.__name__}, {self._dict!r}>'


class FrozenOrderedDict(FrozenDict):

    dict_class = OrderedDict


def encode_length(length, major):
    if length < 24:
        return pack_byte(major + length)
    elif length < 256:
        return pack_byte(major + 24) + pack_byte(length)
    elif length < 65536:
        return pack_byte(major + 25) + pack_be_uint16(length)
    elif length < 4294967296:
        return pack_byte(major + 26) + pack_be_uint32(length)
    elif length < 18446744073709551616:
        return pack_byte(major + 27) + pack_be_uint64(length)
    else:
        raise OverflowError
