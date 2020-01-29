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


from cborx.packing import pack_byte, pack_be_uint16, pack_be_uint32, pack_be_uint64

bjoin = b''.join
sjoin = ''.join


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


class CBORSimple:

    def __init__(self, value):
        if not isinstance(value, int):
            raise TypeError(f'simple value {value} must be an integer')
        if not 0 <= value < 256 or (24 <= value < 31):
            raise ValueError(f'simple value {value} out of range')
        self._value = value

    def __encode_cbor__(self, encoder):
        if self._value <= 31:
            return pack_byte(0xe0 + self._value)
        else:
            return b'\xf8' + pack_byte(self._value)


class CBORUndefined:

    __instance = None

    def __new__(cls, *args, **kwargs):
        if not cls.__instance:
            cls.__instance = super().__new__(cls, *args, **kwargs)
        return cls.__instance

    def __encode_cbor__(self, encoder):
        return b'\xf7'


class CBORILObject:
    '''Base class of indefinite-length objects.'''

    def __init__(self, generator):
        self.generator = generator


class CBORILByteString(CBORILObject):

    def __encode_cbor__(self, encoder):
        encode_byte_string = encoder.encode_byte_string
        if encoder._options.realize_il:
            return encode_byte_string(bjoin(self.generator))
        else:
            parts = (encode_byte_string(byte_string) for byte_string in self.generator)
            return b'\x5f' + bjoin(parts) + b'\xff'


class CBORILTextString(CBORILObject):

    def __encode_cbor__(self, encoder):
        encode_text_string = encoder.encode_text_string
        if encoder._options.realize_il:
            return encode_text_string(sjoin(self.generator))
        else:
            parts = (encode_text_string(text_string) for text_string in self.generator)
            return b'\x7f' + bjoin(parts) + b'\xff'


class CBORILList(CBORILObject):

    def __encode_cbor__(self, encoder):
        if encoder._options.realize_il:
            return encoder.encode_sorted_list(tuple(self.generator))
        else:
            encode_item = encoder.encode_item
            parts = (encode_item(item) for item in self.generator)
            return b'\x9f' + bjoin(parts) + b'\xff'


class CBORILDict(CBORILObject):

    def __encode_cbor__(self, encoder):
        if encoder._options.realize_il:
            return encoder.encode_sorted_dict(tuple(self.generator),
                                              encoder._options.sort_method)
        else:
            encode_item = encoder.encode_item
            parts = (encode_item(key) + encode_item(kvalue) for key, kvalue in self.generator)
            return b'\xbf' + bjoin(parts) + b'\xff'


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
