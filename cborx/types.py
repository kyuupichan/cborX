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


class CBORError(Exception):
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

    def __cbor_parts__(self, encoder):
        yield from _length_parts(self._tag, 0xc0)
        yield from encoder.generate_parts(self._value)


class CBORUndefined:

    __instance = None

    def __new__(cls, *args, **kwargs):
        if not cls.__instance:
            cls.__instance = super().__new__(cls, *args, **kwargs)
        return cls.__instance

    def __cbor_parts__(self, encoder):
        yield b'\xf7'


class CBORILObject:
    '''Base class of indefinite-length objects.'''

    def __init__(self, generator):
        self.generator = generator


class CBORILByteString(CBORILObject):

    def __cbor_parts__(self, encoder):
        yield b'\x5f'
        byte_string_parts = encoder.byte_string_parts
        for byte_string in self.generator:
            yield from byte_string_parts(byte_string)
        yield b'\xff'


class CBORILTextString(CBORILObject):

    def __cbor_parts__(self, encoder):
        yield b'\x7f'
        text_string_parts = encoder.text_string_parts
        for text_string in self.generator:
            yield from text_string_parts(text_string)
        yield b'\xff'


class CBORILList(CBORILObject):

    def __cbor_parts__(self, encoder):
        yield b'\x9f'
        generate_parts = encoder.generate_parts
        for item in self.generator:
            yield from generate_parts(item)
        yield b'\xff'


class CBORILDict(CBORILObject):

    def __cbor_parts__(self, encoder):
        yield b'\xbf'
        generate_parts = encoder.generate_parts
        for key, kvalue in self.generator:
            yield from generate_parts(key)
            yield from generate_parts(kvalue)
        yield b'\xff'
