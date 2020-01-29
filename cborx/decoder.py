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

from io import BytesIO


from cborx.packing import unpack_byte, unpack_be_uint16, unpack_be_uint32, unpack_be_uint64
from cborx.types import CBOREOFError


# TODO:
# Test: nested indefinite-length byte string and other crud
# Test: nested indefinite-length text string and other crud
# Test: undetermined initial bytes
# Test: misplaced break
# Test: ill-formed indefinite-length text string composed of two incomplete UTF-8 pieces
# Handle indefinite-length list
# Handle indefinite-length map
# Handle / test misplaced break
# Handle non-minimal integer / length decodings
# Handle decoding value-shared encodings


uint_unpackers = [unpack_byte, unpack_be_uint16, unpack_be_uint32, unpack_be_uint64]


class CBORDecoder:

    def __init__(self, read):
        self._read = read
        self._major_decoders = (
            self.decode_length,
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
            length, = uint_unpackers[kind](self._read_safe(1 << kind))
            return length
        if first_byte in {0x5f, 0x7f, 0x9f, 0xbf}:
            return None
        raise CBORDecodingError(f'ill-formed CBOR object with initial byte {first_byte}')

    def decode_negative_int(self, first_byte):
        return -1 - self.decode_length(first_byte)

    def _byte_string_parts(self):
        while True:
            first_byte = ord(self._read_safe(1))
            if 0x40 <= first_byte < 0x5f:
                yield self.decode_byte_string(first_byte)
            elif first_byte == 0xff:
                break
            else:
                raise CBORDecodingError(f'CBOR object with initial byte {first_byte} '
                                        f'invalid in indefinite-length byte string')

    def decode_byte_string(self, first_byte):
        length = self.decode_length(first_byte)
        if length is None:
            return b''.join(self._byte_string_parts())
        return self._read_safe(length)

    def _text_string_parts(self):
        while True:
            first_byte = ord(self._read_safe(1))
            if 0x60 <= first_byte < 0x6f:
                yield self.decode_text_string(first_byte)
            elif first_byte == 0xff:
                break
            else:
                raise CBORDecodingError(f'CBOR object with initial byte {first_byte} '
                                        f'invalid in indefinite-length text string')

    def decode_text_string(self, first_byte):
        length = self.decode_length(first_byte)
        if length is None:
            return ''.join(self._text_string_parts())
        utf8_bytes = self._read_safe(length)
        return utf8_bytes.decode()

    def _list_parts(self):
        self._il_nesting += 1
        decode_item = self.decode_item
        while True:
            yield decode_item()

    def decode_list(self, first_byte):
        length = self.decode_length(first_byte)
        if length is None:
            return list(self._list_parts())
        decode_item = self.decode_item
        return [decode_item() for _ in range(length)]

    def decode_dict(self, first_byte):
        raise NotImplementedError

    def decode_tag(self, first_byte):
        raise NotImplementedError

    def decode_simple(self, first_byte):
        raise NotImplementedError

    def _read_safe(self, n):
        result = self._read(n)
        if len(result) == n:
            return result
        raise CBOREOFError(f'need {n:,d} bytes but only {len(result):,d} available')

    def decode_item(self):
        first_byte = ord(self._read_safe(1))
        return self._major_decoders[first_byte >> 5](first_byte)


def loads(binary, **kwargs):
    '''Deserialize a binary object (e.g. a bytes object, a bytearray object, a memoryview
    object) containing a CBOR document to a Python object.

    kwargs: arguments to pass to CBORDecoder
    '''
    decoder = CBORDecoder(BytesIO(binary).read, **kwargs)
    return decoder.decode_item()


def load(fp, **kwargs):
    '''Deserialize fp (a .read() supporting file-like object containing a CBOR document) to a
    Python object.

    kwargs: arguments to pass to CBORDecoder
    '''
    decoder = CBORDecoder(fp.read, **kwargs)
    return decoder.decode_item()


# def load_stream(bytes_gen, **kwargs):
#     '''A generator of top-level decoded CBOR objects reading from a byte stream.

#     The byte stream yields byte strings of arbitrary size.'''
#     decoder = CBORDecoder(bytes_gen, **kwargs)
#     try:
#         decode_item = decoder.decode_item
#         while True:
#             yield decode_item()
#     except CBOREOFError:
#         pass


# async def aload_stream(bytes_async_gen, **kwargs):
#     '''An asynchronous generator of top-level decoded CBOR objects reading from a byte stream.

#     The byte stream asynchronously yields byte strings of arbitrary size.
#     '''
#     decoder = CBORDecoder(bytes_async_gen, **kwargs)
#     try:
#         async_decode_item = decoder.async_decode_item
#         while True:
#             yield await async_decode_item()
#     except CBOREOFError:
#         pass
