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


from packing import unpack_byte


initial_byte_table = []


class ReservedError(Exception):
    pass


class CBORSyntaxError(Exception):
    pass


class CBORBreak(Exception):
    pass


def raise_reserved(read, init_byte):
    raise ReservedError(f'{an initial byte of {init_byte} is reserved}')


def read_uint8(read):
    return ord(read(1))


def read_uint16(read):
    result, = unpack_be_uint16(read(2))
    return result


def read_uint32(read):
    result, = unpack_be_uint32(read(4))
    return result


def read_uint64(read):
    result, = unpack_be_uint64(read(8))
    return result


def read_indefinite_length_byte_string(read):
    def parts(read):
        try:
            while True:
                yield read_definite_length_byte_string(read)
        except CBORBreakException:
            pass

    return b''.join(parts(read))


def read_byte_string(read, init_byte):
    length = read_length(init_byte)
    if length == CBOR_INDEFINITE_LENGTH:
        return read_indefinite_length_byte_string(read)
    return read(length)


def read_definite_length_byte_string(read):
    init_byte = read(1)
    if init_byte & 0xe0 != 64:
        if init_byte == CBOR_BREAK:
            raise CBORBreakException
        raise CBORSyntaxError(f'expected a definite length byte string')
    length = read_length(init_byte)
    if length == CBOR_INDEFINITE_LENGTH:
        raise CBORSyntaxError(f'nested indefinite length byte string')
    return read(length)


def read_definite_length_text_string(read):
    init_byte = read(1)
    if init_byte & 0xe0 != 96:
        if init_byte == CBOR_BREAK:
            raise CBORBreakException
        raise CBORSyntaxError(f'expected a definite length text string')
    length = read_length(init_byte)
    if length == CBOR_INDEFINITE_LENGTH:
        raise CBORSyntaxError(f'nested indefinite length text string')
    return read(length)


def read_indefinite_length_text_string(read):
    def parts(read):
        try:
            while True:
                yield read_definite_length_text_string(read)
        except CBORBreakException:
            pass

    return ''.join(parts(read))


def read_text_string(read, init_byte):
    length = read_length(init_byte)
    if length == CBOR_INDEFINITE_LENGTH:
        return read_indefinite_length_text_string(read)
    return read(length).decode()


def _init_table():
    ibt = initial_byte_table

    # Unsigned integer literal
    for n in range(0, 24):
        ibt[n] = lambda read : n
    ibt[24] = read_uint8
    ibt[25] = read_uint16
    ibt[26] = read_uint32
    ibt[27] = read_uint64
    for n in range(28, 32):
        ibt[n] = partial(raise_reserved, init_byte=n)

    # Signed integer literal
    for n in range(0, 24):
        value = -1 - n
        ibt[n + 32] = lambda read : value
    ibt[24 + 32] = lambda read : - 1 - read_uint8(read)
    ibt[25 + 32] = lambda read : - 1 - read_uint16(read)
    ibt[26 + 32] = lambda read : - 1 - read_uint32(read)
    ibt[27 + 32] = lambda read : - 1 - read_uint64(read)
    for n in range(28, 32):
        ibt[n + 32] = partial(raise_reserved, init_byte=n + 32)

    # Byte strings
    for n in range(0, 24):
        ibt[n + 64] = lambda read : read(n)
    ibt[24 + 64] = lambda read : read(read_uint8(read))
    ibt[25 + 64] = lambda read : read(read_uint16(read))
    ibt[26 + 64] = lambda read : read(read_uint32(read))
    ibt[27 + 64] = lambda read : read(read_uint64(read))
    for n in range(28, 31):
        ibt[n + 64] = partial(raise_reserved, init_byte=n + 64)
    ibt[31 + 64] = read_byte_string_indefinite

    # Text strings
    for n in range(0, 24):
        ibt[n + 96] = lambda read : to_text_string(read(n))
    ibt[24 + 96] = lambda read : to_text_string(read(read_uint8(read)))
    ibt[25 + 96] = lambda read : to_text_string(read(read_uint16(read)))
    ibt[26 + 96] = lambda read : to_text_string(read(read_uint32(read)))
    ibt[27 + 96] = lambda read : to_text_string(read(read_uint64(read)))
    for n in range(28, 31):
        ibt[n + 96] = partial(raise_reserved, init_byte=n + 96)
    ibt[31 + 96] = lambda read: read_text_string_indefinite(read)
