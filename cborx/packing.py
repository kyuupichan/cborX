# Copyright (c) 2018, Neil Booth
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
# and warranty status of this software.

'''Encourage efficient bytes manipulation'''

from struct import Struct


struct_le_i = Struct('<i')
struct_le_q = Struct('<q')
struct_le_H = Struct('<H')
struct_le_I = Struct('<I')
struct_le_Q = Struct('<Q')
struct_be_H = Struct('>H')
struct_be_I = Struct('>I')
struct_be_Q = Struct('>Q')
struct_be_e = Struct('>e')
struct_be_f = Struct('>f')
struct_be_d = Struct('>d')
structB = Struct('B')

pack_le_int32 = struct_le_i.pack
pack_le_int64 = struct_le_q.pack
pack_le_uint16 = struct_le_H.pack
pack_le_uint32 = struct_le_I.pack
pack_le_uint64 = struct_le_Q.pack
pack_be_uint16 = struct_be_H.pack
pack_be_uint32 = struct_be_I.pack
pack_be_uint64 = struct_be_Q.pack
pack_byte = structB.pack

unpack_le_int32 = struct_le_i.unpack
unpack_le_int32_from = struct_le_i.unpack_from
unpack_le_int64 = struct_le_q.unpack
unpack_le_int64_from = struct_le_q.unpack_from
unpack_le_uint16 = struct_le_H.unpack
unpack_le_uint16_from = struct_le_H.unpack_from
unpack_le_uint32 = struct_le_I.unpack
unpack_le_uint32_from = struct_le_I.unpack_from
unpack_le_uint64 = struct_le_Q.unpack
unpack_le_uint64_from = struct_le_Q.unpack_from
unpack_be_uint16 = struct_be_H.unpack
unpack_be_uint16_from = struct_be_H.unpack_from
unpack_be_uint32 = struct_be_I.unpack
unpack_be_uint32_from = struct_be_I.unpack_from
unpack_be_uint64 = struct_be_Q.unpack
unpack_be_uint64_from = struct_be_Q.unpack_from
unpack_byte = structB.unpack

pack_be_float2 = struct_be_e.pack
pack_be_float4 = struct_be_f.pack
pack_be_float8 = struct_be_d.pack
unpack_be_float2 = struct_be_e.unpack
unpack_be_float4 = struct_be_f.unpack
unpack_be_float8 = struct_be_d.unpack

hex_to_bytes = bytes.fromhex


def pack_cbor_length(length, major):
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


def pack_cbor_double(value):
    '''Encoding of a float as an IEEE double-precision payload.'''
    return b'\xfb' + pack_be_float8(value)


def pack_cbor_short_float(value):
    '''Shortest encoding of a float that does not lose precision.'''
    if value == value:
        try:
            pack4 = pack_be_float4(value)
            value4, = unpack_be_float4(pack4)
            if value4 != value:
                raise OverflowError
        except OverflowError:
            return pack_cbor_double(value)
        else:
            try:
                pack2 = pack_be_float2(value)
                value2, = unpack_be_float2(pack2)
                if value2 != value:
                    raise OverflowError
                return b'\xf9' + pack2
            except OverflowError:
                return b'\xfa' + pack4
    else:
        return b'\xf9\x7e\x00'
