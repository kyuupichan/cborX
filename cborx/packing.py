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

__all__ = (
    'pack_le_int32', 'pack_le_int64',
    'pack_le_uint16', 'pack_le_uint32', 'pack_le_uint64',
    'pack_be_uint16', 'pack_be_uint32', 'pack_be_uint64',
    'pack_byte', 'pack_port', 'pack_varint', 'pack_varbytes', 'pack_list',
    'unpack_le_int32', 'unpack_le_int32_from',
    'unpack_le_int64', 'unpack_le_int64_from',
    'unpack_le_uint16', 'unpack_le_uint16_from',
    'unpack_le_uint32', 'unpack_le_uint32_from',
    'unpack_le_uint64', 'unpack_le_uint64_from',
    'unpack_be_uint16', 'unpack_be_uint16_from',
    'unpack_be_uint32', 'unpack_be_uint32_from',
    'unpack_be_uint64', 'unpack_be_uint64_from',
    'unpack_byte', 'unpack_port', 'unpack_header',
    'read_le_int32', 'read_le_int64',
    'read_le_uint16', 'read_le_uint32', 'read_le_uint64',
    'read_be_uint16', 'read_be_uint32', 'read_be_uint64',
    'read_varint', 'read_varbytes', 'read_list',
)


from struct import Struct, error as struct_error
from functools import partial


struct_le_i = Struct('<i')
struct_le_q = Struct('<q')
struct_le_H = Struct('<H')
struct_le_I = Struct('<I')
struct_le_Q = Struct('<Q')
struct_be_H = Struct('>H')
struct_be_I = Struct('>I')
struct_be_Q = Struct('>Q')
structB = Struct('B')
struct_header = Struct('<i 32s 32s 3I')

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
unpack_header = struct_header.unpack

pack_port = pack_be_uint16
unpack_port = unpack_be_uint16
hex_to_bytes = bytes.fromhex
