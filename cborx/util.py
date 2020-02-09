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

'''Utility functions'''

import re
from array import array
from datetime import datetime, date, timezone, time, timedelta


bjoin = b''.join
sjoin = ''.join
time_regex = re.compile(r'T(\d\d):(\d\d):(\d\d)(.\d+)?(Z|([+-])(\d\d):(\d\d))$')


def datetime_from_enhanced_RFC3339_text(text):
    '''Enchanced because it requires an upper case Z and T.'''
    date_part = date.fromisoformat(text[:10])
    if len(text) <= 10:
        return date_part

    time_part = time_regex.match(text[10:])
    if time_part is None:
        raise ValueError
    groups = time_part.groups()
    time_parts = [int(groups[n]) for n in range(3)]
    if groups[3] is None:
        time_parts.append(0)
    else:
        time_parts.append(int(float(groups[3]) * 1_000_000 + 0.5))
    if groups[4] == 'Z':
        time_parts.append(timezone.utc)
    else:
        seconds = (int(groups[6]) * 60 + int(groups[7])) * 60
        if groups[5] == '-':
            seconds = -seconds
        time_parts.append(timezone(timedelta(seconds=seconds)))

    time_part = time(*time_parts)
    return datetime.combine(date_part, time_part)


def uint_to_be_bytes(value):
    '''Convert an unsigned integer to a big-endian sequence of bytes'''
    return value.to_bytes((value.bit_length() + 7) // 8, 'big')


def _analyze_array_tags(base_tag_value):
    '''Determine dynamically for the host machine a map from Python typecodes to tag values,
    and from tag values to decoder instructions.
    '''
    decoder_hints = {}
    typecode_tag_values = {}

    # Integer types

    typecode_sizes = {typecode: array(typecode).itemsize for typecode in 'BHILQ'}
    size_typecodes = {size: typecode for typecode, size in typecode_sizes.items()}
    is_machine_int_le = array('I', [1]).tobytes()[0] == 1

    for tag_value in range(16):
        size = 1 << (tag_value & 3)
        is_tag_le = bool(tag_value & 4)
        if is_tag_le and size == 1:
            continue     # LE bytes are redundant with BE bytes
        typecode = size_typecodes.get(size)
        if typecode:
            if tag_value & 8:  # signed int
                typecode = typecode.lower()
            swap_bytes = (is_tag_le != is_machine_int_le) and size > 1
            decoder_hints[base_tag_value + tag_value] = (typecode, swap_bytes)

    for typecode, size in typecode_sizes.items():
        unsigned_tag_value = (base_tag_value + (size.bit_length() - 1) +
                              (4 if (is_machine_int_le and size > 1) else 0))
        typecode_tag_values[typecode] = unsigned_tag_value
        typecode_tag_values[typecode.lower()] = unsigned_tag_value + 8

    # Floating point types

    typecode_sizes = {typecode: array(typecode).itemsize for typecode in 'fd'}
    size_typecodes = {size: typecode for typecode, size in typecode_sizes.items()}
    is_machine_float_le = array('f', [-0.0]).tobytes()[0] == 0x00

    for tag_value in range(16, 24):
        size = 2 << (tag_value & 3)
        typecode = size_typecodes.get(size)
        if typecode:
            is_tag_le = bool(tag_value & 4)
            swap_bytes = is_tag_le != is_machine_float_le
            decoder_hints[base_tag_value + tag_value] = (typecode, swap_bytes)

    for typecode, size in typecode_sizes.items():
        typecode_tag_values[typecode] = (base_tag_value + 16 + (size.bit_length() - 2) +
                                         (4 if is_machine_float_le else 0))

    return decoder_hints, typecode_tag_values

typed_array_decoder_hints, typecode_to_tag_map = _analyze_array_tags(64)
