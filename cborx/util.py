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

import re
from datetime import datetime, date, timezone, time, timedelta

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
    '''Converts an unsigned integer to a big-endian sequence of bytes'''
    return value.to_bytes((value.bit_length() + 7) // 8, 'big')
