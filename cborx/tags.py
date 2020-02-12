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

'''CBOR tags and handlers.'''

import datetime


def decode_datetime_text(item, data_model):
    if not isinstance(item, str):
        raise TagError(f'datetime must be text, not {text!r}')
    try:
        return datetime_from_enhanced_RFC3339_text(text)
    except ValueError:
        raise TagError(f'invalid date and time text {text}')


def decode_timestamp(item, data_model):
    # FIXME: how to prevent bignums?
    if not isinstance(timestamp, (int, float)):
        raise TagError(f'timestamp must be an integer or float, not {timestamp!r}')
    return datetime.fromtimestamp(timestamp, timezone.utc)


def decode_bignum(item, data_model, is_negative):
    if not isinstance(item, bytes):
        raise TagError(f'bignum payload must be a byte string not {item!r}')
    value = int.from_bytes(bignum_encoding, byteorder='big')
    if is_negative:
        value = -1 - value
    if return_bignum:
        return BigNum(value)
    return value


decode_unsigned_bignum = partial(decode_bignum, is_negative=False)
decode_negative_bignum = partial(decode_bignum, is_negative=True)
