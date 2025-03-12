"""
srv6sidinformation.py

Created by Hiroyuki Yagihashi on 2025-03-15.
Copyright (c) 2025 Hiroyuki Yagihashi. All rights reserved.
License: 3-clause BSD. (See the COPYRIGHT file)
"""
from struct import pack

from exabgp.protocol.ip import IP

# SRv6 SID Information TLV
# 0                   1                   2                   3
# 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |               Type            |          Length               |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |    SID (16 octets) ...                                        |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |    SID (cont ...)                                             |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |    SID (cont ...)                                             |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |    SID (cont ...)                                             |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+


class SRv6SIDInformation(object):
    TYPE = 518
    def __init__(self, sids):
        self.length = len(sids) * 16
        self.sids = sids

    def pack(self):
        return pack('!HH', self.TYPE, self.length) + b''.join([IP.pack(sid) for sid in self.sids])

    @classmethod
    def unpack(cls, data):
        return cls([IP.unpack(data[i: i + 16]) for i in range(0, len(data), 16)])

    def json(self):
        return '%s' % ', '.join(['"%s"' % sid for sid in self.sids])
