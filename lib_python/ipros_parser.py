#!/usr/bin/env python2.7

from IO import OStream, IStream, Rid
import sys
import struct
import util

class IprosParser(object):
    def __init__(self):
        self.HdrLen = IStream('').expectedLen('getIproHdr')
    def generate(self, input):
        while (True):
            try:
                raw = input.read(self.HdrLen)
                if len(raw) == 0:
                    break
                (m,l,s) = IStream(raw).getIproHdr()
                yield (m, IStream(input.read(l)))
            except struct.error:
                pass

