#!/usr/bin/env python2.7

from IO import OStream, IStream, Rid
import sys
import struct
import util

class KustParser(object):
    def __init__(self,
            cell_parser = None,
            mod_parser = None,
            key_printer = None):
        self.cell_parser = cell_parser
        self.mod_parser = mod_parser
        self.key_printer = key_printer
        self.LogHdrLen = IStream('').expectedLen('getKustLogHdr')
    def generate(self, input):
        while (True):
            try:
                raw = input.read(self.LogHdrLen)
                if len(raw) == 0:
                    break
                hdr = IStream(raw).getKustLogHdr()
                body = IStream(input.read(hdr.data_len))
                if body.inAvail == 0:
                    break;
                data = None
                key = None
                if hdr.type == 1 and self.mod_parser:
                    km = body.getKustMod(self.key_printer)
                    key = km.key
                    data = self.mod_parser(hdr, km, IStream(km.mod).getLps())
                elif hdr.type == 2 and self.cell_parser:
                    data = self.cell_parser(hdr, IStream(raw))
                yield (hdr, key, data)
            except struct.error:
                pass

