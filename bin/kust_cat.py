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
                raw = input.read(hdr.data_len)
                if len(raw) == 0:
                    break;
                data = None
                if hdr.type == 1 and self.mod_parser:
                    km = IStream(raw).getKustMod(self.key_printer)
                    data = self.mod_parser(hdr, km, km.mod)
                elif hdr.type == 2 and self.cell_parser:
                    data = self.cell_parser(hdr, IStream(raw))
                yield (hdr, data)
            except struct.error:
                pass

def gbld_mod_parser(hdr, km, istr):
    return 'mod {}:\n{}'.format(km, util.hexdump(istr.data))

def gbld_key_printer(raw):
        return '{}<->{}'.format(raw.getRid(), raw.getRid())

if __name__ == '__main__':
    input = sys.stdin
    if len(sys.argv) > 1:
        input = open(sys.argv[1], 'rb')

    kp = KustParser(mod_parser = gbld_mod_parser, key_printer = gbld_key_printer)
    egen = kp.generate(input)
    for (hdr, data) in egen:
        print '{}:{}'.format(hdr, data)

