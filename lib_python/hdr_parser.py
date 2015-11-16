#!/usr/bin/python2.7

import os
import re

class HdrParserException(Exception):
    pass

class HdrParser(object):
    defineRe = re.compile('^(#define| ) *([a-zA-Z0-9_]+) *=? *([0-9<() ]*) *,? *$')

    def readHdrLine(self, l):
        prsr = self.defineRe.match(l)
        if (not prsr):
            return
        if (len(prsr.group(3))):
            self.Dict[prsr.group(2)] = eval(prsr.group(3))
    def readHdr(self, path):
        f = open(path, 'r')
        for s in f.readlines():
            self.readHdrLine(s)

    def __init__(self, path=None):
        self.Dict = {}
        if path:
            self.readHdr(path)

    def __repr__(self):
        s = ''
        for k in sorted(self.Dict.keys()):
            s += ('{0:30} {1}\n'.format(k,self.Dict[k]))
        return s
    def __getitem__(self, name):
        return self.get(name, None)

    def nameByVal(self, pref, val):
        for k in self.Dict.keys():
            if val == self.Dict[k] and k.startswith(pref):
                return k[len(pref):]
