#!/usr/bin/env python2.7

import re
from subprocess import check_output
from util import chatId
import sys

if (__name__ == '__main__'):
    rid_re = ' *([0-9]):([0-9]*) *'
    one = re.compile('^'+rid_re+'$')
    two = re.compile('^'+rid_re+'-'+rid_re+'$')
    if (two.match(sys.argv[1])):
        print sys.argv[1]
    else:
        id = chatId(sys.argv[1])
        print '{}:{}'.format(id.type, id.id)
