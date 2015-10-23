#!/usr/bin/env python2.7

import time
import sys
import re
from IO import OStream, Rid
from subprocess import check_output
import socket

def now():
    return int(time.mktime(time.gmtime())) + 3*3600

start_time = now()

rid_re = ' *([0-9]):([0-9]*) *'

one = re.compile('^'+rid_re+'$')
two = re.compile('^'+rid_re+'-'+rid_re+'$')

def compot_send(host, port, cmd):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((host, port))
    s.send(cmd)
    s.close()

def chatId(stamp):
    prsr = one.match(stamp)
    if (prsr):
        return Rid(prsr.group(1), prsr.group(2))
    id = check_output('chatByStamp.pl 25 | jq ".results.sn" | sed -e "s/[^0-9]//g"', shell=True)
    return Rid(2, str(id))


def shard(key):
    key_stream = OStream()

    type = None
    if one.match(key):
        prsr = one.match(key)
        key_stream.putRid(int(prsr.group(1)), int(prsr.group(2)))
        type = 'mchat'
    elif two.match(key):
        prsr = two.match(key)
        a = Rid(int(prsr.group(1)), int(prsr.group(2)))
        b = Rid(int(prsr.group(3)), int(prsr.group(4)))
        if (int(a) > int(b)):
            key_stream.putU64(int(b)).putU64(int(a))
        else:
            key_stream.putU64(int(a)).putU64(int(b))
        type = 'st'
    else:
        key_stream.putU64(int(chatId(key)))
        type = 'mchat'
    key_str = hexdump(key_stream.data, simple=True)

    return check_output(['/usr/bin/curl', '-s', 'http://stat.mrim.mail.ru/ctlr_compot?command=wib gbld-{} hex {}'.format(type, key_str)])

def hexdump(src, length=16, simple=False):
    FILTER = ''.join([(len(repr(chr(x))) == 3) and chr(x) or '.' for x in range(256)])
    lines = []
    for c in xrange(0, len(src), length):
        chars = src[c:c+length]
        sep = ' '
        if (simple):
            sep = ''
        hex = sep.join(["%02x" % ord(x) for x in chars])
        printable = ''.join(["%s" % ((ord(x) <= 127 and FILTER[ord(x)]) or '.') for x in chars])
        if (simple):
            lines.append(hex)
        else:
            lines.append("%04x  %-*s  %s\n" % (c, length*3, hex, printable))
    return ''.join(lines)

cmap = {
    'hdr'       : '\033[95m',
    'blue'      : '\033[94m',
    'green'     : '\033[92m',
    'yellow'    : '\033[93m',
    'red'       : '\033[91m',
    '__end'     : '\033[0m',
    'bold'      : '\033[1m',
    'underline' : '\033[4m',
}
def colored(c, s):
    return cmap[c] + s + cmap['__end']

if (__name__ == '__main__'):
    print shard(sys.argv[1])
