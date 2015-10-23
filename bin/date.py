#!/usr/bin/python2.6

import parsedatetime.parsedatetime as pdt
import sys

if(len(sys.argv) != 2):
    raise "Error"
cal = pdt.Calendar()
print cal.parse(sys.argv[1])
