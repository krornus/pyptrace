#!/usr/bin/env python2
import re
import argparse

parser=argparse.ArgumentParser()
parser.add_argument("pid", type=int)
parser.add_argument("addr")

args = parser.parse_args()
with open("/proc/{}/maps".format(args.pid),"r") as f:
    maps=f.read()

pat = r'([0-9a-f]+)-([0-9a-f]+)'
line = None
for x in re.findall(pat, maps):
    if int(args.addr,16) > int(x[0],16) and int(args.addr,16) < int(x[1],16):
        line = x[0]


if line:
    for l in maps.splitlines():
        if line in l:
            print l
