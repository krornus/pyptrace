import pyptrace 
import struct
import os
from distorm3 import Decode, Decode32Bits

#working=pyptrace.instructions("./binaries/warmup", stdin="testin")
#working=pyptrace.instructions("./binaries/args")
working=pyptrace.instructions("./binaries/stdin", argv=["testin"])
#working=pyptrace.instructions("./binaries/narnia0", stdin="a"*20+"\xef\xbe\xad\xde")

for x in working:
    print x
