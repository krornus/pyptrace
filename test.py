import pyptrace 
import struct
import os
from distorm3 import Decode, Decode32Bits

#working=pyptrace.instructions("./binaries/warmup", stdin="testin")
#working=pyptrace.instructions("/bin/ls")
#working=pyptrace.instructions("/bin/ls")
working=pyptrace.instructions("./binaries/args", stdin="testin")
#working=pyptrace.instructions("./binaries/narnia0", stdin="a")#"a"*20+"\xef\xbe\xad\xde")

for pid,x,y in working:

    op = struct.pack("<Q", y)
    op = Decode(x, op, Decode32Bits)[0]

    print "{} - <{}>: {}    {}".format(pid, hex(x), op[3].rjust(15), op[2])

