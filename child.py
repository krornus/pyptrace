import stackmonitor


def execv():
    pwrite = 0
    for x in stackmonitor.monitor("./tool/binaries/execv"):
        if x['ip'] in range(0x00400592, 0x004005a6+1):
            print "{}: {}".format(hex(x['ip']), x['disassembly'])


def rust():
    for x in stackmonitor.monitor("./tool/binaries/rust-dbg"):
        if x['ip'] in range(0x004005d0, 0x004005d0+20):
            print "{}: {}".format(hex(x['ip']), x['disassembly'])

execv()
#rust()
