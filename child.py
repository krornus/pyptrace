import stackmonitor


for x in stackmonitor.monitor("./tool/binaries/execv"):
    if x['ip'] in range(0x0040058a, 0x004005ac+1):
        print "{}: {}".format(hex(x['ip']), x['disassembly'])
