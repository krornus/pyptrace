import stackmonitor

for x in stackmonitor.monitor("/home/spowell/research/pyitrace/tool/binaries/overflow"):
    print x
    if x['ip'] == 0x00007effb76c54d0:
        print x
