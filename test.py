import stackmonitor

for x in stackmonitor.monitor("/bin/ls"):
    if x['ip'] < 0x600000000000 and x['write']['length'] > 0:
        print hex(x['ip']), x['write']
