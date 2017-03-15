import stackmonitor

for x in stackmonitor.monitor("./tool/binaries/overflow"):
    if x['ip'] < 1:
        print x
    
