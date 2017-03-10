import stackmonitor

for x in stackmonitor.monitor("/bin/ls"):
    print hex(x)
