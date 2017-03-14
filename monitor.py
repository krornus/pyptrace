import stackmonitor

def main():
    usr_stack = {}
    kern_stack = {}
    for x in stackmonitor.monitor("/bin/ls"):
        if x['ip'] < 0x600000000000:
            print hex(x['ip']) + ": " + x['disassembly']

def print_frame(bp, sp):
    diff = bp - sp
    if diff > 1000:
        return
    for x in range(bp, sp, -4):
        print hex(x)

    print "="*80 + "\n\n"
    

if __name__ == "__main__":
    main()
