import stackmonitor
import ctypes

def main():
    s = Stack()
    for x in stackmonitor.monitor("./tool/test-app"):
        s.update(x['bp'], x['sp'])
        if x['write']['length'] > 0 and x['ip'] == 0x0000000000400684:
            print hex(x['ip']) + ": " + x['disassembly']
            s.write(x['write']['addr'], x['write']['length'], x['write']['data'])
        if x['ip'] >= 0x0000000000400666 and x['ip'] <= 0x0000000000400726: 
            print hex(x['ip']) + ": " + x['disassembly']
        if x['ip'] == 0x00000000004006c5:
            print s
        if x['ip'] == 0x00000000004006ca:
            print s


def print_frame(bp, sp):
    diff = bp - sp
    if diff > 1000:
        return
    for x in range(bp, sp, -4):
        print hex(x)

    print "="*80 + "\n\n"
    

class Stack(object):

    def __init__(self):
        self.min = None
        self.sp = None
        self.bp = None
        self.stack = []


    def update(self, bp, sp):
        self.bp = bp
        self.sp = sp
    

    def write(self, addr, length, value):
        vp = ctypes.c_char_p(value)
        print "writing {}".format(vp.contents())
        ":".join("{:02x}".format(ord(vp[x])) for x in range(length-1))
        

    def read(self, addr):
        return 0


    def __repr__(self):
        if(self.sp > self.bp):
            return "invalid stack"

        stack = "="*38 + "stack" + "="*37
        stack += "\n"
        stack += "bp => " + hex(self.bp) + "\n"

        for x in range(self.bp-4, self.sp+4, -4):
            stack += "      " + hex(x) + "\n"

        stack += "sp => " + hex(self.sp) + "\n"
        stack += "="*80 + "\n"
        stack += "bp: " + hex(self.bp) + ", sp: " + hex(self.sp)

        return stack

if __name__ == "__main__":
    main()
