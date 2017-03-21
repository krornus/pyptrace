import stackmonitor
import ctypes

def main():
    s = Stack()
    for x in stackmonitor.monitor("./tool/binaries/test-app"):
        s.update(x['ip'], x['bp'], x['sp'])
        s.print_in_range(x, 0x4005e1,0x4005f7)

        
class Stack(object):

    def __init__(self):
        self.min = None
        self.sp = None
        self.bp = None
        self.ip = None
        self.in_range = False
        self.stack = []


    def update(self, ip, bp, sp):
        self.ip = ip
        self.bp = bp
        self.sp = sp
    

    def write(self, addr, length, value):
        print "WRITE " + hex(addr) + ": " + "".join("{:02x}".format(ord(value[x])) for x in range(length))
        

    def read(self, addr, length, value):
        print "READ " + hex(addr) + ": " + "".join("{:02x}".format(ord(value[x])) for x in range(length))


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


    def print_in_range(self, x, p1, p2):

            if not self.in_range and x['ip'] == p1:
                self.in_range = True
            elif self.in_range and x['ip'] == p2:
                self.in_range = False

            if self.in_range: 
                print "="*80
                print hex(x['ip']) + ": " + x['disassembly']
                if x['write']['length'] > 0:
                    self.write(
                        x['write']['addr'], x['write']['length'], x['write']['data'])
                if x['read']['length'] > 0:
                    self.read(
                        x['read']['addr'], x['read']['length'], x['read']['data'])
                if x['read2']['length'] > 0:
                    self.read2(
                        x['read2']['addr'], x['read2']['length'], x['read2']['data'])
                print "="*80

if __name__ == "__main__":
    main()
