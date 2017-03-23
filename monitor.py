import stackmonitor
import ctypes


def main():
    s = Stack()
    hist = []
    post = -1
    

    for x in stackmonitor.monitor("./tool/binaries/test-app"):
        s.update(x)
        s.print_in_range(0x4005e1,0x4005f7)
        if(s.bytes_in_op("\x61\x62")):
            print hex(x['ip']), x['disassembly']
            print "="*80 + "\n" + "HIST\n" + "="*80 
            for x in hist:
                s.print_ops(x)
            print "="*80

            s.print_ops()

            print "="*80 + "\n" + "FUTURE\n" + "="*80 
            post = 0

        if post > -1 and post < 20:
            s.print_ops()
            post += 1
        elif post == 20:
            post += 1
            print "="*80

        hist.append(x)
        if len(hist) > 20:
            hist.pop(0)

        
class Stack(object):

    def __init__(self):
        self.min = None
        self.ins = {}
        self.in_range = False
        self.stack = []


    def update(self, x):
        self.ins = x 

    def bytes_in_op(self, b):
        return self.bytes_in_write(b) or self.bytes_in_read(b) or self.bytes_in_read2(b)


    def bytes_in_write(self, b):
        return self.ins['write']['length'] > 0 and b in self.ins['write']['data']


    def bytes_in_read(self, b):
        return self.ins['read']['length'] > 0 and b in self.ins['read']['data']


    def bytes_in_read2(self, b):
        return self.ins['read2']['length'] > 0 and b in self.ins['read2']['data']

        
    def print_ops(self, x=None):
        if not x:
            x = self.ins

        self.print_write(x)
        self.print_read(x)
        self.print_read2(x)


    def print_write(self, i=None):
        if not i:
            i = self.ins
        if(not i or i['write']['length'] == 0):
            print "WRITE: NULL"
        else:
            print "WRITE " + hex(i['write']['addr']) + "(" + str(i['write']['length']) + " bytes): " + \
            "".join("{:02x}".format(
                ord(i['write']['data'][x])) 
                for x in range(i['write']['length']))
        

    def print_read(self, i=None):
        if not i:
            i = self.ins
        if(not i or i['read']['length'] == 0):
            print "READ: NULL"
        else:
            print "READ " + hex(i['read']['addr']) + ": " + \
            "".join("{:02x}".format(
                ord(i['read']['data'][x])) 
                for x in range(i['read']['length']))


    def print_read2(self, i=None):
        if not i:
            i = self.ins
        if(not i or i['read2']['length'] == 0):
            print "READ2: NULL"
        else:
            print "READ2 " + hex(i['read2']['addr']) + ": " + \
            "".join("{:02x}".format(
                ord(i['read2']['data'][x])) 
                for x in range(i['read2']['length']))


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


    def print_in_range(self, p1, p2):

            if not self.in_range and self.ins['ip'] == p1:
                self.in_range = True
            elif self.in_range and self.ins['ip'] == p2:
                self.in_range = False

            if self.in_range: 
                print "="*80
                print hex(self.ins['ip']) + ": " + self.ins['disassembly']
                self.print_ops()
                print "="*80

if __name__ == "__main__":
    main()
