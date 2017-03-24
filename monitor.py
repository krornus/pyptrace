import stackmonitor
import ctypes


def main():
    s = Stack()
    

    for x in stackmonitor.monitor("./tool/binaries/test-app"):
        s.update(x)
        s.print_in_range(0x4005e1,0x4005f7)

        # test input: "when in the course of human events"
        # apparently gets reads one char (w)
        # then 16 bytes, then 16 again (maybe 32?)
        if(s.bytes_in_write("hen")):
            print hex(x['ip']), x['disassembly']
            s.print_ops(string=True)
            print "="*80

        if(s.bytes_in_write("events")):
            print hex(x['ip']), x['disassembly']
            s.print_ops(string=True)
            print "strlen: {}".format(x['write']['length'])
            print "="*80

        
class Stack(object):

    def __init__(self):
        self.min = None
        self.ins = {}
        self.log = False
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

        
    def print_ops(self, x=None, endianness=True, string=False):
        if not x:
            x = self.ins

        self.print_write(x, endianness, string)
        self.print_read(x, endianness, string)
        self.print_read2(x, endianness, string)


    def print_write(self, i=None, endianness=True, string=False):
        if not i:
            i = self.ins
        if(not i or i['write']['length'] == 0):
            print "WRITE: NULL"
        elif not string:
            print "WRITE " + hex(i['write']['addr']) + ": " + \
                self.print_hex(i['write']['data'], i['write']['length'], endianness)
        else:
            print "WRITE :" + i['write']['data']
        

    def print_read(self, i=None, endianness=True, string=False):
        if not i:
            i = self.ins
        if(not i or i['read']['length'] == 0):
            print "READ: NULL"
        elif not string:
            print "READ " + hex(i['read']['addr']) + ": " + \
                self.print_hex(i['read']['data'], i['read']['length'], endianness)
        else:
            print "READ :" + i['read']['data']


    def print_read2(self, i=None, endianness=True, string=False):
        if not i:
            i = self.ins
        if(not i or i['read2']['length'] == 0):
            print "READ2: NULL"
        elif not string:
            print "READ2 " + hex(i['read2']['addr']) + ": " + \
                self.print_hex(i['read2']['data'], i['read2']['length'], endianness)
        else:
            print "READ2 :" + i['read2']['data']


    def print_hex(self, s, length, endianness=True):
        if endianness: 
            return "".join("{:02x}".format(
                ord(s[x])) for x in range(length-1, -1, -1))
        else:
            return "".join("{:02x}".format(
                ord(s[x])) for x in range(length))


    def print_in_range(self, p1, p2, endianness=True, string=False):

            if not self.log and self.ins['ip'] == p1:
                self.log = True
            elif self.log and self.ins['ip'] == p2:
                self.log = False

            if self.log: 
                print "="*80
                print hex(self.ins['ip']) + ": " + self.ins['disassembly']
                self.print_ops(endianness=endianness, string=string)
                print "="*80


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
