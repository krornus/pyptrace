import stackmonitor
import ctypes


def main():
    s = Stack()
    hist = []
    post = -1
    

    for x in stackmonitor.monitor("./tool/binaries/test-app"):
        s.update(x)
        s.print_in_range(0x4005e1,0x4005f7)

        if(x['disassembly'] == "mov byte ptr [rbx], al"):
            post = 0

        '''
        if(s.bytes_in_op("\x61\x62")):
            print hex(x['ip']), x['disassembly']
            print "="*80 + "\n" + "HIST\n" + "="*80 
            for x in hist:
                s.print_ops(x)
            print "="*80

            s.print_ops(endianness=False)

            print "="*80 + "\n" + "FUTURE\n" + "="*80 
            post = 0
        '''
        if post > -1 and post < 5:
            print x['disassembly']
            s.print_ops(endianness=False)
            post += 1
        elif post == 5:
            post += 1
            print "="*80
        
        hist.append(x)
        if len(hist) > 5:
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

        
    def print_ops(self, x=None, endianness=True):
        if not x:
            x = self.ins

        self.print_write(x, endianness)
        self.print_read(x, endianness)
        self.print_read2(x, endianness)


    def print_write(self, i=None, endianness=True):
        if not i:
            i = self.ins
        if(not i or i['write']['length'] == 0):
            print "WRITE: NULL"
        else:
            print "WRITE " + hex(i['write']['addr']) + ": " + \
                self.print_hex(i['write']['data'], i['write']['length'], endianness)
        

    def print_read(self, i=None, endianness=True):
        if not i:
            i = self.ins
        if(not i or i['read']['length'] == 0):
            print "READ: NULL"
        else:
            print "READ " + hex(i['read']['addr']) + ": " + \
                self.print_hex(i['read']['data'], i['read']['length'], endianness)


    def print_read2(self, i=None, endianness=True):
        if not i:
            i = self.ins
        if(not i or i['read2']['length'] == 0):
            print "READ2: NULL"
        else:
            print "READ2 " + hex(i['read2']['addr']) + ": " + \
                self.print_hex(i['read2']['data'], i['read2']['length'], endianness)


    def print_hex(self, s, length, endianness=True):
        if endianness: 
            return "".join("{:02x}".format(
                ord(s[x])) for x in range(length-1, -1, -1))
        else:
            return "".join("{:02x}".format(
                ord(s[x])) for x in range(length))


    def print_in_range(self, p1, p2, endianness=True):

            if not self.in_range and self.ins['ip'] == p1:
                self.in_range = True
            elif self.in_range and self.ins['ip'] == p2:
                self.in_range = False

            if self.in_range: 
                print "="*80
                print hex(self.ins['ip']) + ": " + self.ins['disassembly']
                self.print_ops(endianness=endianness)
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
