import stackmonitor
import ctypes


def main():
    s = Stack()
    

    for x in stackmonitor.monitor("./tool/binaries/test-app"):
        s.update(x)
        s.print_in_range(0x4005e1,0x4005f7)

        # test input: "Computer Sabotage:  Programmed to Sneeze aaaaa"
        # apparently gets reads one char (C)
        # then 16 byte chunks
        if s.bytes_in_write("puter", string=True):
            print hex(x['ip']), x['disassembly']
            s.print_ops(string=True)
            print "strlen: {}".format(x['write']['length'])
            print "="*80

        if s.bytes_in_write("ramm", string=True):
            print hex(x['ip']), x['disassembly']
            s.print_ops(string=True)
            print "strlen: {}".format(x['write']['length'])
            print "="*80

        #exit sequence
        if x['ip'] > 0x400676 and s.bytes_in_read("aaaa", string=True):
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


    def bytes_in_op(self, b, ins=None, endianness=True, string=False):
        return self.bytes_in_write(b, ins, endianness) or self.bytes_in_read(b, ins, endianness) or self.bytes_in_read2(b, ins, endianness)


    def bytes_in_write(self, b, ins=None, endianness=True, string=False):
        return self.bytes_in_op(b, 'write', ins, endianness, string)
        

    def bytes_in_read(self, b, ins=None, endianness=True, string=False):
        return self.bytes_in_op(b, 'read', ins, endianness, string)
        

    def bytes_in_read2(self, b, ins=None, endianness=True, string=False):
        return self.bytes_in_op(b, 'read2', ins, endianness, string)


    def bytes_in_op(self, b, op, ins=None, endianness=True, string=False):
        if not ins:
            ins = self.ins

        if string:
            endianness=False
        elif endianness:
            b = b[::-1]

        return ins[op]['length'] > 0 and b in ins[op]['data']

        
    def print_ops(self, x=None, endianness=True, string=False):
        if not x:
            x = self.ins

        self.print_write(x, endianness, string)
        self.print_read(x, endianness, string)
        self.print_read2(x, endianness, string)


    def print_write(self, i=None, endianness=True, string=False):
        self.print_op("write", i, endianness, string)
        

    def print_read(self, i=None, endianness=True, string=False):
        self.print_op("read", i, endianness, string)


    def print_read2(self, i=None, endianness=True, string=False):
        self.print_op("read2", i, endianness, string)


    def print_op(self, op, ins=None, endianness=True, string=False):
        if not ins:
            ins = self.ins
        if(not ins or ins[op]['length'] == 0):
            print op + ": NULL"
        elif not string:
            print op + " " + hex(ins[op]['addr']) + ": " + \
                self.print_hex(ins[op]['data'], ins[op]['length'], endianness)
        else:
            print op + " :" + ins[op]['data']

    def print_hex(self, s, length, endianness=True):
        if endianness: 
            return "".join("{:02x}".format(
                ord(s[x])) for x in range(length-1, -1, -1))
        else:
            return "".join("{:02x}".format(
                ord(s[x])) for x in range(length))


    # prints when in range of addresses, including kernel instructions
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



if __name__ == "__main__":
    main()
