import pyitrace
from elftools.elf.elffile import ELFFile
from capstone import Cs,CS_ARCH_X86, CS_MODE_64, CS_MODE_32

def main():

    fn = "/bin/ls"

    f = open(fn, 'rb')

    etool = ELFFile(f)
    elfclass = etool.elfclass

    data = f.read()

    md = None

    if elfclass == 64:
        md = Cs(CS_ARCH_X86, CS_MODE_64)
    elif elfclass == 32:
        md = Cs(CS_ARCH_X86, CS_MODE_32)
    else:
        return -1

    dis = list(md.disasm(data, 0))

    for x in pyitrace.instructions(fn):
        if x < 0xf7000000:
            print hex(x)

    f.close()

if __name__ == "__main__":
    exit(main())

