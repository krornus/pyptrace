import pyitrace

for x in pyitrace.instructions("/home/spowell/programming/python/pyptrace/binaries/stdin"):
    if x < 0xf7000000:
        print hex(x)
