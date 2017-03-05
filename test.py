import pyitrace

for x in pyitrace.instructions("/bin/ls"):
    if x < 0xf7000000:
        print hex(x)

for x in pyitrace.instructions("/bin/echo done"):
    if x < 0xf7000000:
        print hex(x)
