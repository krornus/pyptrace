import pyptrace 

for i in pyptrace.instructions("./binaries/warmup"):
    print hex(i)

