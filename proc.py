import re

usr_line_re = re.compile("^(0x556d[a-f0-9]+):",re.I)
offset = 0x556d09727000

with open("child_log.proc","w") as preproc:
    with open("child_log","r") as f:
        for line in f:
            m = usr_line_re.match(line)
            if m:
                saddr = m.group(1)
                addr = int(saddr,16)-offset
                line=line.replace(saddr,"USR@"+hex(addr))

            preproc.write(line)
