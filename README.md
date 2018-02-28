# pyptrace
## Python instruction execution analysis tool

Backend c module that can be used to dynamically anylyze the execution path of a binary executable.
There is currently only support for x86_64 ELF executables.

## Compiling

Make the python module with ```make```


The module makes use of Intel PIN, this tool must be compiled as well.
The tool is located in ```pyptrace/pin/source/tools/StackMonitor```,
this can be compiled with ```make``` as well.

**TL;DR**
```
  git clone https://github.com/krornus/pyptrace.git
  cd pyptrace
  make
```

## Usage
Import the module (**stackmonitor.so**)
```python
import stackmonitor
```

Iterate instructions for given executable

```python
for ins in stackmonitor.monitor("/bin/ls"):
    print ins['ip']          # the instruction pointer
    print ins['sp']          # the stack pointer
    print ins['bp']          # the base stack pointer
    print ins['disassembly'] # the disassembled instruction

    if ins['write']['length'] > 0: # write is a dictionary populated with data written to the stack
        print ins['write']['addr'] # effective address of write
        print ins['write']['data'] # data written

    # additionally, there are similar 'read' and 'read2' dictionaries.

```
