#include "instruction.h"

int main(int argc, char **argv)
{
    int pid;

    pid = fork();

    if(pid == 0)
    {
        execl("./pin",  "-t", "obj-intel64/itrace.so", itoa(pid), "--", argv[1]);
    }
    else
    {
    }
}
