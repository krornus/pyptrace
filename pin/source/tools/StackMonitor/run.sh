#!/bin/sh

function loop()
{
    for ((i = 0; i < $1; i++)); do
        (./server &) && time ../../../pin -t ./obj-intel64/StackMonitor.so -- "/bin/ls"
    done
}

if [ $# -gt 0 ]; then
    typeset -i N="$1" 2>/dev/null && loop $N || (echo "Expected integer"; exit 1)
else
    loop 1
fi

