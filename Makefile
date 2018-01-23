CC=gcc
DEPS=server.c

FLAGS=-Wall -fPIC -shared

PYINC=-I/usr/include/python2.7/
PYINC+=-lpython2.7

CFLAGS=-I. $(FLAGS)

.PHONY: pin

all: pin stackmonitor

stackmonitor:
	$(CC) $(PYINC) $(CFLAGS) -c -o stackmonitor.o stackmonitor.c
	$(CC) $(CFLAGS) -c -o server.o server.c
	$(CC) $(PYINC) $(CFLAGS) -o stackmonitor.so stackmonitor.o server.o

pin:
	cd ./pin/source/tools/StackMonitor/ && make

clean:
	rm -f $(ODIR)/*.o $(ODIR)/*.so stackmonitor.so
	$(MAKE) -C ./pin/source/tools/StackMonitor clean
