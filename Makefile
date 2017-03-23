CC=gcc
DEPS=server.c
FLAGS=-Wall -fpic -shared

INC=-I/usr/include/python2.7/
INC+=-lpython2.7

CFLAGS=-I. $(INC) $(FLAGS) 

ODIR=obj
_OBJ=stackmonitor.o server.o
OBJ=$(patsubst %,$(ODIR)/%,$(_OBJ))


$(ODIR)/%.o: %.c $(DEPS)
	$(CC) -c -o $@ $< $(CFLAGS)

stackmonitor.so: $(OBJ)
	$(CC) -o $@ $^ $(CFLAGS) $(LIBS)

clean: 
	rm -f $(ODIR)/*.o $(ODIR)/*.so stackmonitor.so
