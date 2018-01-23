CC=gcc
CFLAGS=-no-pie

all:
	$(CC) $(CFLAGS) execv.c -o execv
	$(CC) $(CFLAGS) execv_child.c -o execv_child
	$(CC) $(CFLAGS) overflow.c -o overflow
	$(CC) $(CFLAGS) test_app.c -o test-app

clean:
	rm -f execv execv_child overflow test-app
