CC=gcc
CFLAGS=-g -fPIC

all: interpose.so inject console

interpose.so: interpose.o objdump.o process.o util.o asm.o
	$(CC) $(CFLAGS) $^ -shared -o $@

inject:	inject.o objdump.o process.o util.o
	$(CC) $(CFLAGS) $^ -o $@

console: console.o objdump.o process.o util.o
	$(CC) $(CFLAGS) -lcurses -lreadline -lhistory $^ -o $@

clean:
	-rm *.o
	-rm inject
	-rm console
	-rm interpose.so
