CC = gcc
L=-lssl -lcrypto
CFLAGS = -g -Wall -Wshadow -I.
DEPS = ../sealfstypes.h entries.h
SRCS = $(wildcard *.c)
OBJS = $(SRCS:.c=.o)
TOCLEAN = prep $(OBJS)

all: dump prep verify test

uthash.h:
	rm -rf /tmp/uthash
	git clone https://github.com/troydhanson/uthash.git /tmp/uthash
	cp /tmp/uthash/src/uthash.h .

verify: uthash.h verify.o $(DEPS) heap.h heap.o entries.o
	$(CC) $(CFLAGS) -o $@ $@.o  heap.o entries.o $L

prep: prep.o $(DEPS)
	$(CC) $(CFLAGS) -o $@ $@.o

dump: dump.o $(DEPS) entries.o
	$(CC) $(CFLAGS) -o $@ $@.o entries.o $L

test: test.o
	$(CC) $(CFLAGS) -std=gnu99 -o $@ $@.o

clean:
	rm -f $(TOCLEAN)

nuke: clean
	rm -f  uthash.h

.PHONY: all clean

