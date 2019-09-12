CC = gcc
L=-lssl -lcrypto
CFLAGS = -g -Wall -Wshadow
DEPS = ../sealfstypes.h
SRCS = $(wildcard *.c)
OBJS = $(SRCS:.c=.o)
TOCLEAN = prep $(OBJS)

verify: verify.o $(DEPS)
	$(CC) $(CFLAGS) -o $@ $@.o $L

prep: prep.o $(DEPS)
	$(CC) $(CFLAGS) -o $@ $@.o

dump: dump.o $(DEPS)
	$(CC) $(CFLAGS) -o $@ $@.o

test: test.o
	$(CC) $(CFLAGS) -std=gnu99 -o $@ $@.o

.PHONY: all clean

clean:
	rm -f $(TOCLEAN)

all: dump prep verify test
