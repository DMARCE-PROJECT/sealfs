SEALFS_VERSION="0.91"

EXTRA_CFLAGS += -DSEALFS_VERSION=\"$(SEALFS_VERSION)\"

obj-m += sealfs.o

sealfs-y := dentry.o file.o inode.o main.o super.o lookup.o mmap.o

all:
	make -C /lib/modules/$(shell uname -r)/build M=$(shell pwd) modules

clean:
	cp $(shell pwd)/tools/go/go.mod /tmp
	make -C /lib/modules/$(shell uname -r)/build M=$(shell pwd) clean
	cp /tmp/go.mod $(shell pwd)/tools/go/go.mod

.PHONY: all clean
