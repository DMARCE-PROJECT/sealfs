SEALFS_VERSION="0.2"

EXTRA_CFLAGS += -DSEALFS_VERSION=\"$(SEALFS_VERSION)\"

obj-m += sealfs.o

sealfs-y := dentry.o file.o inode.o main.o super.o lookup.o mmap.o
