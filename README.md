This SealFS prototype is based on wrapfs. The module has
been ported to 5.4.0-66 (the first version was for 4.8.17, then 4.15.0, 
see the tags, though some important BUGS have been removed since then, then 5.4.0-65).


SealFS is a Linux kernel module that implements a stackable file system
that authenticates the written data to provide tamper-evident logs. It
is based on a forward integrity model: upon exploitation, the attacker
is not able to fake the logs generated before elevating privileges.

When SealFS is mounted on top of another file system, it protects
all the files under the mount point. It only allows append-only write
operations and authenticates the data written to the underlying files
(served by other file system).

The current implementation is SealFSv2. SealFSv2
combines ratcheting and storage-based log anti-tamper protection.
This new approach is flexible and enables the user to decide between complete
theoretical security (like in SealFSv1) or partial linear degradation
(like in a classical ratchet scheme), exchanging storage for computation
with user defined parameters to balance security and resource usage.

If you are interested in the version 1 (SealFSv1) described by the paper 

	"SealFS: Storage-based tamper-evident logging" 
	(https://doi.org/10.1016/j.cose.2021.102325)

go to the tag "submitted".


To use it (the man pages of commands are in doc/man, for example, **nroff -man doc/man/sealfs.5** and so on).

```plaintext
       #in sealfs root
       make
       (cd tools; make)
       mkdir /tmp/xxx /tmp/yyy
       sudo insmod sealfs.ko
       tools/prep /tmp/xxx/.SEALFS.LOG /tmp/k1 /tmp/k2 100000000	#last number is size of keystream
       sudo mount -o kpath=/tmp/k1,nratchet=2048 -t sealfs /tmp/xxx /tmp/yyy
       #open files in yyy with append and write, rename them
       sudo umount /tmp/yyy
       tools/verify /tmp/yyy /tmp/k1 /tmp/k2
```
