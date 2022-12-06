This SealFS prototype is based on wrapfs. The module has
been ported to 5.4.0-66 (the first version was for 4.8.17, then 4.15.0, 
see the tags, though some important BUGS have been removed since then, 5.4.0-65).


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


To use it (the man pages of commands are in doc/man, for example, **nroff -man doc/man/sealfs.5** and so on).

```plaintext
       #in sealfs repository dir running as root
       make
       (cd tools; make)
       mkdir /var/logsback /var/seclogs
       sudo insmod sealfs.ko
       tools/prep /var/logsback/.SEALFS.LOG /var/keys/k1 /var/keys/k2 100000000	#last number is size of keystream
       #keep k2 save on another machine
       sudo mount -o kpath=/var/keys/k1,nratchet=2048 -t sealfs /var/logsback /var/seclogs
       #open files in seclogs with append and write, rename them
       echo 'log entry, I am running' >> /tmp/yyy/v.log
       mv /tmp/yyy/v.log /tmp/yyy/v.log.1
       #stop creating logs entries
       sudo umount /var/seclogs
       #forensic analysis, preferably on another clean machine mounting the hard disk
       #recover k2 from the external place in it which was saved
       tools/verify /var/logsback /var/keys/k1 /var/keys/k2
```

If you are interested in the version 2 (SealFSv2) described by the [paper](https://doi.org/10.1016/j.cose.2021.102325)

	"SealFSv2: Combining Storage-Based and Ratcheting for Tamper-evident Logging"

go to the tag **v2_1.0.0**

If you are interested in the version 1 (SealFSv1) described by the [paper](https://doi.org/10.1016/j.cose.2021.102325) 

	"SealFS: Storage-based tamper-evident logging" 


go to the tag **submitted**.

