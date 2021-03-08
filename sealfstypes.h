
// HMAC keylen is also FPR_SIZE
//	this is needed for verify.c in user space, both
// 	kernel and user space tools share this file, and
//	this definition is not present in user space
#ifndef SHA256_DIGEST_SIZE
#define SHA256_DIGEST_SIZE 32
#endif
#define FPR_SIZE SHA256_DIGEST_SIZE
#define DEFAULTLNAME ".SEALFS.LOG"

struct sealfs_keyfile_header {
	uint64_t magic;
	uint64_t burnt; //absolute offset, must start at 0+sizeof(header)
};

struct sealfs_logfile_header {
	uint64_t magic;
};

enum {
	NRATCHETDIGITS=3,
	NRATCHET=(1<<NRATCHETDIGITS)-1,
	FAKEINODE=0xffffffffffffffff,
};

struct sealfs_logfile_entry {
	uint64_t ratchetoffset;			//ratchet offset n of entries %NRATCHET
	uint64_t inode;				// file
	uint64_t offset;  			// in the file
	uint64_t count;   			// len of this write
	uint64_t koffset;			// offset in keyfile
	unsigned char fpr[FPR_SIZE];  // fingerprint
};
