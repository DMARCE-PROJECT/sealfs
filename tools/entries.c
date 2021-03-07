#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <openssl/sha.h>
#include <openssl/err.h>
#include <openssl/hmac.h>
#include <openssl/evp.h>
#include <openssl/ossl_typ.h>
#include "../sealfstypes.h" //shared with kernel module
#include "entries.h"

enum {
	DEBUGENTRY = 0
};

static void
dumpkey(unsigned char *key)
{
	int i;
	char str[3*FPR_SIZE];
	for(i = 0; i <FPR_SIZE; i++)
		sprintf(str+3*i, "%2.2x ", key[i]);
	fprintf(stderr, "KEY %s\n", str);
}

void
fprintentry(FILE *f, struct sealfs_logfile_entry *e)
{
	fprintf(f, "ratchetoffset: %lld "
		"inode: %lld "
		"offset: %lld "
		"count: %lld "
		"koffset: %lld\n",
		(long long) e->ratchetoffset,
		(long long) e->inode,
		(long long) e->offset,
		(long long) e->count,
		(long long) e->koffset);
}

int
freadentry(FILE *f, struct sealfs_logfile_entry *e)
{
	int n;
	n = fread(e, sizeof(*e), 1, f);
	if(n != 1)
		return -1;
	return 1;
}

static int
makehmac(int fd, unsigned char *key,
	struct sealfs_logfile_entry *e , unsigned char *h)
{
	unsigned char buf[Bufsz];
	HMAC_CTX *c;
 	int t = 0;
        int l;
	unsigned int sz;
	int ret = -1;


	c = HMAC_CTX_new();
	if(c == NULL){
	        fprintf(stderr, "HMAC_init: error\n");
		return -1;
	}
 	if(HMAC_Init_ex(c, key, FPR_SIZE, EVP_sha256(), NULL) == 0){
                fprintf(stderr, "HMAC_init: error\n");
		goto fail;
  	}
        if(HMAC_Update(c, (unsigned char*) &e->ratchetoffset, sizeof(uint64_t)) == 0){
		fprintf(stderr, "HMAC_Update error: inode\n");
		goto fail;
	}

        if(HMAC_Update(c, (unsigned char*) &e->inode, sizeof(uint64_t)) == 0){
		fprintf(stderr, "HMAC_Update error: inode\n");
		goto fail;
	}
	if(HMAC_Update(c, (unsigned char*) &e->offset, sizeof(uint64_t)) == 0){
		fprintf(stderr, "HMAC_Update error: offset\n");
		goto fail;
	}
	if(HMAC_Update(c, (unsigned char*) &e->count, sizeof(uint64_t)) == 0){
		fprintf(stderr, "HMAC_Update error: count\n");
		goto fail;
	}
	if(HMAC_Update(c, (unsigned char*) &e->koffset, sizeof(uint64_t)) == 0){
		fprintf(stderr, "HMAC_Update error: koffset\n");
		goto fail;
	}

	if(fd > 0){
  	     	while(t < e->count){
			if(e->count-t < Bufsz)
				l = pread(fd, buf, e->count-t, e->offset+t);
			else
				l = pread(fd, buf, Bufsz, e->offset+t);
			if(l <= 0){
		 	       fprintf(stderr, "can't read from file, offset: %lld "
			       		"premature EOF or error, "
			       		" return value: %d\n",
		 		       (long long)e->offset+t, l);
		 	       goto fail;
			}
	                if(HMAC_Update(c, buf, l) == 0){
		                fprintf(stderr, "HMAC_Update: error\n");
				goto fail;
		 	}
			t += l;
	        }
	}
 	if(HMAC_Final(c, h, &sz) == 0){
		fprintf(stderr, "HMAC_Final: error");
		goto fail;
	}
        if(sz != SHA256_DIGEST_SIZE){
                fprintf(stderr, "unexpected hmac size %d != %d", sz, SHA256_DIGEST_SIZE);
		goto fail;
	}
	ret = 0;
fail:
	HMAC_CTX_free(c);
	return ret;
}

static int
ratchet_key(unsigned char *prevkey, unsigned char *newkey, uint64_t roff)
{
	HMAC_CTX *c;
	unsigned int sz;
	int ret = -1;


	c = HMAC_CTX_new();
	if(c == NULL){
	        fprintf(stderr, "HMAC_init: error\n");
		return -1;
	}
 	if(HMAC_Init_ex(c, prevkey, FPR_SIZE, EVP_sha256(), NULL) == 0){
                fprintf(stderr, "HMAC_init: error\n");
		goto fail;
  	}
        if(HMAC_Update(c, (unsigned char*) &roff, sizeof(roff)) == 0){
		fprintf(stderr, "HMAC_Update error: inode\n");
		goto fail;
	}

 	if(HMAC_Final(c, newkey, &sz) == 0){
		fprintf(stderr, "HMAC_Final: error");
		goto fail;
	}
        if(sz != SHA256_DIGEST_SIZE){
                fprintf(stderr, "unexpected hmac size %d != %d", sz, SHA256_DIGEST_SIZE);
		goto fail;
	}
	ret = 0;
	if(DEBUGENTRY){
		fprintf(stderr, "RATCHET: old, roff %lu ", roff);
		dumpkey(prevkey);
		fprintf(stderr, "RATCHET: new");
		dumpkey(newkey);
	}
fail:
	HMAC_CTX_free(c);
	return ret;
}
int
isentryok(struct sealfs_logfile_entry *e, int logfd, FILE *kf, unsigned char *oldkey, uint64_t lastkeyoff)
{
	unsigned char h[FPR_SIZE];
	unsigned char k[FPR_SIZE];
	int isreratchet;
	int i;
	
	isreratchet = lastkeyoff != e->koffset;
	// TO DEBUG RERATCHET isreratchet = 1;
	if(e->ratchetoffset == 0 || isreratchet) {
		if(fseek(kf, (long) e->koffset, SEEK_SET) < 0){
			fprintf(stderr, "can't seek kbeta\n");
			return 0;
		}
		if(fread(k, FPR_SIZE, 1, kf) != 1){
			fprintf(stderr, "can't read kbeta\n");
			return 0;
		}
		memmove(oldkey, k, FPR_SIZE);
		if(DEBUGENTRY){
			fprintf(stderr, "read key\n");
			dumpkey(k);
		}
		if(isreratchet){
			for(i = 0; i < e->ratchetoffset; i++){
				if(DEBUGENTRY){
					fprintf(stderr, "RERATCHET %d, off: %lu\n", i+1, e->ratchetoffset);
				}
				ratchet_key(oldkey, k, (uint64_t)(i+1));
				memmove(oldkey, k, FPR_SIZE);
			}
		}
	}else{
		ratchet_key(oldkey, k, e->ratchetoffset);
		memmove(oldkey, k, FPR_SIZE);
	}
	if(DEBUGENTRY){
		fprintf(stderr, "verifying key: ");
		dumpkey(k);
	}
	if(makehmac(logfd, k, e, h) < 0){
		fprintf(stderr, "can't make hmac\n");
		return 0;
	}
	return memcmp(h, e->fpr, FPR_SIZE) == 0;
}
