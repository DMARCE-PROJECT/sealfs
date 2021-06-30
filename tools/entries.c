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
	fprintf(f, "ratchetoffset: %ld "
		"inode: %ld "
		"offset: %ld "
		"count: %ld "
		"koffset: %ld\n",
		e->ratchetoffset,
		e->inode,
		e->offset,
		e->count,
		e->koffset);
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

static char *colred = "\x1b[31m";
static char *colgreen = "\x1b[32m";
static char *colend = "\x1b[0m";

int
dumplog(struct sealfs_logfile_entry *e, int fd, int typelog, int isok)
{
	FILE *s;
	char line[Bufsz];
	int fdx;

	if(typelog==LOGNONE){
		return 0;
	}
	fdx = dup(fd);
	if(fd < 0)
		return -1;
	s = fdopen(fdx, "r");
	if(s == NULL)
		return -1;
	if(fseek(s, e->offset, SEEK_SET) < 0){
		fclose(s);
		return -1;
	}
        while (fgets(line, Bufsz, s) != NULL) {
		if(strlen(line) >= e->count){
			line[e->count] = '\0';
		}
		if(typelog == LOGCOLOR){
			if(isok)
				printf("%ld: [OK] %s\n", e->inode, line);
			else
				printf("%ld: [BAD] %s\n", e->inode, line);
		}else{
			if(isok)
				printf("%ld: %s%s%s\n", e->inode, colgreen, line, colend);
			else
				printf("%ld: %s%s%s\n", e->inode, colred, line, colend);
		}
		
		if(ftell(s) - e->offset >= e->count)
			break;
        }
	fclose(s);
	return 0;
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
		 	       fprintf(stderr, "can't read from file, offset: %ld "
			       		"premature EOF or error, "
			       		" return value: %d\n",
		 		       e->offset+t, l);
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
ratchet_key(unsigned char *key, uint64_t roff, uint64_t nratchet)
{
	HMAC_CTX *c;
	unsigned int sz;
	int ret = -1;


	if(DEBUGENTRY){
		fprintf(stderr, "RATCHET: old, roff %lu ", roff);
		dumpkey(key);
	}
	c = HMAC_CTX_new();
	if(c == NULL){
	        fprintf(stderr, "HMAC_init: error\n");
		return -1;
	}
 	if(HMAC_Init_ex(c, key, FPR_SIZE, EVP_sha256(), NULL) == 0){
                fprintf(stderr, "HMAC_init: error\n");
		goto fail;
  	}
        if(HMAC_Update(c, (unsigned char*) &roff, sizeof(roff)) == 0){
		fprintf(stderr, "HMAC_Update error: roffset\n");
		goto fail;
	}
        if(HMAC_Update(c, (unsigned char*) &nratchet, sizeof(nratchet)) == 0){
		fprintf(stderr, "HMAC_Update error: nratchet\n");
		goto fail;
	}

 	if(HMAC_Final(c, key, &sz) == 0){
		fprintf(stderr, "HMAC_Final: error");
		goto fail;
	}
        if(sz != SHA256_DIGEST_SIZE){
                fprintf(stderr, "unexpected hmac size %d != %d", sz, SHA256_DIGEST_SIZE);
		goto fail;
	}
	ret = 0;
	if(DEBUGENTRY){
		fprintf(stderr, "RATCHET: new");
		dumpkey(key);
	}
fail:
	HMAC_CTX_free(c);
	return ret;
}

void
drop(KeyCache *kc)
{
	kc->lastkeyoff = -1;
	kc->lastroff = -1;
	memset(kc->key, 0, FPR_SIZE);
}
int
isrekey(KeyCache *kc, struct sealfs_logfile_entry *e)
{
	return kc->lastkeyoff != e->koffset;
}

int
ismiss(KeyCache *kc, struct sealfs_logfile_entry *e)
{
	return isrekey(kc, e) || kc->lastroff != e->ratchetoffset;
}

int
loadkey(KeyCache *kc, struct sealfs_logfile_entry *e, FILE *kf)
{
	if(fseek(kf, (long) e->koffset, SEEK_SET) < 0){
		fprintf(stderr, "can't seek kbeta\n");
		return -1;
	}
	if(fread(kc->key, FPR_SIZE, 1, kf) != 1){
		fprintf(stderr, "can't read kbeta\n");
		return -1;
	}
	if(DEBUGENTRY){
		fprintf(stderr, "read key\n");
		dumpkey(kc->key);
	}
	kc->lastkeyoff = e->koffset;
	kc->lastroff = 0;
	return 0;
}

void
ratchet(KeyCache *kc, FILE *kf, struct sealfs_logfile_entry *e, int nratchet)
{
	int i;
	for(i = kc->lastroff; i < e->ratchetoffset; i++){
		if(DEBUGENTRY){
			fprintf(stderr, "RERATCHET %d, off: %lu\n", i+1, e->ratchetoffset);
		}
		ratchet_key(kc->key, (uint64_t)(i+1), nratchet);
	}
	kc->lastroff = e->ratchetoffset;
}


int
isentryok(struct sealfs_logfile_entry *e, int logfd, FILE *kf,
		KeyCache *kc, int nratchet)
{
	unsigned char h[FPR_SIZE];

	// TO HELP DEBUG ISREKEY isrekey = 1;
	if(e->ratchetoffset == 0 || isrekey(kc, e)) {
		loadkey(kc, e, kf);
	}
	ratchet(kc, kf, e, nratchet);
	if(DEBUGENTRY){
		fprintf(stderr, "verifying key: ");
		dumpkey(kc->key);
	}
	if(makehmac(logfd, kc->key, e, h) < 0){
		fprintf(stderr, "can't make hmac\n");
		return 0;
	}
	return memcmp(h, e->fpr, FPR_SIZE) == 0;
}

enum {
	MAXNRATCHET = 512
};

int
nratchet_detect(struct sealfs_logfile_entry *e, int logfd, FILE *kf, int *nratchet)
{
	int nratchet_detected;
	int nr;
	KeyCache kc;

	nr = *nratchet;
	drop(&kc);
	nratchet_detected = 1;
	if(isentryok(e, logfd, kf, &kc, nr)){
		fprintf(stderr, "default nratchet: %d\n", nr);
	}else{
		nr = 1;
		drop(&kc);
		while(!isentryok(e, logfd, kf, &kc, nr)){
			nr++;
			if(nr > MAXNRATCHET){
				fprintf(stderr, "can't find an nratchet that works\n");
				nr = NRATCHETDEFAULT;	//continue as before
				nratchet_detected = 0;
				break;
			}
			drop(&kc);
		}
	}
	drop(&kc);
	if(nratchet_detected)
		fprintf(stderr, "nratchet detected: %d\n", nr);
	*nratchet = nr;
	return nratchet_detected;
}
