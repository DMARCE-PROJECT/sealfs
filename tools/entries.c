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
	DEBUGENTRY = 0,
	MaxCount = 100*1024*1024	//100M more than enough
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
dumpbin(struct sealfs_logfile_entry *e, FILE *s, int typelog, int isok)
{
	char c;
	if(e->count > 0) {
		if(fseek(s, e->offset + e->count - 1, SEEK_SET) < 0){
			return -1;
		}
		if(fread(&c, 1, 1, s) < 1) {
			return -1;
		}
	}
	if(typelog == LOGCOLBIN){
		if(isok)
			printf("%s%ld:%s [%ld:%ld), %ld bytes\n", colgreen, e->inode, colend, e->offset, e->offset+e->count, e->count);
		else
			printf("%s%ld:%s [%ld:%ld), %ld bytes\n", colred, e->inode, colend, e->offset, e->offset+e->count, e->count);
	}else{
		if(isok)
			printf("%ld: [OK] [%ld:%ld), %ld bytes\n",  e->inode, e->offset, e->offset+e->count, e->count);
		else
			printf("%ld: [BAD] [%ld:%ld), %ld bytes\n",  e->inode, e->offset, e->offset+e->count, e->count);
	}
	return 0;
}

int
dumplog(struct sealfs_logfile_entry *e, int fd, int typelog, int isok)
{
	FILE *s;
	char line[Bufsz];
	int fdx;
	int ret;

	if(typelog==LOGNONE){
		return 0;
	}
	if(e->count > MaxCount) {
		return -1;
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
	if(typelog == LOGBIN || typelog == LOGCOLBIN){
		ret = dumpbin(e, s, typelog, isok);
		fclose(s);
		return ret;
	}
        while (fgets(line, Bufsz, s) != NULL) {
		if(strlen(line) >= e->count){
			line[e->count] = '\0';
		}
		if(typelog == LOGCOLTEXT){
			if(isok)
				printf("%s%ld:%s %s\n", colgreen, e->inode, colend, line);
			else
				printf("%s%ld:%s %s\n", colred, e->inode, colend, line);
		}else{
			if(isok)
				printf("%ld: [OK] %s\n", e->inode, line);
			else
				printf("%ld: [BAD] %s\n", e->inode, line);
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
	EVP_MD_CTX *c = NULL;
	EVP_PKEY *pkey = NULL;
 	int t = 0;
        int l;
	long unsigned int sz;
	int ret = -1;

	c = EVP_MD_CTX_create();
	if(c == NULL){
	        fprintf(stderr, "EVP_MD_CTX_create: error\n");
		return -1;
	}
	pkey = EVP_PKEY_new_mac_key(EVP_PKEY_HMAC, NULL, key, FPR_SIZE);
	if(pkey == NULL){
	        fprintf(stderr, "EVP_PKEY_new_mac_key: error\n");
		goto fail;
	}

 	if(!EVP_DigestSignInit(c, NULL, EVP_sha256(), NULL, pkey)){
                fprintf(stderr, "EVP_DigestSignInit: error\n");
		goto fail;
  	}
        if(!EVP_DigestSignUpdate(c, (unsigned char*) &e->ratchetoffset, sizeof(uint64_t))){
		fprintf(stderr, "EVP_DigestSignUpdate error: inode\n");
		goto fail;
	}

        if(!EVP_DigestSignUpdate(c, (unsigned char*) &e->inode, sizeof(uint64_t))){
		fprintf(stderr, "EVP_DigestSignUpdate error: inode\n");
		goto fail;
	}
	if(!EVP_DigestSignUpdate(c, (unsigned char*) &e->offset, sizeof(uint64_t))){
		fprintf(stderr, "EVP_DigestSignUpdate error: offset\n");
		goto fail;
	}
	if(!EVP_DigestSignUpdate(c, (unsigned char*) &e->count, sizeof(uint64_t))){
		fprintf(stderr, "EVP_DigestSignUpdate error: count\n");
		goto fail;
	}
	if(!EVP_DigestSignUpdate(c, (unsigned char*) &e->koffset, sizeof(uint64_t))){
		fprintf(stderr, "EVP_DigestSignUpdate error: koffset\n");
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
	                if(!EVP_DigestSignUpdate(c, buf, l)){
		                fprintf(stderr, "EVP_DigestSignUpdate: error\n");
				goto fail;
		 	}
			t += l;
	        }
	}
	sz = SHA256_DIGEST_SIZE;
        if(!EVP_DigestSignFinal(c, h, &sz)|| sz != SHA256_DIGEST_SIZE){
                fprintf(stderr, "unexpected hmac size %ld != %d", sz, SHA256_DIGEST_SIZE);
		goto fail;
	}
	ret = 0;
fail:
	EVP_PKEY_free(pkey);
	EVP_MD_CTX_destroy(c);
	return ret;
}

static int
ratchet_key(unsigned char *key, uint64_t roff, uint64_t nratchet)
{
	EVP_MD_CTX *c = NULL;
	EVP_PKEY *pkey = NULL;
	long unsigned int sz;
	int ret = -1;

	if(DEBUGENTRY){
		fprintf(stderr, "RATCHET: old, roff %lu nratchet %lu ", roff, nratchet);
		dumpkey(key);
	}
	c = EVP_MD_CTX_create();
	if(c == NULL){
	        fprintf(stderr, "HMAC_init: error\n");
		return -1;
	}
	pkey = EVP_PKEY_new_mac_key(EVP_PKEY_HMAC, NULL, key, FPR_SIZE);
	if(pkey == NULL){
	        fprintf(stderr, "EVP_PKEY_new_mac_key: error\n");
		goto fail;
	}
 	if(!EVP_DigestSignInit(c, NULL, EVP_sha256(), NULL, pkey)){
                fprintf(stderr, "EVP_DigestSignInit: error\n");
		goto fail;
  	}
        if(!EVP_DigestSignUpdate(c, (unsigned char*) &roff, sizeof(roff))){
		fprintf(stderr, "EVP_DigestSignUpdate error: roffset\n");
		goto fail;
	}
        if(!EVP_DigestSignUpdate(c, (unsigned char*) &nratchet, sizeof(nratchet))){
		fprintf(stderr, "EVP_DigestSignUpdate error: nratchet\n");
		goto fail;
	}

	sz = SHA256_DIGEST_SIZE;
        if(!EVP_DigestSignFinal(c, key, &sz) || sz != SHA256_DIGEST_SIZE){
                fprintf(stderr, "unexpected hmac size %ld != %d", sz, SHA256_DIGEST_SIZE);
		goto fail;
	}
	ret = 0;
	if(DEBUGENTRY){
		fprintf(stderr, "RATCHET: new");
		dumpkey(key);
	}
fail:
	EVP_PKEY_free(pkey);
	EVP_MD_CTX_destroy(c);
	return ret;
}

void
drop(KeyCache *kc)
{
	kc->lastkeyoff = -1;
	kc->lastroff = -1;
	memset(kc->key, 0, FPR_SIZE);
}

static int
isrekey(KeyCache *kc, struct sealfs_logfile_entry *e)
{
	int isrek;
	isrek = kc->lastkeyoff != e->koffset || kc->lastroff > e->ratchetoffset;
	isrek = isrek || kc->lastkeyoff == -1 || e->ratchetoffset == 0;
	return isrek;
}


static int
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
ratchet(KeyCache *kc, struct sealfs_logfile_entry *e, int nratchet)
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
updatecache(KeyCache *kc, FILE *kf, struct sealfs_logfile_entry *e, int nratchet)
{
	// TO HELP DEBUG ISREKEY isrekey = 1;
	if(isrekey(kc, e)) {
		if(loadkey(kc, e, kf) < 0)
			return -1;
		if(nratchet != 1)
			ratchet_key(kc->key, 0, nratchet);
	}
	ratchet(kc, e, nratchet);
	return 0;
}

int
isentryok(struct sealfs_logfile_entry *e, int logfd, FILE *kf,
		KeyCache *kc, int nratchet)
{
	unsigned char h[FPR_SIZE];

	if(e->ratchetoffset > nratchet || e->count > MaxCount) {
		return 0;
	}
	// TO HELP DEBUG ISREKEY isrekey = 1;
	if(updatecache(kc, kf, e, nratchet) < 0){
		return 0;
	}
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
