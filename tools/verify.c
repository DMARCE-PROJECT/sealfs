#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <err.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdint.h>
#include <dirent.h>
#include <uthash.h>
#include <openssl/sha.h>
#include <openssl/err.h>
#include <openssl/hmac.h>
#include <openssl/evp.h>
#include <openssl/ossl_typ.h>
#include "../sealfstypes.h" //shared with kernel module

/*
 * https://troydhanson.github.io/uthash/userguide.html
 */

enum{
	Maxfiles = 256,
	Maxpath = 4 * 1024,
	Bufsz = 8 * 1024,
};

struct Ofile {
	uint64_t inode;
	int fd;
	uint64_t offset;
	UT_hash_handle hh; /* makes this structure hashable */
};
typedef struct Ofile Ofile;

static void
scandirfiles(char *path, Ofile **ofiles)
{
	DIR *d;
	struct dirent *ent;
	Ofile *o;
	char fpath[Maxpath];

	d = opendir(path);
	if(d == NULL)
		err(1, "can't open dir %s", path);
	while((ent = readdir(d)) != NULL ){
		if(ent->d_name[0] == '.')
			continue;
		switch(ent->d_type){
		case DT_DIR:
			snprintf(fpath, Maxpath, "%s/%s", path, ent->d_name);
			scandirfiles(fpath, ofiles);
			break;
		case DT_REG:
			if(strcmp(DEFAULTLNAME, ent->d_name) == 0)
				continue;
			o = malloc(sizeof(Ofile));
			memset(o, 0, sizeof(Ofile));
			if(o == NULL)
				err(1, "out of memory");
			o->inode = ent->d_ino;
			snprintf(fpath, Maxpath, "%s/%s", path, ent->d_name);
			o->fd = open(fpath, O_RDONLY);
			if(o->fd < 0)
			 	err(1, "can't open file %s", fpath);
 			HASH_ADD(hh, *ofiles, inode, sizeof(uint64_t), o);
		}
	}
	closedir(d);
}

static void
freeofiles(Ofile *ofiles)
{
	Ofile *o, *p;

    	for(o = ofiles; o != NULL;) {
		close(o->fd);
		p = o;
		o = o->hh.next;
		free(p);
    }
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
 	if(HMAC_Final(c, h, &sz) == 0){
		fprintf(stderr, "HMAC_Final: error");
		goto fail;
	}
        if(sz != SHA_DIGEST_LENGTH){
                fprintf(stderr, "unexpected hmac size");
		goto fail;
	}
	ret = 0;
fail:
	HMAC_CTX_free(c);
	return ret;
}

static int
isentryok(struct sealfs_logfile_entry *e, Ofile *o, FILE *kf)
{
	unsigned char k[FPR_SIZE];
	unsigned char h[FPR_SIZE];

	// ensure that the file doesn't have holes and it starts at offset 0.
	// file's records must be ordered in the log
	// coverage must be total

	if(o->offset != e->offset){
		fprintf(stderr, "bad: log's offsets do not match: "
			"%lld vs %lld\n",
			(long long) o->offset,
			(long long) e->offset);
		return 0;
	}
	o->offset += e->count;

	if(fseek(kf, (long) e->koffset, SEEK_SET) < 0){
		fprintf(stderr, "can't seek kbeta\n");
		return 0;
	}
	if(fread(k, FPR_SIZE, 1, kf) != 1){
		fprintf(stderr, "can't read kbeta\n");
		return 0;
	}
	if(makehmac(o->fd, k, e, h) < 0){
		fprintf(stderr, "can't make hmac\n");
		return 0;
	}
	return memcmp(h, e->fpr, FPR_SIZE) == 0;
}

static void
dumpofiles(Ofile *ofiles)
{
	Ofile *o;

	fprintf(stderr, "Ofiles: \n");
    	for(o = ofiles; o != NULL; o = o->hh.next)
		 fprintf(stderr, "ofile inode: %lld fd: %d\n",
	 		(long long)o->inode, o->fd);
}

static void
printentry(FILE *f, struct sealfs_logfile_entry *e)
{
	fprintf(f, "inode: %lld "
		"offset: %lld "
		"count: %lld "
		"koffset: %lld\n",
		(long long) e->inode,
		(long long) e->offset,
		(long long) e->count,
		(long long) e->koffset);
}

#define included(N, A, B) (((A) <= (N)) && ((N) < (B)))

static int
inrange(struct sealfs_logfile_entry *e, uint64_t begin, uint64_t end)
{
	return included(begin, e->offset, e->offset+e->count) ||
		included(end, e->offset, e->offset+e->count) ||
		(begin <= e->offset && e->offset+e->count <= end);
}

/*
 *  inode == 0, check all files, else check only the inode
 *  begin == 0 && end == 0, check the whole file
 *  precondition:  begin <= end
 */
static void
verify(FILE *kf, FILE* lf, char *path, uint64_t inode,
	uint64_t begin, uint64_t end)
{
	struct sealfs_logfile_entry e;
	Ofile *ofiles = NULL;
	Ofile *o = NULL;
	uint64_t c = 0;
	int szhdr = sizeof(struct sealfs_keyfile_header);

	scandirfiles(path, &ofiles);
	if(inode == 0)
		dumpofiles(ofiles);
 	for(;;){
		if(fread(&e, sizeof(e), 1, lf) != 1){
			if(ferror(lf))
				err(1, "can't read from lfile");
			else
				break; //we're done
		}
		HASH_FIND(hh, ofiles, &e.inode, sizeof(uint64_t), o);
		if(o == NULL)
			errx(1, "file with inode %lld not found!",
				(long long) e.inode);
		if(inode != 0){
			if(e.inode != inode)
				continue;
			if(end != 0 && !inrange(&e, begin, end))
				continue;
			/*
			 * init o->offset
			 * o->offset must be the e.offset of the first,
			 * record to check, not begin!
			 */
			if(o->offset == 0)
				o->offset = e.offset;
			printf("checking entry: ");
			printentry(stdout, &e);
		}
		if(! isentryok(&e, o, kf)){
			fprintf(stderr, "can't verify entry: ");
			printentry(stderr, &e);
			exit(1);
		}
		/*
		 * check continuity if we are checking the whole log
		 */
		if(inode == 0 && e.koffset != szhdr + c*FPR_SIZE){
			fprintf(stderr, "koffset not correct: %lld "
					"should be %lld for entry: ",
					(long long) e.koffset,
					(long long) sizeof(struct sealfs_keyfile_header)
						+ c*FPR_SIZE);
			printentry(stderr, &e);
			exit(1);
		}
		c++;
	}
	freeofiles(ofiles);
	if(c == 0)
 		errx(1, "error, no entries in the log\n");
	printf("%lld entries verified, correct logs\n", (long long) c);
}

static void
readchunk(FILE *f, char *p, uint64_t pos)
{
	long old;

	old = ftell(f);
	if(old < 0)
		err(1, "ftell failed");
	if(fseek(f, (long)pos, SEEK_SET) < 0)
		err(1, "fseek failed");
	if(fread(p, FPR_SIZE, 1, f) != 1)
		err(1, "fread failed");
	if(fseek(f, old, SEEK_SET) < 0)
		err(1, "fseek failed");
}

static void
checkkeystreams(FILE *alphaf, FILE *betaf, uint64_t burnt)
{
	char prevalpha[FPR_SIZE];
	char prevbeta[FPR_SIZE];
	char postalpha[FPR_SIZE];
	char postbeta[FPR_SIZE];
	struct stat stata;
	struct stat statb;

	if(fstat(fileno(alphaf), &stata) < 0)
		err(1, "can't stat alpha");
	if(fstat(fileno(betaf), &statb) < 0)
		err(1, "can't stat beta");
	if(stata.st_size != statb.st_size)
		errx(1, "keystreams size do not match");

	if(burnt > stata.st_size)
		errx(1, "keystreams are too small");

	readchunk(alphaf, prevalpha, burnt-FPR_SIZE);
	readchunk(betaf, prevbeta, burnt-FPR_SIZE);
	if(memcmp(prevalpha, prevbeta, FPR_SIZE) == 0)
		errx(1, "keystreams are not valid: last burnt chunk is equal");
	if(burnt == stata.st_size){
		fprintf(stderr, "alpha keystream is completely burnt\n");
		return;
	}
	readchunk(alphaf, postalpha, burnt);
	readchunk(betaf, postbeta, burnt);
	if(memcmp(postalpha, postbeta, FPR_SIZE) != 0)
		errx(1, "keystreams are wrong: first unburnt chunk is different");
}

static void
usage(void)
{
	fprintf(stderr, "USAGE: verify dir kalpha kbeta"
			" [-n lfilename] [-i inode begin end]\n");
	exit(1);
}

int
main(int argc, char *argv[])
{
	FILE *lf;
	FILE *betaf;
	FILE *alphaf;

	int64_t inode = 0;
	int64_t begin = 0;
	int64_t end = 0;
	char *lname = DEFAULTLNAME;
	char *dir;
	char *kalpha;
	char *kbeta;
	struct sealfs_keyfile_header kalphahdr;
	struct sealfs_keyfile_header kbetahdr;
	struct sealfs_logfile_header lheader;
	char lpath[Maxpath];
	int i;

	if(argc < 3 || argc > 8)
		usage();

	dir = argv[1];
	kalpha = argv[2];
	kbeta= argv[3];
	argc-=4;
	argv+=4;
	for(i=0; i<argc; i++){
		if(strncmp(argv[i], "-n", 2) == 0){
			if(argc > i+1){
				lname = argv[i+1];
				i++;
			}else{
				usage();
			}
		}else if(strncmp(argv[i], "-i", 2) == 0){
			if(argc > i+3){
				inode = atoll(argv[i+1]);
				begin = atoll(argv[i+2]);
				end = atoll(argv[i+3]);
				if(inode <= 0 || begin < 0 || end < begin)
 					usage();
				fprintf(stderr, "WARNING: verifying only "
					"one inode: %lld from byte %lld"
					" to byte %lld\n",
					(long long) inode,
					(long long) begin,
					(long long) end);
				i+=3;
			}else
				usage();
		}else
			usage();
	}
	snprintf(lpath, Maxpath, "%s/%s", dir, lname);

	alphaf = fopen(kalpha, "r");
	if(alphaf == NULL)
		err(1, "can't open %s", dir);
	betaf = fopen(kbeta, "r");
	if(betaf == NULL)
		err(1, "can't open %s", dir);
	lf = fopen(lpath, "r");
	if(lf == NULL)
		err(1, "can't open %s", lpath);
	if(fread(&kalphahdr, sizeof(kalphahdr), 1, alphaf) != 1)
		err(1, "can't read kalphahdr");
	if(fread(&kbetahdr, sizeof(kbetahdr), 1, betaf) != 1)
		err(1, "can't read kbetahdr");
	if(fread(&lheader, sizeof(lheader), 1, lf) != 1)
		err(1, "can't read lheader");
	if(lheader.magic != kalphahdr.magic || lheader.magic != kbetahdr.magic)
		errx(1, "magic numbers don't match");
	printf("k1 burnt: %lld\n", (long long)kalphahdr.burnt);
	checkkeystreams(alphaf, betaf, kalphahdr.burnt);
	verify(betaf, lf, dir, inode, begin, end);
	if(inode != 0)
		fprintf(stderr, "WARNING: you SHOULD run a"
			" complete verification"
			" to probe that the file has not been truncated\n");
	fclose(alphaf);
	fclose(betaf);
	fclose(lf);
	exit(EXIT_SUCCESS);
}
