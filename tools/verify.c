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
#include "heap.h"
#include "entries.h"

/*
 * https://troydhanson.github.io/uthash/userguide.html
 */

int	DEBUGJQUEUE;	//true only to debug jQUEUE

#define dhfprintf if(DEBUGJQUEUE)fprintf

enum{
	Maxfiles = 256,
	Maxpath = 4 * 1024,
};

struct Ofile {
	Heap *heap;
	uint64_t inode;
	int fd;
	uint64_t offset;
	UT_hash_handle hh; /* makes this structure hashable */
};
typedef struct Ofile Ofile;

struct Rename {
	uint64_t inode;
	uint64_t newinode;
	UT_hash_handle hh; /* makes this structure hashable */
};
typedef struct Rename Rename;

Rename *
newrename(uint64_t inode, uint64_t newinode)
{
	Rename *r;
	r = malloc(sizeof(Rename));
	memset(r, 0, sizeof(Rename));
	if(r == NULL)
		err(1, "out of memory");
	r->inode = inode;
	r->newinode = newinode;
	return r;
}

static void
scandirfiles(char *path, Ofile **ofiles, Rename *renames)
{
	DIR *d;
	struct dirent *ent;
	Ofile *o;
	char fpath[Maxpath];
	Rename *r;
	r = NULL;

	d = opendir(path);
	if(d == NULL)
		err(1, "can't open dir %s", path);
	while((ent = readdir(d)) != NULL ){
		if(ent->d_name[0] == '.')
			continue;
		switch(ent->d_type){
		case DT_DIR:
			snprintf(fpath, Maxpath, "%s/%s", path, ent->d_name);
			scandirfiles(fpath, ofiles, renames);
			break;
		case DT_REG:
			if(strcmp(DEFAULTLNAME, ent->d_name) == 0)
				continue;
			o = malloc(sizeof(Ofile));
			memset(o, 0, sizeof(Ofile));
			if(o == NULL)
				err(1, "out of memory");
			o->inode = ent->d_ino;
			HASH_FIND(hh, renames, &o->inode, sizeof(uint64_t), r);
			if(r != NULL) {
				o->inode = r->newinode;
				fprintf(stderr, "rename inode fs:%lu -> log:%lu\n",
					o->inode, r->newinode);
			}
			snprintf(fpath, Maxpath, "%s/%s", path, ent->d_name);
			o->fd = open(fpath, O_RDONLY);
			if(o->fd < 0)
			 	err(1, "can't open file %s", fpath);
			o->heap = createheap();
			if(o->heap == NULL)
				err(1, "problem allocating heap");
 			HASH_ADD(hh, *ofiles, inode, sizeof(uint64_t), o);
		}
	}
	closedir(d);
}

static inline int logint2(uint64_t i)
{
	int n;
	n = 0;
	while(i > 0){
		n++;
		i >>= 1;
	}
	return n;
}

static uint64_t
unifyoff(uint64_t offset, uint64_t ratchetoffset, uint64_t nratchet)
{
	//they should not overlap
	return (offset<<logint2(nratchet))+ratchetoffset;
}

//	Ensure that the file doesn't have holes and it starts at offset 0.
//		file's records must be *almost* ordered in the log
//		coverage must be total.
//	There may be some disorder (MaxHeapSz entries), we call this region a jqueue
//		jump-queue.
// 	Keep a minheap of offset and advance it when it is contiguous.
static int
checkjqueues(struct sealfs_logfile_entry *e, Ofile *o, int nratchet)
{
	uint64_t min;
	Heap *heap;
	struct sealfs_logfile_entry *ec;

	dhfprintf(stderr, "CHECKJQUEUE: %p\n", e);
	heap = o->heap;

	if(e != NULL) {
		if(o->offset == e->offset){
			o->offset += e->count;
			return 0;
		}
		ec = (struct sealfs_logfile_entry*)malloc(sizeof(*ec));
		if(!ec)
			err(1, "cannot allocate entry");
		memmove(ec, e, sizeof(struct sealfs_logfile_entry));
		if(insertheap(heap, unifyoff(ec->offset, ec->ratchetoffset, nratchet), ec) < 0){
			free(ec);
			ec = NULL;
			fprintf(stderr, "read %d entries without fixing a jqueue\n", MaxHeapSz);
			return -1;
		}
	}else if(heap == NULL)
		return 0;

	for(;;){	
		ec = (struct sealfs_logfile_entry*)popminheap(heap, &min);
		if(ec == NULL){
			dhfprintf(stderr, "JQUEUE NULL o:%lu\n", o->offset);
			break;
		}
		if(ec != NULL && o->offset == ec->offset){
			dhfprintf(stderr, "JQUEUE advance o:%lu\n", o->offset);
			o->offset += ec->count;
			free(ec);
		}else{
			dhfprintf(stderr, "JQUEUE no advance o:%lu, e:%lu\n",
					o->offset,ec->offset);
			insertheap(heap, min, ec);	//put it back, just took it, so there is place
			break;
		}
	}
	return 0;
}

static void
dumpheap(Heap *heap, int nratchet)
{
	uint64_t min;
	struct sealfs_logfile_entry *e;
	fprintf(stderr, "entries pending, [\n");
	for(;;){
		e = (struct sealfs_logfile_entry*)popminheap(heap, &min);
		if(e == NULL)
			break;
		fprintf(stderr, "\t");
		fprintf(stderr, "min: %ld %ld  ->",
			min, unifyoff(e->offset, e->ratchetoffset, nratchet));
		fprintentry(stderr, e);
	}
	fprintf(stderr, "]\n");
	
}

static void
checktailofiles(Ofile *ofiles, int nratchet)
{
	Ofile *o;
	int err = 0;
    	for(o = ofiles; o != NULL;) {
		if(o->heap != NULL && checkjqueues(NULL, o, nratchet) < 0){
			err = 1;
		}
		if(o->heap->count != 0){
			fprintf(stderr, 
				"disordered offsets pend for ofile inode: %ld fd: %d\n\t",
	 			o->inode, o->fd);
			dumpheap(o->heap, nratchet);
			err=1;
		}
		free(o->heap);
		o = o->hh.next;
	}
	if(err){
		exit(1);
	}
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

static void
freerenames(Rename *renames)
{
	Rename *r, *p;

    	for(r = renames; r != NULL;) {
		p = r;
		r = r->hh.next;
		free(p);
    }
}

static void
dumpofiles(Ofile *ofiles)
{
	Ofile *o;

	fprintf(stderr, "Ofiles: \n");
    	for(o = ofiles; o != NULL; o = o->hh.next)
		 fprintf(stderr, "ofile inode: %ld fd: %d\n",
	 		o->inode, o->fd);
}

#define included(N, A, B) (((A) <= (N)) && ((N) < (B)))

static int
inrange(struct sealfs_logfile_entry *e, uint64_t begin, uint64_t end)
{
	return included(begin, e->offset, e->offset+e->count) ||
		included(end, e->offset, e->offset+e->count) ||
		(begin <= e->offset && e->offset+e->count <= end);
}

enum {
	MAXNRATCHET = 512
};

/*
 *  inode == 0, check all files, else check only the inode
 *  begin == 0 && end == 0, check the whole file
 *  precondition:  begin <= end
 */
static void
verify(FILE *kf, FILE* lf, char *path, uint64_t inode,
	uint64_t begin, uint64_t end, Rename *renames, int nratchet)
{
	struct sealfs_logfile_entry e;
	Ofile *ofiles = NULL;
	Ofile *o = NULL;
	uint64_t c;
	int szhdr;
	KeyCache kc;
	int gotnratchet;
	int fd;

	c = 0;
	szhdr = sizeof(struct sealfs_keyfile_header);
	drop(&kc);
	gotnratchet = 0;

	scandirfiles(path, &ofiles, renames);
	if(inode == 0)
		dumpofiles(ofiles);
 	for(;;){
		if(freadentry(lf, &e) < 0){
			if(ferror(lf))
				err(1, "can't read from lfile");
			break; //we're done
		}
		HASH_FIND(hh, ofiles, &e.inode, sizeof(uint64_t), o);

		if(o == NULL && e.inode != FAKEINODE)
			errx(1, "file with inode %ld not found!",
				e.inode);
		fd = -1;
		if(e.inode != FAKEINODE)
			fd = o->fd;
			
		if(!gotnratchet && e.ratchetoffset >= 1){
			gotnratchet = nratchet_detect(&e, fd, kf, &nratchet);
		}
		if(e.inode == FAKEINODE){
			if(!isentryok(&e, fd, kf, &kc, nratchet)){
				fprintf(stderr, "can't verify entry: ");
				fprintentry(stderr, &e);
				exit(1);
			}
			goto done;
		}

		if(inode != 0){
			if(e.inode != inode || (end != 0 && !inrange(&e, begin, end)))
				continue;	
			/*
			 * init o->offset
			 * o->offset must be the e.offset of the first,
			 * record to check, not start!
			 * paurea: I don't understand this, is it a BUG?
			 */
			if(o->offset == 0)
				o->offset = e.offset;
			//printf("checking entry: ");
			//fprintentry(stdout, &e);
		}
		if(checkjqueues(&e, o, nratchet) < 0 || ! isentryok(&e, fd, kf, &kc, nratchet)){
			fprintf(stderr, "can't verify entry: ");
			fprintentry(stderr, &e);
			exit(1);
		}
done:
		/*
		 * check continuity if we are checking the whole log
		 * it may still be correct (see checkjqueue), but warn the user
		 */
		if(inode == 0 && e.koffset != szhdr + (c/nratchet)*FPR_SIZE){
			fprintf(stderr, "warning: koffset not correct: %ld "
					"should be %ld for entry: ",
					 e.koffset,
					sizeof(struct sealfs_keyfile_header)
						+  (c*nratchet + e.ratchetoffset)*FPR_SIZE);
			fprintentry(stderr, &e);
			//exit(1);
		}
		c++;
	}
	checktailofiles(ofiles, nratchet);
	freeofiles(ofiles);
	freerenames(renames);
	if(c == 0)
 		errx(1, "error, no entries in the log\n");
	printf("%ld entries verified, correct logs\n", c);
}

static void
readchunk(FILE *f, char *p, uint64_t pos)
{
	long old;

	old = ftell(f);
	if(old < 0)
		err(1, "ftell failed");
	if(fseek(f, (long)pos, SEEK_SET) < 0)
		err(1, "fseek failed reading chunk: %lu", pos);
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
			" [-Dh] [-n lfilename] [-i inode begin end] [-nfs0 nlog0 -nfs1 nlog1...] \n");
	exit(1);
}

static void
setdebugs(char *arg)
{
	int i;
	for(i = 0; i < strlen(arg); i++){
		if(arg[i] == 'h') {
			fprintf(stderr, "Debug: jqueue debugging\n");
			DEBUGJQUEUE++;
		}
	}
}

void
setinode_begend(char *argv[], int64_t *inode, int64_t *begin, int64_t *end)
{
	*inode = atoll(argv[0]);
	*begin = atoll(argv[1]);
	*end = atoll(argv[2]);
	if(inode <= 0 || begin < 0 || end < begin)
			usage();
	fprintf(stderr, "WARNING: verifying only "
		"one inode: %ld from byte %ld to byte %ld\n",
		*inode, *begin, *end);
}

int
main(int argc, char *argv[])
{
	FILE *lf;
	FILE *betaf;
	FILE *alphaf;

	int nratchet;
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
	Rename *renames;
	Rename *r;
	renames = NULL;
	nratchet = NRATCHET;
	if(argc < 3)
		usage();

	dir = argv[1];
	kalpha = argv[2];
	kbeta= argv[3];
	argc-=4;
	argv+=4;
	for(i=0; i<argc; i++){
		if(strnlen(argv[i], 2) >= 2 && argv[i][0] == '-' ) {
			if(argv[i][1] == 'D'){
				setdebugs(argv[i]+2); 
			}else if(atoi(argv[i]+1) != 0 && argc > i+1) {	
				r = newrename(atoi(argv[i]+1), atoi(argv[i+1]));
				HASH_ADD(hh, renames, inode, sizeof(uint64_t), r);
				i++;
			} else if(argv[i][1] == 'n' && argc > i+1){
				lname = argv[i+1];
				i++;
			} else if(argv[i][1] == 'i' && argc > i+3){
				setinode_begend(argv+i+1, &inode, &begin, &end);
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
	printf("k1 burnt: %ld\n", kalphahdr.burnt);
	checkkeystreams(alphaf, betaf, kalphahdr.burnt);
	verify(betaf, lf, dir, inode, begin, end, renames, nratchet);
	if(inode != 0)
		fprintf(stderr, "WARNING: you SHOULD run a"
			" complete verification"
			" to probe that the file has not been truncated\n");
	fclose(alphaf);
	fclose(betaf);
	fclose(lf);
	exit(EXIT_SUCCESS);
}
