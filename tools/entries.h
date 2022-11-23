extern void fprintentry(FILE *f, struct sealfs_logfile_entry *e);
extern int freadentry(FILE *f, struct sealfs_logfile_entry *e);
extern int dumplog(struct sealfs_logfile_entry *e, int fd, int typelog, int isok);
enum{
	Bufsz = 8 * 1024,
	NRATCHETDEFAULT=1,
};

struct KeyCache{
	unsigned char key[FPR_SIZE];
	uint64_t lastroff;
	uint64_t lastkeyoff;
};
typedef struct KeyCache KeyCache;

extern void drop(KeyCache *kc);
extern int isentryok(struct sealfs_logfile_entry *e, int logfd, FILE *kf, KeyCache *kc, int nratchet);
extern int nratchet_detect(struct sealfs_logfile_entry *e, int logfd, FILE *kf, int *nratchet);

enum {
	LOGNONE = 0,
	LOGTEXT,
	LOGCOLTEXT,
};
