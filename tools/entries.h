extern void fprintentry(FILE *f, struct sealfs_logfile_entry *e);
extern int freadentry(FILE *f, struct sealfs_logfile_entry *e);
enum{
	Bufsz = 8 * 1024,
};

struct KeyCache{
	unsigned char key[FPR_SIZE];
	uint64_t lastroff;
	uint64_t lastkeyoff;
};
typedef struct KeyCache KeyCache;
extern int isentryok(struct sealfs_logfile_entry *e, int logfd, FILE *kf, KeyCache *kc, int nratchet);

extern void drop(KeyCache *kc);
extern int isrekey(KeyCache *kc, struct sealfs_logfile_entry *e);
extern int ismiss(KeyCache *kc, struct sealfs_logfile_entry *e);
extern int loadkey(KeyCache *kc, struct sealfs_logfile_entry *e, FILE *kf);
extern void ratchet(KeyCache *kc, FILE *kf, struct sealfs_logfile_entry *e, int nratchet);
