void fprintentry(FILE *f, struct sealfs_logfile_entry *e);
int freadentry(FILE *f, struct sealfs_logfile_entry *e);
int isentryok(struct sealfs_logfile_entry *e, int logfd, FILE *kf, unsigned char *oldkey, uint64_t lastkeyoff);
enum{
	Bufsz = 8 * 1024,
};