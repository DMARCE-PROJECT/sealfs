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
#include "../sealfstypes.h" //shared with kernel module

enum{
	Maxpath=512,
};

void
usage(void)
{
	errx(1, "dump dir [lfilename]");
}

static void
dump(FILE* lf)
{
	struct sealfs_logfile_entry e;
	uint64_t c = 0;
  	for(;;){
		if(fread(&e, sizeof(e), 1, lf) != 1){
 			if(ferror(lf))
				err(1, "can't read from lfile");
			else
				break; //we're done
		}
		printf("#%lld\n"
			"\tinode: %lld\n"
			"\toffset: %lld\n"
			"\tcount: %lld\n"
			"\tkoffset: %lld\n",
			(long long) c,
			(long long) e.inode,
			(long long) e.offset,
			(long long) e.count,
			(long long) e.koffset);
		c++;
	}
 	printf("%lld entries dumped\n", (long long) c);
}

int
main(int argc, char *argv[])
{
	FILE *lf;
	char *lname = DEFAULTLNAME;
	struct sealfs_logfile_header lheader;
	char lpath[Maxpath];

	if(argc != 2 && argc != 3)
		usage();
	if(argc == 3)
		lname = argv[2];
	snprintf(lpath, Maxpath, "%s/%s", argv[1], lname);

	lf = fopen(lpath, "r");
	if(lf == NULL)
		err(1, "can't open %s", lpath);
 	if(fread(&lheader, sizeof(lheader), 1, lf) != 1)
		err(1, "can't read lheader");
	printf("magic: %lld\n", (long long)lheader.magic);
	dump(lf);
	fclose(lf);
	exit(EXIT_SUCCESS);
}
