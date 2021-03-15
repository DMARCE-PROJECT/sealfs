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
#include "entries.h"

enum{
	Maxpath=512,
	DEBUG = 0,
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
		if(freadentry(lf, &e) != 1){
 			if(ferror(lf))
				err(1, "can't read from lfile");
			else
				break; //we're done
		}
		if(DEBUG)
			fprintf(stderr, "read %lu bytes\n", sizeof(e));
		fprintf(stdout, "#%ld\n", c);
		fprintentry(stdout, &e);
		c++;
	}
 	printf("%ld entries dumped\n", c);
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
	if(DEBUG)
		fprintf(stderr, "read %lu bytes\n", sizeof(lheader));
	printf("magic: %ld\n", lheader.magic);
	dump(lf);
	fclose(lf);
	exit(EXIT_SUCCESS);
}
