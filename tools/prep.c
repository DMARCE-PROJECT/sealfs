#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <err.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/random.h>
#include <stdint.h>
#include "../sealfstypes.h" //shared with kernel module

enum{
	Bsz = 8*1024,
};

void
usage(void)
{
	errx(1, "usage: prep lfile kfile1 kfile2 kfile_size");
}

static void
createkfile(int kfd1, int kfd2,
		struct sealfs_keyfile_header *kheader,
		uint64_t sz)
{
	int w, rfd, nr;
	uint64_t t, tr;
	char buf[Bsz];

	w = write(kfd1, kheader, sizeof(struct sealfs_keyfile_header));
	if(w != sizeof(struct sealfs_keyfile_header))
		err(1, "can't write kheader in kfile1");
	w = write(kfd2, kheader, sizeof(struct sealfs_keyfile_header));
	if(w != sizeof(struct sealfs_keyfile_header))
		err(1, "can't write kheader in kfile2");
	rfd = open("/dev/urandom", O_RDONLY);
	if(rfd < 0)
		errx(1, "can't open urandom file");
	t = 0;
	while(t < sz){
		if(sz - t < Bsz)
			tr = sz - t;
		else
			tr = Bsz;
		nr = read(rfd, buf, tr);
		if(nr < 0)
			err(1, "can't read from /dev/urandom");
		if(nr == 0)
			err(1, "eof? bug");
		if(write(kfd1, buf, nr) != nr)
			err(1, "can't write kfile1");
		if(write(kfd2, buf, nr) != nr)
			err(1, "can't write kfile2s");
		t += nr;
	}
	close(rfd);
}

static void
createlfile(int fd, struct sealfs_logfile_header *lheader)
{
	int w;

	w = write(fd, lheader, sizeof(struct sealfs_logfile_header));
	if(w != sizeof(struct sealfs_logfile_header))
		err(1, "can't write lheader");
}

int
main(int argc, char *argv[])
{
	uint64_t sz;
	int lfd, kfd1, kfd2;
	struct sealfs_keyfile_header kheader;
	struct sealfs_logfile_header lheader;

	if(argc != 5)
		usage();
	sz = atoll(argv[4]);
	if(sz <= 0)
		usage();
	lfd = open(argv[1], O_WRONLY|O_CREAT|O_TRUNC, 0600);
	if(lfd<0)
		err(1, "can't create %s", argv[1]);
	kfd1 = open(argv[2], O_WRONLY|O_CREAT|O_TRUNC, 0600);
	if(kfd1<0)
		err(1, "can't create %s", argv[2]);
	kfd2 = open(argv[3], O_WRONLY|O_CREAT|O_TRUNC, 0600);
	if(kfd2<0)
		err(1, "can't create %s", argv[3]);

	if(getrandom(&kheader.magic, 8, 0) != 8)
		err(1, "can't generate magic");
	memset(&kheader, 0, sizeof(kheader));
	memset(&lheader, 0, sizeof(lheader));
	kheader.burnt = sizeof(struct sealfs_keyfile_header);
	lheader.magic = kheader.magic;
	createkfile(kfd1, kfd2, &kheader, sz);
	createlfile(lfd, &lheader);
	close(kfd1);
	close(kfd2);
	close(lfd);
	exit(EXIT_SUCCESS);
}
