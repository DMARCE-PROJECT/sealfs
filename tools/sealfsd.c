#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <err.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <regex.h>

/*
 * Simple daemon to reburn the burnt area of
 * kalpha periodically, version 0, can (should) be improved.
 */

enum{
	Bufsz = 1024 * 8,
	Maxmounts = 256,
	Maxpath = 256,
	Maxline = 2048,
	Wsize = 8
	Period = 1, // seconds
	WritesPerSecond = 100, // stimation, number of log entries per second
	Overburns = 10,  // number of overwrites
};

#define TAIL (((uint64_t)WritesPerSecond)*Period*Overburns*FPR_SIZE);

int urandomfd;


struct Mounted{
	char kalpha[Maxpath];
	char sealfslog[Maxpath];
};
typedef struct Mounted Mounted;

struct Table{
	Mounted arr[Maxmounts];
	int len;
};
typedef struct Table Table;

void
makemounted(Mounted *m, char *str)
{
	snprintf(m->kalpha, Maxpath, "PRUEBA BETA");
	snprintf(m->sealfslog, Maxpath, "PRUENA LOG");
}

int
findmounts(Table *table)
{
	char procpath[Maxpath];
	char line[Maxline];
	FILE *f;
	regex_t preg;
	char * regexpr = "^[^ ]+ +[^ ]+ +sealfs ";
	//char * regexpr = "^[^ ]+ +[^ ]+ +ext4 ";

	if(regcomp(&preg, regexpr, REG_EXTENDED|REG_NOSUB|REG_NEWLINE) < 0)
		err(1, "regcomp failed");
	snprintf(procpath, Maxpath, "/proc/%d/mounts", getpid());
	f = fopen(procpath, "r");
	if(f == NULL){
		fprintf(stderr, "can't open proc file\n");
		return -1;
	}
	while(fgets(line, Maxline, f) != NULL){
		if(regexec(&preg, line, 1, NULL, 0) == 0){
			fprintf(stderr, "mount matches: %s", line);
			makemounted(&(table->arr[table->len]), line);
 		}
	}
	if(!feof(f)){
		fprintf(stderr, "error while reading mounts\n");
		return -1;
	}
	fclose(f);
	return 0;
}

int
wrrand(int fd, uint64_t count)
{
	uint64_t total = 0;
	size_t sz = 0;
	char buf[Bufsz];

	while(total <= count){
		if(count - total < Bufsz)
			sz = count - total;
		else
		 	sz = Bufsz;
		if(nr = read(urandomfd, buf, sz) < 0){
			warn("can't read from /dev/urandom");
			return -1;
		}
		if(write(fd, buf, sz) != sz){
			warn("can't write tail");
			return -1;
		}
		total += sz;
	}
	if(fsync(fd) < 0){
		warn("fsync failed");
		return -1;
	}
	return 0;
}

int
reburn(char *path)
{
 	struct sealfs_keyfile_header kalphahdr;
	uint64_t burnt;
	uint64_t pos;
	uint64_t from;
	int fd;
	char random[Rsz];

	fd = open(path, O_RDWR);
	if(fd < 0){
		warn("can't open %s", path);
		return -1;
	}
	// short read not probable
	if(read(fd, &kalphahdr, sizeof(kalphahdr) != sizeof(kalphahdr)){
		warn("can't read kalpha header");
		return -1;
	}
	burnt = kalphahdr.burnt;

	if((long long)burnt - TAIL < sizeof(kalphahdr))
		from = sizeof(kalphahdr);
	else
		from = burnt - TAIL;

	if(seek(fd, from, SEEK_SET) != from){
		warn("can't seek kalpha");
		return -1;
	}
	if(wrrand(fd, TAIL) < 0){
		warn("can't write tail");
		return -1;
	}
	fclose(f);
	return 0;


int
doerase(Table *t)
{
	int i;
	int fd;

	for(i=0; i<t->len; i++){
		fprintf(stderr, "reburning %s\n", t->kalpha);
		if(reburn(t->kalpha) < 0){
			fprintf(stderr, "doerase: can't reburn %s\n",
				t[i]->kalpha);
		}
	}
}

int
main(int argc, char *argv[])
{
	Table t;

	//daemon(0, 1);

	if((urandomfd = open("/dev/urandom", O_READ)) < 0) {
		err(1, "can't open /dev/urandom");
	}
 	for(;;){
		sleep(Period);
		memset(&t, 0, sizeof(t));
		if(findmounts(&t) < 0){
			errx(1, "can't read mount table");
		}
		if(doerase(&t) < 0){
			fprintf(stderr, "warning: doerase() had problems");
		}
	}
	close(urandomfd);
	exit(EXIT_SUCCESS);
}
