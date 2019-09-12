#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <err.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/wait.h>
#include <inttypes.h>

enum{
	Plen = 256,
	Heatingrnds = 500,
};

void
heating(int fd, int wsize)
{
	int i;
	char buf[wsize];
	int sz;

	sz = snprintf(buf, wsize, "[%d] HEATING ", getpid());
	for(i=sz; i<wsize-1; i++)
		buf[i] = 'X';
	buf[i] = '\n';

	for(i=0; i<Heatingrnds; i++){
		if(write(fd, buf, wsize) != wsize)
			err(1, "write failed!");
	}
}

static void
child(int fd, int wsize, int wrounds)
{
 	int i;
	int sz;
	char buf[wsize];
	unsigned cycles_low, cycles_high, cycles_low1, cycles_high1;
	uint64_t start, end;
	uint64_t times[wrounds];
	int nw;

	sz = snprintf(buf, wsize, "[%d] ", getpid());
	for(i=sz; i<wsize-1; i++)
		buf[i] = 'X';
	buf[i] = '\n';

	heating(fd, wsize);

	asm volatile ("CPUID\n\t"
	 	"RDTSC\n\t"
		 "mov %%edx, %0\n\t"
		 "mov %%eax, %1\n\t": "=r" (cycles_high), "=r" (cycles_low)::
		"%rax", "%rbx", "%rcx", "%rdx");

	asm volatile("RDTSCP\n\t"
		 "mov %%edx, %0\n\t"
		 "mov %%eax, %1\n\t"
		"CPUID\n\t": "=r" (cycles_high1), "=r" (cycles_low1):: "%rax",
		"%rbx", "%rcx", "%rdx");

	asm volatile ("CPUID\n\t"
		 "RDTSC\n\t"
		 "mov %%edx, %0\n\t"
		 "mov %%eax, %1\n\t": "=r" (cycles_high), "=r" (cycles_low)::
		"%rax", "%rbx", "%rcx", "%rdx");

	asm volatile("RDTSCP\n\t"
		 "mov %%edx, %0\n\t"
		 "mov %%eax, %1\n\t"
		"CPUID\n\t": "=r" (cycles_high1), "=r" (cycles_low1):: "%rax",
		"%rbx", "%rcx", "%rdx");

	for(i=0; i<wrounds; i++){
		asm volatile ("CPUID\n\t"
			 "RDTSC\n\t"
			 "mov %%edx, %0\n\t"
			 "mov %%eax, %1\n\t": "=r" (cycles_high), "=r"
			(cycles_low):: "%rax", "%rbx", "%rcx", "%rdx");

		nw = write(fd, buf, wsize);

		asm volatile("RDTSCP\n\t"
			 "mov %%edx, %0\n\t"
			 "mov %%eax, %1\n\t"
			 "CPUID\n\t": "=r" (cycles_high1), "=r"
			(cycles_low1):: "%rax", "%rbx", "%rcx", "%rdx");


		if(nw != wsize)
			err(1, "write failed!");

		start = ( ((uint64_t)cycles_high << 32) | cycles_low );
		end = ( ((uint64_t)cycles_high1 << 32) | cycles_low1 );

		if ( (end - start) < 0) {
			errx(1, "CRITICAL ERROR: loop:%d  start = %llu, end = %llu\n",
				i,
				(long long unsigned int) start,
				(long long unsigned int) end);
 		} else {
			times[i] = end - start;
		}
	}
	close(fd);
	for(i=0; i<wrounds; i++){
		printf("%lld\n", (long long) times[i]);
	}
}

void
usage()
{
	errx(1, "usage: test [-s | -p] nprocs wsize wrounds dir");
}

int
main(int argc, char *argv[])
{
 	int sts;
	int errors=0;
	int pid;
 	char fd = -1;
 	char path[Plen] = "";
	int i;
	int nprocs;
	int wrounds;
	int wsize;
	int shared = 0;

	if(argc != 6)
		usage();
	if(strcmp(argv[1], "-s") == 0){
		shared++;
	}else if(strcmp(argv[1], "-p") != 0){
		usage();
	}
	nprocs = atoi(argv[2]);
	if(nprocs > 256)
		errx(1, "too many procs (%d)", nprocs);
	wsize = atoi(argv[3]);
	wrounds = atoi(argv[4]);
	if(shared){
		snprintf(path, Plen, "%s/file000", argv[5]);
		fd = open(path,O_CREAT|O_TRUNC|O_APPEND|O_WRONLY, 0666);
		if(fd < 0)
			err(1, "can't open file %s", path);
	}
	for(i=0; i<nprocs; i++){
		switch(fork()){
		case -1:
			err(1, "can't fork");
		case 0:
			if(!shared){
				snprintf(path, Plen, "%s/file%03d", argv[5], i);
				fd = open(path,
					O_CREAT|O_TRUNC|O_APPEND|O_WRONLY, 0666);
				if(fd < 0)
					err(1, "cant open file %s", path);
			}
			child(fd, wsize, wrounds);
			exit(0);
		}
	}
	while((pid=wait(&sts)) != -1){
 		if(WIFEXITED(sts) && WEXITSTATUS(sts) != 0){
			fprintf(stderr, "process failed: %d\n", pid);
			errors++;
		}
	}
	exit(errors);
}
