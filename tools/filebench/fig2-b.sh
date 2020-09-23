#!/bin/sh

datadir=/home/esoriano/datafilebench
nossd=/var/tmp
ssd=/mnt/ssd
once=/home/esoriano/once
ksize=$((1024 * 1024 * 1024))
linksdir=/tmp/links/
nthreads=1

echo 0 > /proc/sys/kernel/randomize_va_space
rm $datadir/* 2> /dev/null

if ! lsmod | grep -q sealfs 
then
	echo sealfs module not loaded >&2
	exit 1
fi
if mount|grep sealfs
then
	echo sealfs is mounted 1>&2
	exit 1
fi

mkdir -p $linksdir

for r in $nossd $ssd
do
	for nprocs in 1 2 4 8 16 32 64
	do
		disk=SSD
		test $r = $nossd && disk=NOSSD

		echo '#running without sealfs:' disk:$disk nprocs:$nprocs nthreads:$nthreads
		rm $r/sealfs/* 2> /dev/null
		rm -rf $linksdir/* 2>/dev/null
		./createbenchfiles.sh $r/sealfs $linksdir $nprocs
		rm x.f 2> /dev/null
		sed -e "s/SEALFSNPROCS/$nprocs/" -e "s/SEALFSNTHREADS/$nthreads/" < fig2-b.f > x.f
		outputf=$datadir/fig2-b-ext4-$disk-NP$nprocs-NT$nthreads
		filebench -f x.f > $outputf  2>&1
		if test $? -ne 0 || ! grep -q 'IO Summary' $outputf
		then
			echo filebench failed >&2
			exit 1
		fi	

		echo '#running with sealfs:' disk:$disk nprocs:$nprocs nthreads:$nthreads
		rm $r/sealfs/* 2> /dev/null
		rm $r/k1x 2>/dev/null
                rm -rf $linksdir/*  2>/dev/null
		cp $once/.SEALFS.LOG  $r/sealfs
		cp $once/k1x $r
		sleep 2
		sync
		sync
		if ! mount -t sealfs $r/sealfs $r/sealfs -o kpath=$r/k1x
		then
			echo cant mount >&2
			exit 1
		fi
		if ! mount | grep -q "on $r/sealfs type sealfs"
		then
			echo sealfs is not mounted >&2
			exit 1
		fi
		./createbenchfiles.sh $r/sealfs $linksdir  $nprocs
		rm x.f 2> /dev/null
		sed -e "s/SEALFSNPROCS/$nprocs/" -e "s/SEALFSNTHREADS/$nthreads/" < fig2-b.f > x.f
		outputf=$datadir/fig2-b-sealfs-$disk-NP$nprocs-NT$nthreads
		filebench -f x.f > $outputf  2>&1
		umount $r/sealfs
		if mount|grep sealfs
		then
			echo sealfs is mounted 1>&2
			exit 1
		fi
                if test $? -ne 0 || ! grep -q 'IO Summary' $outputf
                then
                        echo filebench failed >&2
                        exit 1
                fi
	done
done

cp -a $datadir /home/esoriano/fig2

