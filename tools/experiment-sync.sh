#!/bin/sh

ksize=$((1024 * 1024 * 1024))
nossd=/var/tmp
ssd=/mnt/ssd
once=/home/esoriano/once
datadir=/home/esoriano/data
code=/home/esoriano/sealfs
wrounds=1000

if mount | grep -q 'type sealfs'
then
        echo sealfs is mounted, clean up before running the experiment >&2
        exit 1
fi

for d in $ssd/sealfs $nossd/sealfs $once $datadir $code
do
	if ! test -d $d
	then
		echo $d does not exist, create it >&2
		exit 1
	fi
done

rm $ssd/sealfs/* $nossd/sealfs/* $ssd/k[12] $nossd/k[12] 2> /dev/null

if ! test -f $once/k1 || ! test -f $once/.SEALFS.LOG
then
        echo prepare first >&2
	echo run: $code/tools/prep $once/.SEALFS.LOG $once/k1 $once/k2 $ksize >&2
	exit 1
fi

if ! insmod $code/sealfs.ko
then
        echo cant load module >&2
        exit 1
fi

shared='-s'
nprocs=1
for r in $nossd $ssd
do
	for wsize in 100 1000
	do
		disk=SSD
		test $r = $nossd && disk=NOSSD

		echo '#running with sealfs:' $shared disk:$disk nprocs:$nprocs wsize:$wsize wrounds:$wrounds SYNC
		rm $r/sealfs/* 2> /dev/null
		cp $once/.SEALFS.LOG  $r/sealfs/
		cp $once/k1 $r

	        if ! mount -t sealfs $r/sealfs $r/sealfs -o kpath=$r/k1,syncio
	        then
	                echo cant mount >&2
	                exit 1
	        fi
		if ! mount | grep -q "on $r/sealfs type sealfs"
		then
		        echo sealfs is not mounted >&2
		        exit 1
		fi

		$code/tools/test $shared $nprocs $wsize $wrounds $r/sealfs > $datadir/$nprocs-$wsize$shared-$disk-SEALFS-SYNC.data

	        x=$(grep -v 'HEATING' $r/sealfs/file??? | wc -l)
	        if test $x -ne $(($nprocs * $wrounds))
	        then
	                echo buggy: lines do not match: $x >&2
	                exit 1
	        fi
	        umount $r/sealfs
	done
done
rmmod sealfs
