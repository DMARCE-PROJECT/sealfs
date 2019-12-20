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

for r in $nossd $ssd
do
        for shared in '-s' '-p'
        do
                for nprocs in 1 2 4 8 16 32 64
                do
                        for wsize in 100 1000 10000
			do
				disk=SSD
				test $r = $nossd && disk=NOSSD

				echo '#running without sealfs:' $shared disk:$disk nprocs:$nprocs wsize:$wsize wrounds:$wrounds
				rm $r/sealfs/* 2> /dev/null
				$code/tools/test $shared $nprocs $wsize $wrounds $r/sealfs > $datadir/$nprocs-$wsize$shared-$disk-NOSEALFS.data

				echo '#running with sealfs:' $shared disk:$disk nprocs:$nprocs wsize:$wsize wrounds:$wrounds
				rm $r/sealfs/* 2> /dev/null
				cp $once/.SEALFS.LOG  $r/sealfs/
				cp $once/k1 $r
				cp $once/k1 $r/k2

			        if ! mount -t sealfs $r/sealfs $r/sealfs -o kpath=$r/k1
			        then
			                echo cant mount >&2
			                exit 1
			        fi
				if ! mount | grep -q "on $r/sealfs type sealfs"
				then
				        echo sealfs is not mounted >&2
				        exit 1
				fi

				$code/tools/test $shared $nprocs $wsize $wrounds $r/sealfs > $datadir/$nprocs-$wsize$shared-$disk-SEALFS.data

			        x=$(grep -v 'HEATING' $r/sealfs/file??? | wc -l)
			        if test $x -ne $(($nprocs * $wrounds))
			        then
			                echo buggy: lines do not match: $x >&2
			                exit 1
			        fi
			        umount $r/sealfs
				if ! ./verify $r/sealfs $r/k1 $r/k2
				then
					echo BUG: verification failed >&2
					exit 1
				fi
			done
		done
	done
done
rmmod sealfs
