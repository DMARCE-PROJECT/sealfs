#!/bin/sh

ksize=$((1024 * 1024 * 1024))
nossd=/var/tmp
ssd=/var/tmp/ssd	#not really
once=$HOME/tmp/once
datadir=/var/tmp/data
code=$HOME/gits/sealfs
wrounds=1000

if mount | grep -q 'type sealfs'
then
        echo sealfs is mounted, clean up before running the experiment >&2
        exit 1
fi

for d in $ssd/sealfs $once $datadir $code
do
	if ! test -d $d
	then
		echo $d does not exist, create it >&2
		exit 1
	fi
done

rm $ssd/sealfs/* $ssd/k[12]  2> /dev/null

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

for r in $ssd	#$nossd
do
        for shared in '-s' '-p'
        do
                for nprocs in 1 2 4 8 16 32 64
                do
                        for wsize in 100 1000 10000
			do
				for nratchet in 1 8 16 64
					do		
						disk=SSD
						echo 3 > /proc/sys/vm/drop_caches	#free pagecache and slab
		
						echo '#running without sealfs:' $shared disk:$disk nprocs:$nprocs nratchet:$nratchet wsize:$wsize wrounds:$wrounds
						rm $r/sealfs/* 2> /dev/null
						$code/tools/test $shared $nprocs $wsize $wrounds $r/sealfs > $datadir/$nprocs-$wsize$shared-RATCHET-$disk-NOSEALFS.data
		
						echo '#running with sealfs:' $shared disk:$disk nprocs:$nprocs wsize:$wsize wrounds:$wrounds
						rm $r/sealfs/* 2> /dev/null
						cp $once/.SEALFS.LOG  $r/sealfs/
						cp $once/k1 $r
		
					        if ! mount -t sealfs $r/sealfs $r/sealfs -o nratchet=$nratchet,kpath=$r/k1
					        then
					                echo cant mount >&2
					                exit 1
					        fi
						if ! mount | grep -q "on $r/sealfs type sealfs"
						then
						        echo sealfs is not mounted >&2
						        exit 1
						fi
						wnratchet=`seq -w $nratchet 100 | head -1`
						$code/tools/test $shared $nprocs $wsize $wrounds $r/sealfs > $datadir/$nprocs-$wsize$shared-RATCHET$wnratchet-$disk-SEALFS.data
		
					        x=$(grep -v 'HEATING' $r/sealfs/file??? | wc -l)
					        if test $x -ne $(($nprocs * $wrounds))
					        then
					                echo buggy: lines do not match: $x >&2
					                exit 1
					        fi
					        umount $r/sealfs
				done
			done
		done
	done
done
rmmod sealfs
