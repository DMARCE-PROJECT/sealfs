#!/bin/sh

usage() {
	echo $0 2>&1
	exit 1
}

if [ $# -ne 0 ]; then
	usage
fi

TESTNAME=verification

#THIS CAN BE CHANGED FOR SPECIAL DISKS
ssd=/tmp/ssd
once=/tmp/once
code=$(git rev-parse --show-toplevel)

rm -r $ssd
mkdir -p $ssd
mkdir -p $ssd/sealfs
mkdir -p $once

r=$ssd

wrounds=1000
ksize=$((1024 * 1024 * 1024))

if mount | grep -q 'type sealfs'
then
        echo sealfs is mounted, clean up before running the experiment >&2
        exit 1
fi

for d in $ssd/sealfs $once $code
do
	if ! test -d $d
	then
		echo $d does not exist, create it >&2
		exit 1
	fi
done
rm $ssd/sealfs/* $ssd/k[12]  2> /dev/null
sync; sync


if ! test -f $once/k1 || ! test -f $once/.SEALFS.LOG
then
        echo preparing first >&2
	$code/tools/prep $once/.SEALFS.LOG $once/k1 $once/k2 $ksize >&2
fi

badcode () {
	echo could not make $1 in /tmp/code 2>&1
	exit 1
}

rm -rf /tmp/code
mkdir /tmp/code
cp -a $code/* /tmp/code
if test -f ${TESTNAME}_*; then
	filename=`echo ${TESTNAME}_*|sed s/${TESTNAME}_//g|head`
fi

(cd /tmp/code/module; make clean; make) || badcode kernel

(cd $code/tools; make) || badcode tools

runonce(){
	sudo rmmod sealfs
	if ! sudo insmod /tmp/code/module/sealfs.ko
	then
	        echo cant load module >&2
	        exit 1
	fi
	rm $r/sealfs/* 2> /dev/null
	cp $once/.SEALFS.LOG  $r/sealfs/
	cp $once/k1 $r
	if ! sudo mount -t sealfs $r/sealfs $r/sealfs -o async,nratchet=$nratchet,kpath=$r/k1
	  then
	          echo cant mount >&2
	          exit 1
	  fi
	if ! mount | grep -q "on $r/sealfs type sealfs"
	then
	   echo sealfs is not mounted >&2
	   exit 1
	fi
	nprocs=4
	wsize=100
	wrounds=250000
	end=$((wrounds*nprocs*wsize))
	
	$code/tools/test -s $nprocs $wsize $wrounds $r/sealfs > /dev/null
	inode=$(ls -i $r/sealfs|awk '{print $1}')
	sync; sync
	sudo umount $r/sealfs
	sync; sync
	if sudo $code/tools/verify $r/sealfs $r/k1 $once/k2 >/dev/null 2>&1; then
		echo OK for $1$nratchet
	else
		echo nprocs: $nprocs wsize: $wsize wrounds: $wrounds $r/sealfs 
		echo FAIL: sudo $code/tools/verify  $r/sealfs $r/k1 $once/k2 2>&1;
		exit 1
	fi
	echo
}

NRATCHET='1 2 32 64'
for n in `seq 1 20`; do
	for nratchet in $NRATCHET; do
		runonce
	done
done
sudo rmmod sealfs
