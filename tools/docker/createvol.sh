#!/bin/sh

nogit() {
	echo "sealgit does not exist: $SEALGIT" 1>&2;
	echo "configure SEALGIT in script" 1>&2;
	exit 1
}

export SEALGIT=/home/paurea/gits/sealfs

if ! [ -d "$SEALGIT" ]; then
	nogit
fi

(cd $SEALGIT/tools; make > /dev/null)

usage() {
	echo "usage: $0 dir" 1>&2;
	exit 1
}

VOLNAME=sealfsVolume

already() {
	echo "volume $VOLNAME already exists" 1>&2;
	echo "make sure it is not in use and run:" 1>&2;
	echo "	docker volume rm sealfsVolume" 1>&2;
	exit 1
}

nodir() {
	echo "dir $1 does not exist" 1>&2;
	exit 1
}

nosealfs() {
	echo "no sealfs support in kernel" 1>&2;
	echo "run as root:" 1>&2;
	echo "	insmod sealfs.ko" 1>&2;
	exit 1
}

case $# in
1)
	SEALDIR=$1
	shift
	;;
*)
	usage
esac

if ! [ -d "$SEALDIR" ]; then
	nodir $SEALDIR
fi

if ! lsmod|grep -q sealfs > /dev/null; then
	nosealfs
fi

NAME=`docker volume ls|grep $VOLNAME`
if [ "$NAME" ]; then
	already
fi

#takes two minutes for 16M on my machine to create with the algorithm below
KSIZE=$((16 * 1024 * 1024))
echo "KSIZE: $KSIZE" 1>&2

echo "creating key" 1>&2

KFILE=`mktemp /tmp/KFILEXXXX`
for i in `seq 1 64`; do
	for j in `seq 1 8`; do
		head -c $(($KSIZE/ (8*64) )) /dev/zero | openssl enc -aes-256-cbc -pbkdf2 -iter 100000 -salt -pass pass:"$(head -c 20 /dev/urandom | base64)" >> $KFILE &
	done
	wait
done
echo $KFILE
KFILE2=`mktemp /tmp/KFILE2XXXX`
cat $KFILE > $KFILE2
$SEALGIT/tools/prep $SEALDIR/.SEALFS.LOG $KFILE $KFILE2  $KSIZE

docker volume create sealfsVolume
sudo mount -o kpath=$KFILE -t sealfs $SEALDIR /var/lib/docker/volumes/sealfsVolume/_data && nomount

echo "created volume $VOLNAME, save key file $KFILE2" 1>&2
