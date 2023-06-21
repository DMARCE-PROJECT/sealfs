#!/bin/sh

nogit() {
	echo "sealgit does not exist: $SEALGIT" 1>&2;
	echo "set SEALGIT var before running script or run inside git" 1>&2;
	exit 1
}

if ! [ -d "$SEALGIT" ]; then
	export SEALGIT=$(git rev-parse --show-toplevel)
fi


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
	echo "	sudo umount /var/lib/docker/volumes/sealfsVolume/_data" 1>&2;
	echo "	docker volume rm sealfsVolume" 1>&2;
	exit 1
}

nodir() {
	echo "dir $1 does not exist" 1>&2;
	exit 1
}

nodir() {
	echo "could not mount $SEALDIR" 1>&2;
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

KSIZE=$((128 * 1024 * 1024))
echo "KSIZE: $KSIZE" 1>&2

echo "creating key" 1>&2

KFILE=`mktemp /tmp/KFILEXXXX`
echo > $KFILE

echo $KFILE
KFILE2=`mktemp /tmp/KFILE2XXXX`
$SEALGIT/tools/prep $SEALDIR/.SEALFS.LOG $KFILE $KFILE2  $KSIZE

docker volume create sealfsVolume
sudo mount -o kpath=$KFILE -t sealfs $SEALDIR /var/lib/docker/volumes/sealfsVolume/_data || nomount

echo "created volume $VOLNAME, save key file $KFILE2" 1>&2
