#!/bin/sh


usage(){
	echo $0 sealfspath localpath nfiles 1>&2
	exit 1
}

if [ $# != 3 ]; then
	usage
fi

if ! test -d $1; then
	echo $1 is not a directory 1>&2
	usage
fi

SEALPATH=$1
shift

if ! test -d $1; then
	echo $1 is not a directory 1>&2
	usage
fi

LOCALPATH=$1
shift

export NFILES=$1
shift

if [ $# != 0 ]; then
	echo too many arguments 1>&2
	usage
fi


echo '#'sealpath: $SEALPATH localpath: $LOCALPATH nfiles: $NFILES 1>&2


for i in `seq -w 1 10000000 |head -$NFILES`; do
	mkdir -p "$LOCALPATH"/testF/$i
done

for i in `seq -w 1 10000000|head -$NFILES`; do
	touch $SEALPATH/$i
	ln -s $SEALPATH/$i "$LOCALPATH"/testF/$i/00000001
done
