#!/bin/sh


usage(){
        echo "usage: outside.sh [-g] " 1>&2;
        exit 1
}
GOCMDS=false
if [ "$1" = '-g' ]; then
        GOCMDS=true
	shift
fi

if [ "$1" = '-i' ]; then
        INTERACTIVE=true
	shift
fi

if [ "$#" -ne 0 ]; then
        usage
fi

export GITSEAL=$(git rev-parse --show-toplevel)
sudo cp /boot/vmlinuz-$(uname -r) /tmp

export SEALCMDS="prep dump verify test"
export EXTRACMDS=" /usr/bin/sh /usr/bin/sed /usr/bin/awk /usr/bin/xxd $SEALCMDS"
#make all sealfs
cd $GITSEAL
make all || exit 1
cp sealfs.ko /var/tmp

cd tools
make all || exit 1
#add xxd for debugging
cp $EXTRACMDS /var/tmp

if [ "$GOCMDS" = true ]; then
	(
		cd $GITSEAL/tools/go/cmd
		(cd verify; go build; cp verify /var/tmp)
		(cd prep; go build; cp prep /var/tmp)
	)
fi

CMDSINSIDE=""
for i in $EXTRACMDS; do
	CMDNAME=`basename $i`
	CMDSINSIDE="$CMDSINSIDE -files /var/tmp/$CMDNAME"
done

export SEALHD=/var/tmp/sealhd

mount|grep $SEALHD && sudo umount $SEALHD
touch $SEALHD
rm "$SEALHD"
dd if=/dev/zero of=$SEALHD bs=1 count=1 seek=4G > /dev/null 2>&1
mkfs.ext3 $SEALHD > /dev/null 2>&1
mkdir -p /tmp/hd
sudo mount -o loop,user $SEALHD /tmp/hd || exit 1
#used to be 1G.
ksize=$((128 * 1024 * 1024))
sudo cp /var/tmp/sealfs.ko /tmp/hd
sudo /var/tmp/prep /tmp/hd/.SEALFS.LOG /tmp/hd/k1 /tmp/hd/k2 $ksize
sudo umount $SEALHD

cp $GITSEAL/tools/uroot/inside.sh /var/tmp/


export OUTPUT=/tmp/OUTPUT_seal
touch /tmp/OUTPUT_seal
rm "$OUTPUT"


if [ "$INTERACTIVE" = true ]; then
	sudo /var/tmp/inside.sh -o > $OUTPUT 
else
	sudo /var/tmp/inside.sh  -o > $OUTPUT 2> /dev/null &	
	PIDRUN=$!
	
	echo waiting for tests to finish
	while ! egrep 'ENDTEST' $OUTPUT; do
		sleep 1
		echo -n .
	done
	
	kill $PIDRUN
fi

rm -f /var/tmp/inside.sh /var/tmp/sealfs.ko /var/tmp/inside.sh
CMDS=`echo $CMDSINSIDE| sed 's/-files //g'`
rm $CMDS

rm "$SEALHD"
sed -E -n '/STARTTEST/,/ENDTEST|\#[^0-9]/p' $OUTPUT

if sed -E -n '/STARTTEST/,/ENDTEST|\#[^0-9]/p' $OUTPUT|grep FAIL > /dev/null; then
	echo cat $OUTPUT 1>&2
	echo FAILED TESTS 1>&2
	exit 1
else
	echo OK TESTS 1>&2
fi
exit 0

