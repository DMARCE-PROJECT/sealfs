#!/bin/sh

usage(){
        echo "usage: runtest [-i]" 1>&2;
        exit 1
}

if [ "$1" = '-i' ]; then
        INTERACTIVE=true
	shift
fi

if [ "$#" -ne 0 ]; then
        usage
fi

PATHuroot=$(which u-root)
PATHqemu=$(which qemu-system-x86_64)
if ! [ -x $PATHuroot ] || ! [ -x $PATHqemu ]; then
	echo '#' make sure you run: 1>&2
	echo '	'sudo apt install qemu-system qemu-system-x86 1>&2
	echo '	'go get github.com/u-root/u-root 1>&2
	exit 1
fi

#prepare a kernel in tmp
export GITSEAL=$(cleanname $PWD/../..)
sudo cp /boot/vmlinuz-$(uname -r) /tmp
sudo chown 777 /tmp/
export KERNEL=/tmp/vmlinuz-$(uname -r)
sudo chown $USER $KERNEL
chmod 777 $KERNEL

export SEALCMDS="prep dump verify test /usr/bin/sh"
export EXTRACMDS="/usr/bin/sed /usr/bin/awk /usr/bin/xxd $SEALCMDS"
#make all sealfs
cd $GITSEAL
make all || exit 1
cp sealfs.ko /var/tmp
cd tools
make all || exit 1
#add xxd for debugging
cp $EXTRACMDS /var/tmp


CMDSINSIDE=""
for i in $EXTRACMDS; do
	CMDNAME=`basename $i`
	CMDSINSIDE="$CMDSINSIDE -files /var/tmp/$CMDNAME"
done

echo building uroot
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
sudo /var/tmp/prep /tmp/hd/.SEALFS.LOG /tmp/hd/k1 /tmp/hd/k2 $ksize
sudo umount $SEALHD


cp $GITSEAL/tools/uroot/inside.sh /var/tmp/
chmod +x /var/tmp/inside.sh
if ! u-root -uinitcmd=/var/tmp/inside.sh $CMDSINSIDE -files "/var/tmp/sealfs.ko" -files /var/tmp/inside.sh> /tmp/$$_uroot 2>&1; then
	cat /tmp/$$_uroot 1>&2
	echo u-root error  1>&2
	exit 1
fi


rm -f /var/tmp/inside.sh /var/tmp/sealfs.ko /var/tmp/verify  /var/tmp/prep  /var/tmp/dump  /var/tmp/inside.sh /var/tmp/test


export OUTPUT=/tmp/OUTPUT_seal
touch /tmp/OUTPUT_seal
rm "$OUTPUT"

export NPROC=$(nproc)
NPROC=$(( ($NPROC + 1 )/ 2 ))

#	killall qemu-system-x86_64
if [ "$INTERACTIVE" = true ]; then
	qemu-system-x86_64 -smp $NPROC -kernel $KERNEL -initrd /tmp/initramfs.linux_amd64.cpio -hda $SEALHD -nographic -append "console=ttyS0"

else
	qemu-system-x86_64 -smp $NPROC -kernel $KERNEL -initrd /tmp/initramfs.linux_amd64.cpio  -hda $SEALHD -nographic -append "console=ttyS0" > $OUTPUT 2> /dev/null &
	PIDQEMU=$!
	
	echo waiting for qemu to finish
	while ! egrep '/.......#' $OUTPUT; do
		sleep 1
		echo -n .
	done
	
	#	killall qemu-system-x86_64
	
	kill $PIDQEMU
fi

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

