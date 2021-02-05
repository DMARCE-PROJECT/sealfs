#!/bin/bash

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

#make all sealfs
cd $GITSEAL
make all || exit 1
cp sealfs.ko /var/tmp
cd tools
make all || exit 1
cp prep dump verify test /var/tmp
ksize=$((1024 * 1024))
/var/tmp/prep /var/tmp/.SEALFS.LOG /var/tmp/k1 /var/tmp/k2 $ksize

echo building uroot

cp $GITSEAL/tools/uroot/inside.sh /var/tmp/
chmod +x /var/tmp/inside.sh
if ! u-root -uinitcmd=/var/tmp/inside.sh -files "/var/tmp/test" -files "/var/tmp/sealfs.ko" -files /var/tmp/k1 -files /var/tmp/k2 -files /var/tmp/.SEALFS.LOG -files /var/tmp/verify -files /var/tmp/prep -files /var/tmp/dump  -files /var/tmp/inside.sh> /tmp/$$_uroot 2>&1; then
	cat /tmp/$$_uroot 1>&2
	echo u-root error  1>&2
	exit 1
fi


#rm /var/tmp/inside.sh /var/tmp/sealfs.ko /var/tmp/k1 /var/tmp/k2 /var/tmp/.SEALFS.LOG /var/tmp/verify  /var/tmp/prep  /var/tmp/dump  /var/tmp/inside.sh /var/tmp/test


export OUTPUT=/tmp/OUTPUT_seal
touch /tmp/OUTPUT_seal
rm "$OUTPUT"

#	killall qemu-system-x86_64
if [ "$INTERACTIVE" = true ]; then
	qemu-system-x86_64 -kernel $KERNEL -initrd /tmp/initramfs.linux_amd64.cpio -nographic -append "console=ttyS0" 
	exit 0
fi

qemu-system-x86_64 -kernel $KERNEL -initrd /tmp/initramfs.linux_amd64.cpio -nographic -append "console=ttyS0" > $OUTPUT 2> /dev/null &
PIDQEMU=$!

echo waiting for qemu to finish
while ! egrep '\#' $OUTPUT|egrep '~/'; do
	sleep 1
	echo -n .
done

kill $PIDQEMU
sed -E -n '/STARTTEST/,/ENDTEST|\#/p' $OUTPUT
