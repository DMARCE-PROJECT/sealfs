#!/bin/sh

#configure this
UROOT_PATH=$HOME/src/go/src/github.com/u-root/u-root

usage(){
        echo "usage: runtest [-g] [-i]" 1>&2;
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

PATHuroot=$(which u-root)
PATHqemu=$(which qemu-system-x86_64)
if ! [ -d $UROOT_PATH ] || ! [ -x $PATHuroot ] || ! [ -x $PATHqemu ]; then
	echo '#' make sure you run: 1>&2
	echo '	sudo apt install qemu-system qemu-system-x86' 1>&2
	echo '	sudo apt install qemu-kvm libvirt-clients libvirt-daemon-system bridge-utils virt-manager' 1>&2
	echo "	mkdir -p $UROOT_PATH;"  1>&2
	echo "	cd $UROOT_PATH; git clone https://github.com/u-root/u-root; "  1>&2
	echo '		cd u-root; go install' 1>&2
	exit 1
fi

#prepare a kernel in tmp
export GITSEAL=$(git rev-parse --show-toplevel)
sudo cp /boot/vmlinuz-$(uname -r) /tmp

export KERNEL=/tmp/vmlinuz-$(uname -r)
sudo chown $USER $KERNEL
chmod 777 $KERNEL

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
sudo cp /var/tmp/sealfs.ko /tmp/hd
sudo /var/tmp/prep /tmp/hd/.SEALFS.LOG /tmp/hd/k1 /tmp/hd/k2 $ksize
sudo umount $SEALHD


cp $GITSEAL/tools/uroot/inside.sh /var/tmp/
chmod +x /var/tmp/inside.sh
if ! (cd $UROOT_PATH; u-root -uroot-source $UROOT_PATH -uinitcmd=/var/tmp/inside.sh $CMDSINSIDE -files /var/tmp/inside.sh cmds/core/* ) > /tmp/$$_uroot 2>&1; then
	cat /tmp/$$_uroot 1>&2
	echo u-root error  1>&2
	exit 1
fi


rm -f /var/tmp/inside.sh /var/tmp/sealfs.ko /var/tmp/inside.sh
CMDS=`echo $CMDSINSIDE| sed 's/-files //g'`
rm $CMDS


export OUTPUT=/tmp/OUTPUT_seal
touch /tmp/OUTPUT_seal
rm "$OUTPUT"

export NPROC=$(nproc)
NPROC=$(( ($NPROC + 1 )/ 2 ))

#	killall qemu-system-x86_64
if [ "$INTERACTIVE" = true ]; then
	qemu-system-x86_64 -m 4G -smp $NPROC -kernel $KERNEL -initrd /tmp/initramfs.linux_amd64.cpio -drive format=raw,file="$SEALHD",index=0,media=disk -nographic -append "console=ttyS0"

else
	qemu-system-x86_64 -m 4G -smp $NPROC -kernel $KERNEL -initrd /tmp/initramfs.linux_amd64.cpio  -drive format=raw,file="$SEALHD",index=0,media=disk -nographic -append "console=ttyS0" > $OUTPUT 2> /dev/null &
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

