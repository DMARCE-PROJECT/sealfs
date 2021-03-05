#!/usr/bin/sh

mkdir -p /mount/hd
mount /dev/sda /mount/hd

#This check functions can have -v added at the end to know more

checktest() {
	if test "$3" = "-v"; then
		if /var/tmp/verify /tmp/x /mount/hd/k1 /mount/hd/k2 $2; then
			echo $1 OK
		else
			echo $1 FAIL
		fi
		return
	fi
	if /var/tmp/verify /tmp/x /mount/hd/k1 /mount/hd/k2 $2 > /dev/null 2>&1; then
		echo $1 OK
	else
		echo $1 FAIL
	fi
}
checkfailtest() {	
	if test "$3" = "-v"; then
		if ! /var/tmp/verify /tmp/x /mount/hd/k1 /mount/hd/k2 $2; then
			echo $1 OK
		else
			echo $1 FAIL
		fi
		return
	fi
	if ! /var/tmp/verify /tmp/x /mount/hd/k1 /mount/hd/k2 $2 > /dev/null 2>&1; then
		echo $1 OK
	else
		echo $1 FAIL
	fi
}
resettest() {
	cp /mount/hd/.SEALFS.LOG /tmp/x
	cp /mount/hd/k2 /mount/hd/k1
}

echo STARTTEST
insmod /var/tmp/sealfs.ko
mkdir /tmp/x
mkdir /tmp/y
cp /mount/hd/.SEALFS.LOG /tmp/x

echo TEST 1 '----------------'
############################# 1 TEST
mount -o kpath=/mount/hd/k1 -t sealfs /tmp/x /tmp/y
echo -n 01234567 >> /tmp/y/zzz
echo -n 01234567 >> /tmp/y/zzz
echo -n 0DD4567 >> /tmp/y/zzz
mv /tmp/y/zzz /tmp/y/zzz.1
echo -n 01234567 >> /tmp/y/zzz
umount /tmp/y
/var/tmp/dump /tmp/x|grep entries

checktest TEST1 "-6 6"

# TO SEE simple test, change the above for:
#checktest TEST1 "-6 6" -v
#exit 0

echo TEST 2 '----------------'
############################# 2 TEST
resettest

mount -o kpath=/mount/hd/k1 -t sealfs /tmp/x /tmp/y
/var/tmp/test -s 2 17 2 /tmp/y
mv /tmp/y/file000  /tmp/y/file000.1
/var/tmp/test -s 128 17 1000 /tmp/y
mv /tmp/y/file000  /tmp/y/file000.2
/var/tmp/test -s 2 17 2 /tmp/y
mv /tmp/y/file000  /tmp/y/file000.3
umount /tmp/y

checktest TEST2

echo TEST 3 '----------------'
############################# 3 TEST simulate race condition
###LOG_HDR_SZ=16

echo with ratchet it stopped working, rethink
echo it was the test for race condition

echo TEST 4 '----------------' DISABLED, CPUID not present in qemu
############################# 4 TEST (new key so it does not fail)
##resettest

##mount -o kpath=/mount/hd/k1 -t sealfs /tmp/x /tmp/y
##/var/tmp/test -p 4 17 1000 /tmp/y
# CPUID is invalid opcode
##umount /tmp/y


echo TEST 5 '----------------'
############################# 5 TEST, should fail (new key so it does not fail because of that)
resettest

mount -o kpath=/mount/hd/k1 -t sealfs /tmp/x /tmp/y
#write twice on the same one, should fail
/var/tmp/test -s 2 17 2 /tmp/y
/var/tmp/test -s 60 17 1000 /tmp/y
umount /tmp/y

#SHOULD FAIL
checkfailtest TEST5

echo ENDTEST
