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
checktest17() {
	if test "$3" = "-v"; then
		if /var/tmp/verify /tmp/x /mount/hd/k1 /mount/hd/k2 -r 17 $2; then
			echo $1 OK
		else
			echo $1 FAIL
		fi
		return
	fi
	if /var/tmp/verify /tmp/x /mount/hd/k1 /mount/hd/k2 -r 17 $2 > /dev/null 2>&1; then
		echo $1 OK
	else
		echo $1 FAIL
	fi
}
resettest() {
	rm -r /tmp/x/*
	cp /mount/hd/.SEALFS.LOG /tmp/x
	cp /mount/hd/k2 /mount/hd/k1
}

echo STARTTEST
insmod /var/tmp/sealfs.ko
mkdir /tmp/x
mkdir /tmp/y
cp /mount/hd/.SEALFS.LOG /tmp/x

mandatorytest1(){	
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
}

test2(){	
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
}

test3(){		
	echo TEST 3 '----------------'
	############################# 3 TEST simulate race condition
	
	resettest
	
	mount -o kpath=/mount/hd/k1 -t sealfs /tmp/x /tmp/y
	/var/tmp/test -s 2 17 2 /tmp/y
	
	umount /tmp/y
	
	HDRSZ=8
	ENTRYSZ=72
	dd if=/tmp/x/.SEALFS.LOG bs=$HDRSZ count=1 of=/tmp/hdr >/dev/null 2>&1
	
	#with if=file, dd has a bug with skip ??
	dd bs=$HDRSZ skip=1 of=/tmp/body < /tmp/x/.SEALFS.LOG >/dev/null 2>&1
	dd bs=$ENTRYSZ count=3 of=/tmp/start < /tmp/body >/dev/null 2>&1
	dd bs=$ENTRYSZ count=3 skip=3 of=/tmp/medium < /tmp/body >/dev/null 2>&1
	#without count this last one has trailing zeros WTF dd?
	dd bs=$ENTRYSZ count=6 skip=6 of=/tmp/end < /tmp/body >/dev/null 2>&1
	
	echo hdr start medium end
	cat /tmp/hdr /tmp/start /tmp/medium /tmp/end > /tmp/x/.SEALFS.LOG
	checktest TEST3hsme -Dh
	
	echo hdr medium start end
	cat /tmp/hdr /tmp/medium /tmp/start /tmp/end > /tmp/x/.SEALFS.LOG
	checktest TEST3hmse -Dh
	/var/tmp/dump /tmp/x

	echo hdr medium end start 
	cat /tmp/hdr /tmp/medium /tmp/end /tmp/start  > /tmp/x/.SEALFS.LOG
	checktest TEST3hmes -Dh

	echo hdr end start medium 
	cat /tmp/hdr  /tmp/end /tmp/start /tmp/medium > /tmp/x/.SEALFS.LOG
	checktest TEST3hesm -Dh
	
	#SHOULD FAIL
	echo hdr medium end
	cat /tmp/hdr /tmp/medium /tmp/end > /tmp/x/.SEALFS.LOG
	checkfailtest TEST3hme -Dh
	
	echo hdr medium start
	cat /tmp/hdr /tmp/medium /tmp/start > /tmp/x/.SEALFS.LOG
	checktest TEST3hms -Dh
}

test4(){
	echo TEST 4 '----------------' DISABLED, CPUID not present in qemu
	############################# 4 TEST (new key so it does not fail)
	##resettest
	
	##mount -o kpath=/mount/hd/k1 -t sealfs /tmp/x /tmp/y
	##/var/tmp/test -p 4 17 1000 /tmp/y
	# CPUID is invalid opcode
	##umount /tmp/y
}

test5() {	
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
}

test6(){	
	#####umount test
	############################# 6 TEST
	echo TEST 6 '----------------'
	resettest
	mount -o nratchet=17,kpath=/mount/hd/k1 -t sealfs /tmp/x /tmp/y
	echo -n 01234567 >> /tmp/y/zzz
	echo -n 01234567 >> /tmp/y/zzz
	echo -n 0DD4567 >> /tmp/y/zzz
	mv /tmp/y/zzz /tmp/y/zzz.1
	echo -n 01234567 >> /tmp/y/zzz
	umount /tmp/y
	mount -o nratchet=17,kpath=/mount/hd/k1 -t sealfs /tmp/x /tmp/y
	echo -n 0DD4567 >> /tmp/y/zzz
	mv /tmp/y/zzz.1 /tmp/y/zzz.2
	mv /tmp/y/zzz /tmp/y/zzz.1
	umount /tmp/y
	/var/tmp/dump /tmp/x|grep entries
	checktest17 TEST6
}

#the fist one does not reset
mandatorytest1
test2
test3
exit 0
test4
test5
test6


echo ENDTEST
