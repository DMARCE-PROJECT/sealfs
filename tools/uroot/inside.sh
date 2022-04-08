#!/var/tmp/sh

mkdir -p /mount/hd
mount /dev/sda /mount/hd

#This check functions can have -v added at the end to know more

checktest() {
	sync; sync
	if test "$3" = "-v"; then
		if /var/tmp/verify /tmp/x /mount/hd/k1 /mount/hd/k2 $2; then
			echo $1 OK
		else
			echo $1 FAIL
		fi
		return
	fi
	sync; sync
	if /var/tmp/verify /tmp/x /mount/hd/k1 /mount/hd/k2 $2 > /dev/null 2>&1; then
		echo $1 OK
	else
		echo $1 FAIL
	fi
}
checkfailtest() {	
	if test "$3" = "-v"; then
		sync; sync
		if ! /var/tmp/verify /tmp/x /mount/hd/k1 /mount/hd/k2 $2; then
			echo $1 OK
		else
			echo $1 FAIL
		fi
		return
	fi
	sync; sync
	if ! /var/tmp/verify /tmp/x /mount/hd/k1 /mount/hd/k2 $2 > /dev/null 2>&1; then
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
	echo TEST 1 '-------basic test---------'
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
	echo TEST 2 '-----basic test-----------'
	############################# 2 TEST
	resettest
	
	mount -o kpath=/mount/hd/k1 -t sealfs /tmp/x /tmp/y
	/var/tmp/test -s 2 17 2 /tmp/y
	mv /tmp/y/file000  /tmp/y/file000.1
	/var/tmp/test -s 128 17 1000 /tmp/y
#to debug, can take down until unmount
	mv /tmp/y/file000  /tmp/y/file000.2
	/var/tmp/test -s 2 17 2 /tmp/y
	mv /tmp/y/file000  /tmp/y/file000.3

	umount /tmp/y
	
	checktest TEST2
}

test3(){		
	echo TEST 3 '------check heap, verify in different orders----------'
	############################# 3 TEST simulate race condition
	
	resettest
	
	mount -o nratchet=2,kpath=/mount/hd/k1 -t sealfs /tmp/x /tmp/y
	/var/tmp/test -s 2 17 2 /tmp/y
	
	umount /tmp/y
	
	#sizeof(sealfs_logfile_header)
	HDRSZ=8
	ENTRYSZ=72
	dd if=/tmp/x/.SEALFS.LOG bs=$HDRSZ count=1 of=/tmp/hdr >/dev/null 2>&1

	#with if=file, dd has a bug with skip ??
	dd bs=$HDRSZ skip=1 of=/tmp/body < /tmp/x/.SEALFS.LOG >/dev/null 2>&1
	dd bs=$ENTRYSZ count=3 of=/tmp/start < /tmp/body >/dev/null 2>&1
	dd bs=$ENTRYSZ count=3 skip=3 of=/tmp/medium < /tmp/body >/dev/null 2>&1
	#without count this last one has trailing zeros WTF dd?
	dd bs=$ENTRYSZ count=6 skip=6 of=/tmp/end < /tmp/body >/dev/null 2>&1
	
	DUMPLOGS=no
	if test "$DUMPLOGS" = yes; then
		echo LOG "==="
		/var/tmp/xxd /tmp/x/.SEALFS.LOG | /var/tmp/sed 12q
		echo HDR "==="
		/var/tmp/xxd /tmp/hdr | /var/tmp/sed 1q
		echo BODY "==="
		/var/tmp/xxd /tmp/body | /var/tmp/sed 12q
		echo START "==="
		/var/tmp/xxd /tmp/start | /var/tmp/sed 4q
		echo MEDIUM "==="
		/var/tmp/xxd /tmp/medium | /var/tmp/sed 4q
		echo END "==="
		/var/tmp/xxd /tmp/end | /var/tmp/sed 4q
	fi

	echo hdr start medium end
	cat /tmp/hdr /tmp/start /tmp/medium /tmp/end > /tmp/x/.SEALFS.LOG
	checktest TEST3hsme -Dh
	
	echo hdr medium start end
	cat /tmp/hdr /tmp/medium /tmp/start /tmp/end > /tmp/x/.SEALFS.LOG
	checktest TEST3hmse -Dh
	#/var/tmp/dump /tmp/x

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
	echo TEST 5 '-------nratchet 32, -p ---------'
	############################# 4 TEST (new key so it does not fail)
	resettest
	
	mount -o nratchet=32,kpath=/mount/hd/k1 -t sealfs /tmp/x /tmp/y
	/var/tmp/test -p 4 17 1000 /tmp/y
	# CPUID is invalid opcode
	umount /tmp/y
	checktest TEST4
}

test5() {	
	echo TEST 5 '-------break key, OK means failed verification---------'
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
	echo TEST 6 '------remount----------'
	resettest
	mount -o nratchet=17,kpath=/mount/hd/k1 -t sealfs /tmp/x /tmp/y
	echo -n 01234567 >> /tmp/y/zzz
	echo -n 01234567 >> /tmp/y/zzz
	echo -n 0DD4567 >> /tmp/y/zzz
	mv /tmp/y/zzz /tmp/y/zzz.1
	echo -n 01234567 >> /tmp/y/zzz
	umount /tmp/y
	checktest TEST6
	sync; sync
	#remount
	mount -o nratchet=17,kpath=/mount/hd/k1 -t sealfs /tmp/x /tmp/y
	echo -n 0DD4567 >> /tmp/y/zzz
	mv /tmp/y/zzz.1 /tmp/y/zzz.2
	mv /tmp/y/zzz /tmp/y/zzz.1
	umount /tmp/y
	/var/tmp/dump /tmp/x|grep entries
	checktest TEST6
}
test7(){	
	echo TEST 7 '------default nratchet and 1 nratchet----------'
	############################# 7 TEST
	resettest
	
	mount -o kpath=/mount/hd/k1 -t sealfs /tmp/x /tmp/y
	/var/tmp/test -s 32 1 1 /tmp/y
	umount /tmp/y
	
	checktest TEST7A

	resettest
	
	mount -o nratchet=1,kpath=/mount/hd/k1 -t sealfs /tmp/x /tmp/y
	/var/tmp/test -s 32 1 1 /tmp/y
	umount /tmp/y
	
	checktest TEST7B
}

test8(){	
	echo TEST 8 '----------------'
	############################# 8 TEST
	resettest
	
	mount -o kpath=/mount/hd/k1 -t sealfs /tmp/x /tmp/y
	/var/tmp/test -s 1 20000 1 /tmp/y
	umount /tmp/y
	
	checktest TEST8
}

checktestOffset() {
	sync; sync
	if test "$3" = "-v"; then
		if /var/tmp/verify /tmp/x /mount/hd/k1 /mount/hd/k2 -i 6 220000 2240000 $2; then
			echo $1 OK
		else
			echo $1 FAIL
		fi
		return
	fi
	sync; sync
	if /var/tmp/verify /tmp/x /mount/hd/k1 /mount/hd/k2  -i 6 220000 2240000 $2 > /dev/null 2>&1; then
		echo $1 OK
	else
		echo $1 FAIL
	fi
}

test9(){	
	echo TEST 9 '-------verification with offset ---------'
	############################# 8 TEST
	resettest
	
	mount -o kpath=/mount/hd/k1 -t sealfs /tmp/x /tmp/y
	/var/tmp/test -s 1 20000 1 /tmp/y
	umount /tmp/y
	checktestOffset TEST9
}




#the first one does not reset
mandatorytest1
test2
test3
test4
test5
test6
test7
test8
test9


echo ENDTEST
