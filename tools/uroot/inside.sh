#!/var/tmp/sh

usage(){
        echo "usage: inside.sh [-o] " 1>&2;
        exit 1
}

OUTSIDE=false
if [ "$1" = '-o' ]; then
        OUTSIDE=true
	shift
fi

mkdir -p /mount/hd
if test "$OUTSIDE" = true; then
	if lsmod|grep sealfs > /dev/null 2>&1 ; then
		 rmmod sealfs
	fi
	export SEALHD=/var/tmp/sealhd
	mount -o loop,user $SEALHD /mount/hd || exit 1
else
	mount /dev/sda /mount/hd
fi

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

insmod /mount/hd/sealfs.ko
rm /mount/hd/sealfs.ko	##once passed we don't want it to interfere with the test
rm -r /tmp/x
rm -r /tmp/y
mkdir -p /tmp/x
mkdir -p /tmp/y
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
	/var/tmp/test -s 2 17 2 /tmp/y > /dev/null
	mv /tmp/y/file000  /tmp/y/file000.1
	/var/tmp/test -s 128 17 1000 /tmp/y > /dev/null
#to debug, can take down until unmount
	mv /tmp/y/file000  /tmp/y/file000.2
	/var/tmp/test -s 2 17 2 /tmp/y > /dev/null
	mv /tmp/y/file000  /tmp/y/file000.3

	umount /tmp/y
	
	checktest TEST2
}

test3(){		
	echo TEST 3 '------check heap, verify in different orders----------'
	############################# 3 TEST simulate race condition
	
	resettest
	
	mount -o nratchet=2,kpath=/mount/hd/k1 -t sealfs /tmp/x /tmp/y
	/var/tmp/test -s 2 17 2 /tmp/y > /dev/null
	
	umount /tmp/y

	#sizeof(sealfs_logfile_header)
	HDRSZ=8
	ENTRYSZ=72

	DD=dd
	if test "$OUTSIDE" = true; then
		chmod a+rw /tmp/x/.SEALFS.LOG
		dd if=/tmp/x/.SEALFS.LOG bs=$HDRSZ count=1 of=/tmp/hdr >/dev/null 2>&1
	
		dd bs=$HDRSZ skip=1 of=/tmp/body < /tmp/x/.SEALFS.LOG >/dev/null 2>&1
		dd bs=$ENTRYSZ count=3 of=/tmp/start < /tmp/body >/dev/null 2>&1
		dd bs=$ENTRYSZ count=3 skip=3 of=/tmp/medium < /tmp/body >/dev/null 2>&1
		dd bs=$ENTRYSZ skip=6 of=/tmp/end < /tmp/body >/dev/null 2>&1
	else	
		dd -if /tmp/x/.SEALFS.LOG -bs $HDRSZ -count 1 -of /tmp/hdr >/dev/null 2>&1
	
		dd -bs $HDRSZ -skip 1 -of /tmp/body < /tmp/x/.SEALFS.LOG >/dev/null 2>&1
		dd -bs $ENTRYSZ -count 3 -of /tmp/start < /tmp/body >/dev/null 2>&1
		dd -bs $ENTRYSZ -count 3 -skip 3 -of /tmp/medium < /tmp/body >/dev/null 2>&1
		dd -bs $ENTRYSZ -skip 6 -of /tmp/end < /tmp/body >/dev/null 2>&1
	fi
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
	checktest TEST3hmse -Dh #-v
	#/var/tmp/dump /tmp/x |/var/tmp/sed 10q

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
	
	#SHOULD FAIL
	echo hdr medium start
	cat /tmp/hdr /tmp/medium /tmp/start > /tmp/x/.SEALFS.LOG
	checkfailtest TEST3hms -Dh
}

test4(){
	echo TEST 4 '-------nratchet 32, -p ---------'
	############################# 4 TEST (new key so it does not fail)
	resettest
	
	mount -o nratchet=32,kpath=/mount/hd/k1 -t sealfs /tmp/x /tmp/y
	/var/tmp/test -p 4 17 1000 /tmp/y >/dev/null 
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
	/var/tmp/test -s 2 17 2 /tmp/y >/dev/null 
	/var/tmp/test -s 60 17 1000 /tmp/y >/dev/null 
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
	checktest TEST6A
	sync; sync
	#remount
	mount -o nratchet=17,kpath=/mount/hd/k1 -t sealfs /tmp/x /tmp/y
	echo -n 0DD4567 >> /tmp/y/zzz
	mv /tmp/y/zzz.1 /tmp/y/zzz.2
	mv /tmp/y/zzz /tmp/y/zzz.1
	umount /tmp/y
	/var/tmp/dump /tmp/x|grep entries
	checktest TEST6B
}
test7(){	
	echo TEST 7 '------default nratchet and 1 nratchet----------'
	############################# 7 TEST
	resettest
	
	mount -o kpath=/mount/hd/k1 -t sealfs /tmp/x /tmp/y
	/var/tmp/test -s 32 1 1 /tmp/y >/dev/null 
	umount /tmp/y
	
	checktest TEST7A

	resettest
	
	mount -o nratchet=1,kpath=/mount/hd/k1 -t sealfs /tmp/x /tmp/y
	/var/tmp/test -s 32 1 1 /tmp/y >/dev/null 
	umount /tmp/y
	
	checktest TEST7B
}

test8(){	
	echo TEST 8 '----------------'
	############################# 8 TEST
	resettest
	
	mount -o kpath=/mount/hd/k1 -t sealfs /tmp/x /tmp/y
	/var/tmp/test -s 1 20000 1 /tmp/y >/dev/null 
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
	############################# 9 TEST
	resettest
	
	mount -o kpath=/mount/hd/k1 -t sealfs /tmp/x /tmp/y
	/var/tmp/test -s 1 20000 1 /tmp/y >/dev/null 
	umount /tmp/y
	checktestOffset TEST9
}


test10(){	
	echo TEST 10 '-----try to create link, not allowed-----------'
	############################# 10 TEST
	resettest
	
	mount -o kpath=/mount/hd/k1 -t sealfs /tmp/x /tmp/y
	/var/tmp/test -s 2 17 2 /tmp/y > /dev/null
	RES=OK
	if ln -s /tmp/y/file000  /tmp/y/file000.1 2>/dev/null; then
		RES=FAILED
	fi
	umount /tmp/y
	echo TEST10A $RES
	checktest TEST10B
}

test11(){	
	echo TEST 11 '-----follow bad link-----------'
	############################# 11 TEST
	resettest
	NAME=aaa
	seq 1 10 > /tmp/x/$NAME
	ln -s /tmp/x/$NAME /tmp/x/link
	rm /tmp/x/$NAME
	mount -o kpath=/mount/hd/k1 -t sealfs /tmp/x /tmp/y
	seq 1 10 >> /tmp/y/equal
	RES=OK
	for i in `seq 1 10`; do
		if cmp /tmp/y/link /tmp/y/equal 2>/dev/null; then
			RES=FAILED
			break
		fi
	done
	umount /tmp/y
	echo TEST11A $RES
	checktest TEST11B
}

test12(){	
	echo TEST 12 '-----try to remove file inside sealfs-----------'
	############################# 12 TEST
	resettest
	
	mount -o kpath=/mount/hd/k1 -t sealfs /tmp/x /tmp/y
	/var/tmp/test -s 2 17 2 /tmp/y > /dev/null
	RES=OK
	if rm /tmp/y/file000 2>/dev/null; then
		RES=FAILED
		break
	fi
	umount /tmp/y
	echo TEST12 $RES
}

test13(){	
	echo TEST 13 '-----remove file under sealfs-----------'
	############################# 13 TEST
	resettest
	
	mount -o kpath=/mount/hd/k1 -t sealfs /tmp/x /tmp/y
	/var/tmp/test -s 2 17 2 /tmp/y > /dev/null
	umount /tmp/y
	
	rm /tmp/x/file000 
	#SHOULD FAIL
	checkfailtest TEST13
}

test14(){	
	echo TEST 14 '-----follow good link-----------'
	############################# 14 TEST
	resettest
	NAME=aaa
	seq 1 10 > /tmp/x/$NAME
	ln -s /tmp/x/$NAME /tmp/x/link
	mount -o kpath=/mount/hd/k1 -t sealfs /tmp/x /tmp/y
	seq 1 10 >> /tmp/y/equal
	RES=OK
	for i in `seq 1 100`; do
		if ! cmp /tmp/y/link /tmp/y/equal 2>/dev/null; then
			ls -la /tmp/x
			ls -la /tmp/y
			echo '-#0 link'
			cat /tmp/y/link
			echo '-#1 equal'
			cat /tmp/y/equal
			RES=FAILED
			break
		fi
	done
	umount /tmp/y
	rm /tmp/x/link
	echo TEST14A $RES
	checktest TEST14B
}

getout() {
	umount /mount/hd
	exit $1
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
test10
test11
test12
test13
test14

echo ENDTEST

getout 0