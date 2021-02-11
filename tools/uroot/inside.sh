#!/bbin/elvish

mkdir -p /mount/hd
mount /dev/sda /mount/hd

echo STARTTEST

echo TEST 1 '----------------'
############################# 1 TEST
insmod /var/tmp/sealfs.ko
mkdir /tmp/x
mkdir /tmp/y
cp /mount/hd/.SEALFS.LOG /tmp/x
mount -o kpath=/mount/hd/k1 -t sealfs /tmp/x /tmp/y
echo -n 01234567 >> /tmp/y/zzz
echo -n 01234567 >> /tmp/y/zzz
mv /tmp/y/zzz /tmp/y/zzz.1
echo -n 01234567 >> /tmp/y/zzz
umount /tmp/y

/var/tmp/verify /tmp/x /mount/hd/k1 /mount/hd/k2

echo TEST 2 '----------------'
############################# 2 TEST
cp /mount/hd/k2 /mount/hd/k1
cp /mount/hd/.SEALFS.LOG /tmp/x
mount -o kpath=/mount/hd/k1 -t sealfs /tmp/x /tmp/y
/var/tmp/test -s 2 17 2 /tmp/y
mv /tmp/y/file000  /tmp/y/file000.1
/var/tmp/test -s 128 17 1000 /tmp/y
mv /tmp/y/file000  /tmp/y/file000.2
/var/tmp/test -s 2 17 2 /tmp/y
mv /tmp/y/file000  /tmp/y/file000.3
umount /tmp/y
/var/tmp/verify /tmp/x /mount/hd/k1 /mount/hd/k2

echo TEST 3 '----------------'
############################# 3 TEST simulate race condition
###LOG_HDR_SZ=16


cp /mount/hd/k2 /mount/hd/k1
cp /mount/hd/.SEALFS.LOG /tmp/x
mount -o kpath=/mount/hd/k1 -t sealfs /tmp/x /tmp/y
/var/tmp/test -s 2 17 2 /tmp/y

umount /tmp/y

dd if=/tmp/x/.SEALFS.LOG bs=16 count=1 of=/tmp/hdr
#with if=file, skip bug
dd bs=16 skip=1 of=/tmp/body < /tmp/x/.SEALFS.LOG
dd bs=64 count=3 of=/tmp/start < /tmp/body
dd bs=64 count=3 skip=3 of=/tmp/medium < /tmp/body
#without count this last one has trailing zeros WTF dd?
dd bs=64 count=5 skip=6 of=/tmp/end < /tmp/body

echo hdr start medium end
cat /tmp/hdr /tmp/start /tmp/medium /tmp/end > /tmp/x/.SEALFS.LOG
/var/tmp/verify /tmp/x /mount/hd/k1 /mount/hd/k2 -h 

echo hdr medium start end
cat /tmp/hdr /tmp/medium /tmp/start /tmp/end > /tmp/x/.SEALFS.LOG
/var/tmp/verify /tmp/x /mount/hd/k1 /mount/hd/k2 -h 

echo hdr medium end start 
cat /tmp/hdr /tmp/medium /tmp/end /tmp/start  > /tmp/x/.SEALFS.LOG
/var/tmp/verify /tmp/x /mount/hd/k1 /mount/hd/k2 -h

echo hdr end start medium 
cat /tmp/hdr  /tmp/end /tmp/start /tmp/medium > /tmp/x/.SEALFS.LOG
/var/tmp/verify /tmp/x /mount/hd/k1 /mount/hd/k2 -h

echo SHOULD FAIL
echo hdr medium end
cat /tmp/hdr /tmp/medium /tmp/end > /tmp/x/.SEALFS.LOG
/var/tmp/verify /tmp/x /mount/hd/k1 /mount/hd/k2 -h

echo SHOULD FAIL
echo hdr medium start
cat /tmp/hdr /tmp/medium /tmp/start > /tmp/x/.SEALFS.LOG
/var/tmp/verify /tmp/x /mount/hd/k1 /mount/hd/k2 -h

##echo TEST 4 '----------------'
############################# 4 TEST (new key so it does not fail)
##cp /mount/hd/.SEALFS.LOG /tmp/x
##cp /mount/hd/k2 /mount/hd/k1

##mount -o kpath=/mount/hd/k1 -t sealfs /tmp/x /tmp/y
##/var/tmp/test -p 4 17 1000 /tmp/y
# CPUID is invalid opcode
##umount /tmp/y


echo TEST 5 '----------------'
############################# 5 TEST, should fail (new key so it does not fail because of that)
cp /mount/hd/.SEALFS.LOG /tmp/x
cp /mount/hd/k2 /mount/hd/k1

mount -o kpath=/mount/hd/k1 -t sealfs /tmp/x /tmp/y
#write twice on the same one, should fail
/var/tmp/test -s 2 17 2 /tmp/y
/var/tmp/test -s 60 17 1000 /tmp/y
umount /tmp/y

echo SHOULD FAIL
# how do I make conditionals work in this shell????
/var/tmp/verify /tmp/x /mount/hd/k1 /mount/hd/k2

echo ENDTEST
