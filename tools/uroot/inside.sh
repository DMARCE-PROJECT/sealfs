#!/bbin/elvish

#change this path

echo STARTTEST
insmod /var/tmp/sealfs.ko
mkdir /tmp/x
mkdir /tmp/y
cp /var/tmp/.SEALFS.LOG /tmp/x
mount -o kpath=/var/tmp/k1 -t sealfs /tmp/x /tmp/y
echo -n 01234567 >> /tmp/y/zzz
echo -n 01234567 >> /tmp/y/zzz
mv /tmp/y/zzz /tmp/y/zzz.1
echo -n 01234567 >> /tmp/y/zzz
umount /tmp/y

/var/tmp/verify /tmp/x /var/tmp/k1 /var/tmp/k2

#second test

mount -o kpath=/var/tmp/k1 -t sealfs /tmp/x /tmp/y
/var/tmp/test -s 2 17 2 /tmp/y
mv /tmp/y/file000  /tmp/y/file000.1
/var/tmp/test -s 60 17 1000 /tmp/y
mv /tmp/y/file000  /tmp/y/file000.2
/var/tmp/test -s 2 17 2 /tmp/y
mv /tmp/y/file000  /tmp/y/file000.3

/var/tmp/verify /tmp/x /var/tmp/k1 /var/tmp/k2

#third test (new key so it does not fail)
cp /var/tmp/k2 /var/tmp/k1

mount -o kpath=/var/tmp/k1 -t sealfs /tmp/x /tmp/y
/var/tmp/test -s 2 17 2 /tmp/y
/var/tmp/test -s 60 17 1000 /tmp/y


echo SHOULDFAIL
# how do I make conditionals work in this shell????
/var/tmp/verify /tmp/x /var/tmp/k1 /var/tmp/k2



echo ENDTEST
