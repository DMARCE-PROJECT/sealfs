#!/bbin/elvish

#change this path

insmod /var/tmp/sealfs.ko
mkdir /tmp/x
mkdir /tmp/y
cp /var/tmp/.SEALFS.LOG /tmp/x
mount -o kpath=/var/tmp/k1 -t sealfs /tmp/x /tmp/y
echo -n 01234567 >> /tmp/y/zzz
echo -n 01234567 >> /tmp/y/zzz
umount /tmp/y

/var/tmp/verify /tmp/x /var/tmp/k1 /var/tmp/k2
