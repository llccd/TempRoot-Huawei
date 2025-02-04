#!/system/bin/sh
mount -o remount,suid,dev /data
mount -o remount,rw /
chmod 751 /sbin
cp /data/data/com.termux/files/home/bin/sud/su /sbin
mount -o remount,ro /