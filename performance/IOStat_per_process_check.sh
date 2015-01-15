#!/bin/sh

# CentOS 5.x - running OK

wget http://aspersa.googlecode.com/svn/trunk/iodump
echo 1 > /proc/sys/vm/block_dump
while true; do sleep 1; dmesg -c; done | perl iodump
