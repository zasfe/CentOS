#!/bin/sh

#
# Disable IPv6
#
# http://www.itzgeek.com/how-tos/mini-howtos/disable-ipv6-on-centos-6-rhel-6.html
# https://mbrownnyc.wordpress.com/2012/09/18/completely-disable-ipv6-in-centos6/

echo "install ipv6 /bin/true" > /etc/modprobe.d/ipv6_disabled.conf

echo "NETWORKING_IPV6=no" >> /etc/sysconfig/network
echo "IPV6INIT=no" >> /etc/sysconfig/network
