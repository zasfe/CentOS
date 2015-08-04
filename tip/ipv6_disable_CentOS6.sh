echo "install ipv6 /bin/true" > /etc/modprobe.d/ipv6_disabled.conf

echo "NETWORKING_IPV6=no" >> /etc/sysconfig/network
echo "IPV6INIT=no" >> /etc/sysconfig/network
