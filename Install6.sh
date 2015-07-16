#!/bin/sh 


###################
## 0. yuminstall ##
###################

echo "01 00 * * * root rdate -su time.bora.net | clock -w" >> /etc/crontab
/etc/rc.d/init.d/crond restart

## /* System Update */
yum -y update

## /* Remove Package */
yum -y remove apmd mkbootdisk dosfstools eject
yum -y remove gnome-vfs2 libgnomeui libgnome libbonoboui dogtail gnome-mount gnome-python2 gnome-python2-bonobo gnome-python2-gconf gnome-python2-gnomevfs
yum -y remove gnome-mime-data gnome-keyring libbonobo at-spi pyspi
yum -y remove libgnomecanvas gail
yum -y remove pcmciautils
yum -y remove firstboot-tui
yum -y remove hal kudzu smartmontools
yum -y remove ppp rp-pppoe
yum -y remove ypbind yp-tools
yum -y remove lftp irda-utils bluez-utils authconfig rhpl
yum -y remove dhcpv6_client dhclient dhcdbd
yum -y remove gtk2 GConf2 libglade2 bluez-gnome cairo-java frysk glib-java libgcj libgconf-java libgtk-java libnotify libwnck notification-daemon pygtk2
yum -y remove startup-notification pango xorg-x11-xfs chkfontpath cups cups-libs paps xorg-x11-fonts-base xorg-x11-server-Xvfb
yum -y remove xorg-x11-font-utils
yum -y remove system-config-network-tui NetworkManager
yum -y install pcre-devel

## /* Remove Directory */
rm -rf /var/log/cups

## /* Install Package */
yum -y install glibc gcc*

yum -y install libc-client libc-client-devel libjpeg* libpng* gd gd-devel gd-progs freetype* libxml2 libxml2-devel libmcrypt libmcrypt-devel db4-utils db4-devel gdbm* flex libart* lynx curl curl-devel libcurl-devel compat-libstdc* compat-glibc* lm_sensors lm_sensors-devel php-mbstring openssl* ncurses*
yum -y install net-snmp
yum -y install xinetd
yum -y install sysstat
yum -y install vim*
yum -y install rpm-devel elfutils-devel
yum -y install vsftpd
yum -y install sendmail-cf dovecot

rpm --nodeps -e mysql

#rpm -e system-config-httpd
#rpm -e httpd --noscripts

echo "alias vi='vim'" >> /root/.bashrc

source /root/.bashrc

## /* HISTORY */
echo "export HISTTIMEFORMAT=\"%F %T \"" >> /etc/profile.d/history.sh
source /etc/profile.d/history.sh

yum groupinstall "Development Tools"
yum groupinstall "Development Libraries"  


