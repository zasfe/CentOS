#!/bin/sh 


###################
## 0. yuminstall ##
###################

rdate -su time.bora.net | clock -w

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
##yum -y remove dhcpv6_client dhclient dhcdbd
yum -y remove gtk2 GConf2 libglade2 bluez-gnome cairo-java frysk glib-java libgcj libgconf-java libgtk-java libnotify libwnck notification-daemon pygtk2
yum -y remove startup-notification pango xorg-x11-xfs chkfontpath cups cups-libs paps xorg-x11-fonts-base xorg-x11-server-Xvfb
yum -y remove xorg-x11-font-utils
yum -y remove system-config-network-tui NetworkManager


## /* Remove Directory */
rm -rf /var/log/cups

## /* Install Package */
yum -y install glibc gcc*

yum -Y install gcc_x86_64 compat-gcc-32.x86_64 compat-gcc-32-c++.x86_64 compat-libgcc-296.i386 gcc.x86_64 gcc-c++.x86_64 libgcc.i386 vim* lynx openssl gdbm.x86_64 gdbm-devel.x86_64 gd.x86_64 gd-devel.x86_64
yum -y install pcre-devel
yum -y install libc-client libc-client-devel libjpeg* libpng* gd gd-devel gd-progs freetype* libxml2 libxml2-devel libmcrypt libmcrypt-devel db4-utils db4-devel gdbm* flex libart* lynx curl curl-devel compat-libstdc* compat-glibc* lm_sensors lm_sensors-devel php-mbstring ncurses*
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


##############
## 1. fstab ##
##############

sed -e "s;LABEL=/tmp              /tmp                    ext3    defaults        1 2;LABEL=/tmp              /tmp                    ext3    defaults,noexec,nodev,nosuid        1 2;g" < /etc/fstab > /etc/fstab.tmp
cp -f /etc/fstab.tmp /etc/fstab

rm -rf /var/tmp
ln -s /tmp /var/tmp


echo #!/bin/sh > /etc/cron.daily/logrotate
echo >> /etc/cron.daily/logrotate
echo TMPDIR=/var >> /etc/cron.daily/logrotate
echo export TMPDIR >> /etc/cron.daily/logrotate
echo /usr/sbin/logrotate /etc/logrotate.conf >> /etc/cron.daily/logrotate
echo EXITVALUE=$? >> /etc/cron.daily/logrotate
echo if [ $EXITVALUE != 0 ]; then >> /etc/cron.daily/logrotate
echo     /usr/bin/logger -t logrotate "ALERT exited abnormally with [$EXITVALUE]" >> /etc/cron.daily/logrotate
echo fi >> /etc/cron.daily/logrotate
echo exit 0 >> /etc/cron.daily/logrotate


#############
## 2. i18n ##
#############

cp -pa /etc/sysconfig/i18n /usr/local/src/
echo LANG="ko_KR.eucKR" > /etc/sysconfig/i18n
echo SUPPORTED="en_US.UTF-8:en_US:en:ko_KR.eucKR:ko_KR.UTF-8:ko_KR:ko" >> /etc/sysconfig/i18n
echo SYSFONT="latarcyrheb-sun16" >> /etc/sysconfig/i18n

sleep 3
source /etc/sysconfig/i18n


################
## 3. selinux ##
################

cp -pa /etc/selinux/config /usr/local/src/
echo SELINUX=disabled > /etc/selinux/config
echo SELINUXTYPE=targeted >> /etc/selinux/config



################
## 4. vsftpd  ##
################

cp -pa /etc/vsftpd/vsftpd.conf /usr/local/src/conf_file/vsftpd.conf
cat /etc/vsftpd/vsftpd.conf | sed -e "s/anonymous_enable=YES/anonymous_enable=NO/g" -e "s/#chroot_list_enable=YES/chroot_list_enable=YES/g" -e "s/tcp_wrappers=YES/tcp_wrappers=NO/g" > /usr/local/src/conf_file/vsftpd.conf.tmp

cp -f /usr/local/src/conf_file/vsftpd.conf.tmp /etc/vsftpd/vsftpd.conf

/etc/init.d/vsftpd restart

chkconfig --level 3 vsftpd on



##################
## 5. sendmail  ##
##################

cd /etc/mail

cp -pa /etc/mail/sendmail.mc /usr/local/src/conf_file/sendmail.mc

#cat /etc/mail/sendmail.mc | sed -e "s/dnl define(`SMART_HOST',`smtp.your.provider')/

#cp -f /usr/local/src/conf_file/sendmail.mc /etc/mail/ 
mv -f /etc/mail/sendmail.cf /etc/mail/sendmail.cf_old
make -C /etc/mail

/etc/rc.d/init.d/sendmail restart
/etc/rc.d/init.d/saslauthd start
chkconfig --level 3 saslauthd on

/etc/rc.d/init.d/dovecot start
chkconfig --level 3 dovecot on


################
## 6. sysctl  ##
################

cp -pa /etc/sysctl.conf /usr/local/src/conf_file/sysctl.conf

echo net.ipv4.ip_conntrack_max = 600000 >> /etc/sysctl.conf
echo net.ipv4.tcp_max_syn_backlog = 2048 >> /etc/sysctl.conf
echo net.ipv4.tcp_syncookies = 1 >> /etc/sysctl.conf
echo net.ipv4.conf.all.accept_redirects = 0 >> /etc/sysctl.conf
echo net.ipv4.icmp_echo_ignore_broadcasts = 1 >> /etc/sysctl.conf
echo net.ipv4.conf.all.accept_source_route = 0 >> /etc/sysctl.conf
echo net.ipv4.tcp_sack = 0 >> /etc/sysctl.conf
echo net.ipv4.tcp_timestamps = 0 >> /etc/sysctl.conf
echo net.ipv4.tcp_window_scaling = 0 >> /etc/sysctl.conf
echo net.ipv4.tcp_tw_reuse = 0 >> /etc/sysctl.conf
echo net.ipv4.tcp_tw_recycle = 0 >> /etc/sysctl.conf

sysctl -p /etc/sysctl.conf

cd /usr/bin; chmod 700 wget lynx curl lwp-* GET

chmod 700 /usr/bin/find
chmod 700 /bin/netstat
chmod 700 /usr/bin/lsattr
chmod 700 /usr/bin/which
chmod 700 /usr/bin/whereis
chmod 700 /usr/bin/locate
chmod 700 /usr/bin/wget
chmod 700 /usr/bin/curl
chmod 700 /usr/bin/GET
chmod 700 /usr/bin/lynx
chmod 700 /usr/bin/unzip




####################
## 7. daemon_set  ##
####################


chkconfig --level 3 acpid on
chkconfig --level 3 anacron off
#chkconfig --level 3 apmd off
chkconfig --level 3 atd off
chkconfig --level 3 cpuspeed off
chkconfig --level 3 gpm off
#chkconfig --level 3 haldaemon off
chkconfig --level 3 iptables off
#chkconfig --level 3 kudzu off
chkconfig --level 3 mdmonitor off
chkconfig --level 3 messagebus off
chkconfig --level 3 portmap off
chkconfig --level 3 rpcgssd off
chkconfig --level 3 rpcidmapd off
chkconfig --level 3 rpcsvcgssd off
#chkconfig --level 3 bluetooth off
#chkconfig --level 3 xfs off
chkconfig --level 3 avahi-daemon off
#chkconfig --level 3 firstboot off
#chkconfig --level 3 hidd off
chkconfig --level 3 irqbalance on
chkconfig --level 3 readahead_early off
#chkconfig --level 3 smartd off
#chkconfig --level 3 cups off
chkconfig --level 3 lm_sensors off
chkconfig --level 3 netfs off
chkconfig --level 3 nfslock off
chkconfig --level 3 auditd off
chkconfig --level 3 ip6tables off
chkconfig --level 3 restorecond off
chkconfig --level 3 pcscd off
chkconfig --level 3 mcstrans off
chkconfig --level 3 lvm2-monitor off
chkconfig --level 3 autofs off
chkconfig --level 3 rawdevices off
chkconfig --level 3 microcode_ctl off
chkconfig --level 3 xinetd off
chkconfig --level 3 yum-updatesd off


#####################
## 8. etc_setting  ##
#####################


cp -pa /etc/acpi/events/power.conf /usr/local/src/conf_file/power.conf

echo \#\!/bin/sh > /etc/acpi/actions/powerbutton.sh
echo >> /etc/acpi/actions/powerbutton.sh
echo ps awwux \> /root/ps.\`date +\%Y%m%d%H\`.txt >> /etc/acpi/actions/powerbutton.sh
echo pstree \> /root/pstree.\`date +\%Y\%m\%d\%H\` >> /etc/acpi/actions/powerbutton.sh
echo ps awwux \|grep nobody \> /root/nobody.\`date +\%Y\%m\%d\%H\`.txt >> /etc/acpi/actions/powerbutton.sh
echo free \> /root/memory.\`date +\%Y\%m\%d\%H\`.txt >> /etc/acpi/actions/powerbutton.sh
echo dmesg \> /root/dmesg.\`date +\%Y\%m\%d\%H\` >> /etc/acpi/actions/powerbutton.sh
echo netstat -na \> /root/netstat.\`date +\%Y\%m\%d\%H\`.txt >> /etc/acpi/actions/powerbutton.sh
echo /usr/bin/reboot -n >> /etc/acpi/actions/powerbutton.sh

cp -pa /etc/acpi/actions/powerbutton.sh /usr/local/src/powerbutton.sh

cat /etc/acpi/events/power.conf | sed -e "s/aa/action=\/etc\/acpi\/actions\/powerbutton.sh/g" > /usr/local/src/power.conf.new
cp -f /usr/local/src/power.conf.new /etc/acpi/events/power.conf


####################
## 9. Yum Update  ##
####################

yum -y update


#!/bin/bash
#
## /* Permission Setting */
chmod 700 /bin/dd
chmod 755 /bin/df
chmod 700 /bin/dmesg
chmod 700 /bin/mail
chmod 700 /bin/mount
chmod 700 /bin/mknod
chmod 700 /bin/netstat
#chmod 700 /bin/ping
#chmod 700 /bin/ping6
chmod 755 /bin/ps
chmod 700 /bin/sync
chmod 700 /bin/umount
chmod 755 /bin/uname
chmod 700 /bin/traceroute

chmod 700 /usr/bin/c++
chmod 700 /usr/bin/chage
chmod 700 /usr/bin/chfn
chmod 700 /usr/bin/curl
chmod 755 /usr/bin/find
chmod 700 /usr/bin/finger
chmod 700 /usr/bin/g++
chmod 700 /usr/bin/gcc
chmod 700 /usr/bin/install
chmod 700 /usr/bin/iostat
chmod 700 /usr/bin/last
chmod 700 /usr/bin/lastlog
chmod 700 /usr/bin/man
chmod 700 /usr/bin/make
chmod 700 /usr/bin/nslookup
chmod 700 /usr/bin/pstree
chmod 700 /usr/bin/rlog
chmod 700 /usr/bin/rlogin
chmod 700 /usr/bin/top
chmod 700 /usr/bin/uptime
chmod 700 /usr/bin/w
chmod 700 /usr/bin/wall
chmod 700 /usr/bin/wget
chmod 700 /usr/bin/whereis
chmod 700 /usr/bin/which
chmod 700 /usr/bin/who
chmod 700 /usr/bin/write

chmod 700 /usr/sbin/edquota
chmod 700 /usr/sbin/glibc_post_upgrade.i686
chmod 700 /usr/sbin/groupadd
chmod 700 /usr/sbin/groupdel
chmod 700 /usr/sbin/grpconv
chmod 700 /usr/sbin/grpunconv
chmod 700 /usr/sbin/pwconv
chmod 700 /usr/sbin/pwunconv
chmod 700 /usr/sbin/useradd
chmod 700 /usr/sbin/userdel
