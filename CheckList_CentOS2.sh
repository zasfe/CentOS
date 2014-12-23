#!/bin/sh

LANG=C
export LANG

alias ls=ls

CREATE_FILE=`hostname`"_before_ini_".txt

echo > $CREATE_FILE 2>&1

if [ -d /cas/backup ]
 then
   echo "  " >> $CREATE_FILE 2>&1
 else
echo "##################################   BACKUP START !!!   ################################################"
mkdir /cas/backup
mkdir /cas/backup/dev/
mkdir /cas/backup/hidden/
mkdir /cas/backup/etc
mkdir /cas/backup/etc/default/

echo "######################################  1.계정관리  ####################################################"

cp -p /etc/passwd /cas/backup/etc/

cp -p /etc/group /cas/backup/etc/

cp -p /etc/login.defs /cas/backup/etc/

mkdir -p /cas/backup/etc/pam.d/
cp -p /etc/pam.d/su /cas/backup/etc/pam.d/

cp -p /etc/shadow /cas/backup/etc/


cp -p /etc/profile /cas/backup/etc/


mkdir -p /cas/backup/sbin/
mkdir -p /cas/backup/usr/bin/
mkdir -p /cas/backup/usr/sbin/

cp -p /sbin/dump /cas/backup/sbin/
cp -p /sbin/showfdmn /cas/backup/sbin/
cp -p /sbin/showfsets /cas/backup/sbin/
cp -p /usr/bin/at /cas/backup/usr/bin/
cp -p /usr/bin/lpq /cas/backup/usr/bin/
cp -p /usr/bin/lpq-lpd /cas/backup/usr/bin/
cp -p /usr/bin/lpr /cas/backup/usr/bin/
cp -p /usr/bin/lpr-lpd /cas/backup/usr/bin/
cp -p /usr/bin/lprm /cas/backup/usr/bin/
cp -p /usr/bin/lprm-lpd /cas/backup/usr/bin/
cp -p /usr/bin/newgrp /cas/backup/usr/bin/
cp -p /usr/sbin/lpc /cas/backup/usr/sbin/
cp -p /usr/sbin/lpc-lpd /cas/backup/usr/sbin/
cp -p /usr/sbin/traceroute /cas/backup/usr/sbin/

mkdir -p /cas/backup/inetd.conf/
cp -p /etc/inetd.conf /cas/backup/etc/
mkdir -p /cas/backup/etc/xinetd.conf
cp -p /etc/xintd.conf /cas/backup/etc/
mkdir -p /cas/backup/etc/xinetd.d/*
cp -p /etc/xinetd.d/* /cas/backup/etc/xinetd.d/

cp -p /etc/hosts /cas/backup/etc/

cp -p /etc/*ftpusers* /cas/backup/etc/
cp -p /etc/ftpd/ftpusers /cas/backup/etc/
cp -p /etc/*ftpd.conf /inetsec/backup/etc/

cp -p /etc/pam.d/login /cas/backup/etc/pam.d

cp -p /etc/dfs/dfstab /cas/backup/etc/

cp -p /etc/services /cas/backup/etc/

mkdir -p /cas/backup/etc/rc0.d/
mkdir -p /cas/backup/etc/rc1.d/
mkdir -p /cas/backup/etc/rc2.d/
mkdir -p /cas/backup/etc/rc3.d/
mkdir -p /cas/backup/etc/rc4.d/
mkdir -p /cas/backup/etc/rc5.d/
mkdir -p /cas/backup/etc/rc6.d/
mkdir -p /cas/backup/var/spool/cron/crontabs/

cp -p /etc/rc0.d/* /cas/backup/etc/rc0.d/
cp -p /etc/rc1.d/* /cas/backup/etc/rc1.d/
cp -p /etc/rc2.d/* /cas/backup/etc/rc2.d/
cp -p /etc/rc3.d/* /cas/backup/etc/rc3.d/
cp -p /etc/rc4.d/* /cas/backup/etc/rc4.d/
cp -p /etc/rc5.d/* /cas/backup/etc/rc5.d/
cp -p /etc/rc6.d/* /cas/backup/etc/rc6.d/

cp -p /etc/inittab /cas/backup/etc/
cp -p /etc/syslog.conf /cas/backup/etc/
mkdir -p /cas/backup/etc/snmp/
cp -p /etc/snmp/snmpd.conf /cas/backup/etc/snmp/
mkdir -p /cas/backup/etc/
cp -p /etc/crontab /cas/backup/etc/
mkdir -p /cas/backup/etc/cron.daily/
mkdir -p /cas/backup/etc/cron.hourly/
mkdir -p /cas/backup/etc/cron.monthly/
mkdir -p /cas/backup/etc/cron.weekly/
mkdir -p /cas/backup/var/spool/cron/
cp -p /etc/cron.daily/* /cas/backup/etc/cron.daily/
cp -p /etc/cron.hourly/* /cas/backup/etc/cron.hourly/
cp -p /etc/cron.monthly/* /cas/backup/etc/cron.monthly/
cp -p /etc/cron.weekly/* /cas/backup/etc/cron.weekly/


echo "######################################  3.네트워크 서비스  #############################################"
mkdir -p /cas/backup/etc/dfs/
cp -p /etc/dfs/dfstab /cas/backup/etc/dfs/

mkdir -p /cas/backup/etc/autofs/
cp -p /etc/rc2.d/S74autofs /cas/backup/etc/autofs/

cp -p /etc/hosts.equiv /cas/backup/etc/

mkdir -p /cas/backup/etc/mail
cp -p /etc/mail/sendmail.cf /cas/backup/etc/mail
cp -p /etc/named.conf /cas/backup/etc/
cp -p /etc/named.boot /cas/backup/etc/
cp -p /etc/issue /cas/backup/etc/


echo "######################################  4.로그 관리  ###################################################"

cp -p /etc/login.defs /cas/backup/etc/

cp -p /etc/syslog.conf /cas/backup/etc/default/


echo "##########    egrep -i fail|err|panic /var/log/messages*   ########"
echo "##########    egrep -i fail|err|panic /var/log/messages*   ########" >> /cas/backup/4.4_log_check.txt 2>&1
egrep -i "fail|err|panic" /var/log/messages* | tail				     >> /cas/backup/4.4_log_check.txt 2>&1
echo " "								     >> /cas/backup/4.4_log_check.txt 2>&1

echo "##########      egrep -i fail|err|panic /var/log/syslog*   ########"
echo "##########      egrep -i fail|err|panic /var/log/syslog*   ########" >> /cas/backup/4.4_log_check.txt 2>&1
egrep -i "fail|err|panic" /var/log/syslog* | tail				     >> /cas/backup/4.4_log_check.txt 2>&1
echo " " 								     >> /cas/backup/4.4_log_check.txt 2>&1

echo "##########       egrep -i fail|err|panic /var/log/authlog   #######"
echo "##########       egrep -i fail|err|panic /var/log/authlog   #######" >> /cas/backup/4.4_log_check.txt 2>&1
egrep -i "fail|err|panic" /var/log/authlog | tail				     >> /cas/backup/4.4_log_check.txt 2>&1
echo " " 								     >> /cas/backup/4.4_log_check.txt 2>&1

echo "###############         4.5 log file mode change    #################"
ls -alL /var/log/wtmp							>> /cas/backup/4.5_log_perm.txt 2>&1
ls -alL /var/run/utmp							>> /cas/backup/4.5_log_perm.txt 2>&1
ls -alL /var/log/btmp							>> /cas/backup/4.5_log_perm.txt 2>&1
ls -alL /var/log/pacct						        >> /cas/backup/4.5_log_perm.txt 2>&1
ls -alL /var/log/messages					        >> /cas/backup/4.5_log_perm.txt 2>&1
ls -alL /var/log/lastlog							>> /cas/backup/4.5_log_perm.txt 2>&1
ls -alL /var/log/secure* 					        >> /cas/backup/4.5_log_perm.txt 2>&1


echo "######################################  5. 주요 응용 설정  #############################################"
cp -p /etc/ftpusers /cas/backup/etc/
mkdir -p /cas/backup/etc/ftpd/
cp -p /etc/ftpd/ftpusers /cas/backup/etc/ftpd/

cp -p /etc/rc3.d/S76snmpdx /cas/backup/etc/
cp -p /etc/snmp/conf/snmpd.conf /cas/backup/etc/

cp -p /etc/rc2.d/S88sendmail /cas/backup/etc/
cp -p /etc/mail/sendmail.cf /cas/backup/etc/

cp -p /etc/rc3.d/S90samba /cas/backup/etc/

cp -p /etc/ssh/sshd_config /cas/backup/etc/

echo "####################################   BACKUP END !!!   ################################################"

fi


echo "INFO_CHKSTART"  >> $CREATE_FILE 2>&1
echo >> $CREATE_FILE 2>&1

echo " "
echo "★ Ⅱ. 전체 결과물 출력  ★ ****************************************************************************" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo "######################################### Start Time ###################################################"
date
echo " "
echo "######################################### Start Time ###################################################" >> $CREATE_FILE 2>&1
date >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1

echo "=================================== System Information Query Start ====================================="
echo "=================================== System Information Query Start =====================================" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1

echo "#######################################   Kernel Information   #########################################"
echo "#######################################   Kernel Information   #########################################" >> $CREATE_FILE 2>&1
uname -a >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1

echo "* IP_Start " >> $CREATE_FILE 2>&1
echo "#########################################   IP Information   ###########################################"
echo "#########################################   IP Information   ###########################################" >> $CREATE_FILE 2>&1
ifconfig -a >> $CREATE_FILE 2>&1
echo "* IP_End " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1

echo "#########################################   Network Status   ###########################################"
echo "#########################################   Network Status   ###########################################" >> $CREATE_FILE 2>&1
netstat -an | egrep -i "LISTEN|ESTABLISHED" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1

echo "#######################################   Routing Information   ########################################"
echo "#######################################   Routing Information   ########################################" >> $CREATE_FILE 2>&1
netstat -rn >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1

echo "##########################################   Process Status   ##########################################"
echo "##########################################   Process Status   ##########################################" >> $CREATE_FILE 2>&1
ps -ef >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1


echo "##########################################   User Env   ################################################"
echo "##########################################   User Env   ################################################" >> $CREATE_FILE 2>&1
env >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1

echo " " >> $CREATE_FILE 2>&1
echo "=================================== System Information Query End ======================================="
echo "=================================== System Information Query End =======================================" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1


echo >> $CREATE_FILE 2>&1
echo "********************************************* START ****************************************************" >> $CREATE_FILE 2>&1
echo >> $CREATE_FILE 2>&1
echo
echo "********************************************* START ****************************************************"
echo
echo >> $CREATE_FILE 2>&1

echo "========================================================================================================" >> $CREATE_FILE 2>&1
echo "========================================================================================================" >> $CREATE_FILE 2>&1
echo >> $CREATE_FILE 2>&1
echo "INFO_CHKEND"  >> $CREATE_FILE 2>&1


echo "1.01 START" >> $CREATE_FILE 2>&1
echo "############################ 1.계정관리 - 1.1 Default 계정 삭제 ########################################"
echo "############################ 1.계정관리 - 1.1 Default 계정 삭제 ########################################" >> $CREATE_FILE 2>&1
echo "--------------------------------------------------------------------------------------------------------" >> $CREATE_FILE 2>&1
echo "■ 기준 : /etc/passwd파일에 lp, uucp, nuucp 계정이 모두 존재하지 않으면 양호" >> $CREATE_FILE 2>&1
echo "■ 현황" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
if [ `cat /etc/passwd | egrep "lp:|uucp:|nuucp:" | grep -v "lpd" | wc -l` -eq 0 ]
  then
    echo "lp, uucp, nuucp 계정이 존재하지 않습니다."  >> $CREATE_FILE 2>&1
  else
    cat /etc/passwd | egrep "lp:|uucp:|nuucp:" >> $CREATE_FILE 2>&1
fi

if [ `cat /etc/passwd | egrep -i "lp:|uucp:|nuucp:"| grep -v "lpd" | wc -l` -gt 0 ]
    then
      echo "● 1.01 결과 : 취약" >> $CREATE_FILE 2>&1
    else
      echo "● 1.01 결과 : 양호" >> $CREATE_FILE 2>&1
fi

echo " " >> $CREATE_FILE 2>&1
echo "########################################################################################################" >> $CREATE_FILE 2>&1
echo "========================================================================================================" >> $CREATE_FILE 2>&1
echo "1.01 END" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1



echo "1.02 START" >> $CREATE_FILE 2>&1
echo "############################ 1.계정관리 - 1.2 root group 관리 ##########################################"
echo "############################ 1.계정관리 - 1.2 root group 관리 ##########################################" >> $CREATE_FILE 2>&1
echo "--------------------------------------------------------------------------------------------------------" >> $CREATE_FILE 2>&1
echo "■ 기준 : root 계정만 UID가 0이면 양호" >> $CREATE_FILE 2>&1
echo "■ 현황" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
if [ -f /etc/passwd ]
  then
    awk -F: '$3==0 { print $1 " -> UID=" $3 }' /etc/passwd >> $CREATE_FILE 2>&1
  else
    echo "/etc/passwd 파일이 없습니다." >> $CREATE_FILE 2>&1
fi
echo " " >> $CREATE_FILE 2>&1

echo "☞ /etc/passwd 파일 내용" >> $CREATE_FILE 2>&1
cat /etc/passwd >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1

if [ `awk -F: '$3==0  { print $1 }' /etc/passwd | grep -v "root"| wc -l` -eq 0 ]
  then
    echo "● 1.02 결과 : 양호" >> $CREATE_FILE 2>&1
  else
    echo "● 1.02 결과 : 취약" >> $CREATE_FILE 2>&1
fi
echo "########################################################################################################" >> $CREATE_FILE 2>&1
echo "========================================================================================================" >> $CREATE_FILE 2>&1
echo "1.02 END" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1



echo "1.03 START" >> $CREATE_FILE 2>&1
echo "############################ 1.계정관리 - 1.3 passwd 파일 권한 설정 ####################################"
echo "############################ 1.계정관리 - 1.3 passwd 파일 권한 설정 ##########################3#########" >> $CREATE_FILE 2>&1
echo "--------------------------------------------------------------------------------------------------------" >> $CREATE_FILE 2>&1
echo "■ 기준 : /etc/passwd 파일권한이 644이면 양호" >> $CREATE_FILE 2>&1
echo "■ 현황" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
if [ -f /etc/passwd ]
  then
    ls -alL /etc/passwd >> $CREATE_FILE 2>&1
  else
    echo "/etc/passwd 파일이 없습니다." >> $CREATE_FILE 2>&1
fi
echo " " >> $CREATE_FILE 2>&1

if [ `ls -alL /etc/passwd | awk '{print $1}' | grep "...-.--.--" | wc -l` -eq 1 ]
  then
    echo "● 1.03 결과 : 양호" >> $CREATE_FILE 2>&1
  else
    echo "● 1.03 결과 : 취약" >> $CREATE_FILE 2>&1
fi
echo " " >> $CREATE_FILE 2>&1
echo "########################################################################################################" >> $CREATE_FILE 2>&1
echo "========================================================================================================" >> $CREATE_FILE 2>&1
echo "1.03 END" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1




echo "1.04 START" >> $CREATE_FILE 2>&1
echo "############################ 1.계정관리 - 1.4 group 파일 권한 설정 #####################################"
echo "############################ 1.계정관리 - 1.4 group 파일 권한 설정 #####################################" >> $CREATE_FILE 2>&1
echo "--------------------------------------------------------------------------------------------------------" >> $CREATE_FILE 2>&1
echo "■ 기준 : /etc/group 파일 권한이 644이면 양호" >> $CREATE_FILE 2>&1
echo "■ 현황" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
ls -alL /etc/group >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1

if [ `ls -alL /etc/group |  awk '{print $1}' | grep "...-.--.--" | wc -l` -eq 1 ]
      then
        echo "● 1.04 결과 : 양호" >> $CREATE_FILE 2>&1
      else
        echo "● 1.04 결과 : 취약" >> $CREATE_FILE 2>&1
fi
echo " " >> $CREATE_FILE 2>&1
echo "########################################################################################################" >> $CREATE_FILE 2>&1
echo "========================================================================================================" >> $CREATE_FILE 2>&1
echo "1.04 END" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1



echo "1.05 START" >> $CREATE_FILE 2>&1
echo "############################ 1.계정관리 - 1.5 패스워드 최소길이 설정 ###################################"
echo "############################ 1.계정관리 - 1.5 패스워드 최소길이 설정 ###################################" >> $CREATE_FILE 2>&1
echo "--------------------------------------------------------------------------------------------------------" >> $CREATE_FILE 2>&1
echo "■ 기준 : /etc/login.defs에서 PASS_MIN_LEN   8 이상으로 설정되어 있으면 양호" >> $CREATE_FILE 2>&1
echo "■ 현황" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
if [ `ps -ef | grep "JMC" | grep -v "grep" | wc -l` -eq 0 ]
 then
  if [ -f /etc/login.defs ]
    then
      grep -v '^ *#' /etc/login.defs | grep -i "PASS_MIN_LEN" >> $CREATE_FILE 2>&1
    else
      echo "/etc/login.defs 파일이 없습니다." >> $CREATE_FILE 2>&1
  fi
 else
   echo "계정관리시스템(AMS)이 실행중입니다." >> $CREATE_FILE 2>&1
fi

echo " " >> $CREATE_FILE 2>&1
echo " " > password_1.txt

if [ `ps -ef | grep "JMC" | grep -v "grep" | wc -l` -eq 0 ]
 then
  if [ `cat /etc/login.defs | grep -i "PASS_MIN_LEN" | grep -v "#" | egrep [0-9] | awk '{print $2}' | wc -l` -eq 0 ]
    then
      echo "● 1.05 결과 : 취약" >> password_1.txt
    else
      if [ `cat /etc/login.defs | grep -i "PASS_MIN_LEN"| grep -v "#" | awk '{print $2}'` -gt 7 ]
        then
          echo "● 1.05 결과 : 양호" >> password_1.txt
        else
          echo "● 1.05 결과 : 취약" >> password_1.txt
      fi
  fi
 else
  echo "● 1.05 결과 : 양호" >> password_1.txt
fi

if [ `cat password_1.txt | grep "취약" | wc -l` -eq 0 ]
 then
  echo "● 1.05 결과 : 양호" >> $CREATE_FILE 2>&1
 else
  echo "● 1.05 결과 : 취약" >> $CREATE_FILE 2>&1
fi

rm -rf password_1.txt

echo " " >> $CREATE_FILE 2>&1
echo "########################################################################################################" >> $CREATE_FILE 2>&1
echo "========================================================================================================" >> $CREATE_FILE 2>&1
echo "1.05 END" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1





echo "1.06 START" >> $CREATE_FILE 2>&1
echo "############################ 1.계정관리 - 1.6 패스워드 최대 사용기간 설정 ###################################"
echo "############################ 1.계정관리 - 1.6 패스워드 최대 사용기간 설정 ###################################" >> $CREATE_FILE 2>&1
echo "--------------------------------------------------------------------------------------------------------" >> $CREATE_FILE 2>&1
echo "■ 기준 : /etc/login.defs에서 PASS_MAX_DAYS 90 이하면 양호" >> $CREATE_FILE 2>&1
echo "■ 현황" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
if [ `ps -ef | grep "JMC" | grep -v "grep" | wc -l` -eq 0 ]
 then
  if [ -f /etc/login.defs ]
   then
     grep -v '^ *#' /etc/login.defs | grep -i "PASS_MAX_DAYS" >> $CREATE_FILE 2>&1
   else
     echo "/etc/login.defs 파일이 없습니다." >> $CREATE_FILE 2>&1
  fi
 else
   echo "계정관리시스템(AMS)이 실행중입니다." >> $CREATE_FILE 2>&1
fi

echo " " >> $CREATE_FILE 2>&1

echo " " > password_2.txt

if [ `ps -ef | grep "JMC" | grep -v "grep" | wc -l` -eq 0 ]
 then
  if [ `cat /etc/login.defs | grep -i "PASS_MAX_DAYS" | grep -v "#" | egrep  [0-9] | awk '{print $2}' | wc -l` -eq 0 ]
   then
     echo "● 1.06 결과 : 취약" >> password_2.txt
   else
     if [ `cat /etc/login.defs | grep -i "PASS_MAX_DAYS" | grep -v "#" | awk '{print $2}'` -gt 90 ]
      then
       echo "● 1.06 결과 : 취약" >> password_2.txt
      else
       echo "● 1.06 결과 : 양호" >> password_2.txt
     fi
  fi
else
  echo "● 1.06 결과 : 양호" >> password_2.txt
fi

if [ `cat password_2.txt | grep "취약" | wc -l` -eq 0 ]
 then
  echo "● 1.06 결과 : 양호" >> $CREATE_FILE 2>&1
 else
  echo "● 1.06 결과 : 취약" >> $CREATE_FILE 2>&1
fi

rm -rf password_2.txt

echo " " >> $CREATE_FILE 2>&1
echo "########################################################################################################" >> $CREATE_FILE 2>&1
echo "========================================================================================================" >> $CREATE_FILE 2>&1
echo "1.06 END" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1


echo "1.07 START" >> $CREATE_FILE 2>&1
echo "############################ 1.계정관리 - 1.7 패스워드 최소 사용기간 설정 ###################################"
echo "############################ 1.계정관리 - 1.7 패스워드 최소 사용기간 설정 ###################################" >> $CREATE_FILE 2>&1
echo "--------------------------------------------------------------------------------------------------------" >> $CREATE_FILE 2>&1
echo "■ 기준 : /etc/login.defs에서 PASS_MIN_DAYS  1 이상이면 양호" >> $CREATE_FILE 2>&1
echo "■ 현황" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
if [ `ps -ef | grep "JMC" | grep -v "grep" | wc -l` -eq 0 ]
 then
  if [ -f /etc/login.defs ]
    then
      grep -v '^ *#' /etc/login.defs | grep -i "PASS_MIN_DAYS" >> $CREATE_FILE 2>&1
    else
      echo "/etc/login.defs 파일이 없습니다." >> $CREATE_FILE 2>&1
  fi
 else
   echo "계정관리시스템(AMS)이 실행중입니다." >> $CREATE_FILE 2>&1
fi

echo " " >> $CREATE_FILE 2>&1

echo " " > password_3.txt

if [ `ps -ef | grep "JMC" | grep -v "grep" | wc -l` -eq 0 ]
 then
  if [ `cat /etc/login.defs | grep -i "PASS_MIN_DAYS" | egrep [0-9] | grep -v "#" |awk '{print $2}' | wc -l` -eq 0 ]
   then
     echo "● 1.07 결과 : 취약" >> password_3.txt
   else
    if [ `cat /etc/login.defs | grep -i "PASS_MIN_DAYS" | grep -v "#" | awk '{print $2}'` -gt 0 ]
     then
      echo "● 1.07 결과 : 양호" >> password_3.txt
     else
      echo "● 1.07 결과 : 취약" >> password_3.txt
    fi
  fi
else
  echo "● 1.07 결과 : 양호" >> password_3.txt
fi


if [ `cat password_3.txt | grep "취약" | wc -l` -eq 0 ]
 then
  echo "● 1.07 결과 : 양호" >> $CREATE_FILE 2>&1
 else
  echo "● 1.07 결과 : 취약" >> $CREATE_FILE 2>&1
fi

rm -rf password_3.txt

echo " " >> $CREATE_FILE 2>&1
echo "########################################################################################################" >> $CREATE_FILE 2>&1
echo "========================================================================================================" >> $CREATE_FILE 2>&1
echo "1.07 END" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1



echo "1.08 START" >> $CREATE_FILE 2>&1
echo "############################ 1.계정관리 - 1.8 shell 제한 ###############################################"
echo "############################ 1.계정관리 - 1.8 shell 제한 ###############################################" >> $CREATE_FILE 2>&1
echo "--------------------------------------------------------------------------------------------------------" >> $CREATE_FILE 2>&1
echo "■ 기준 : 로그인이 필요하지 않은 시스템 계정에 /bin/false(nologin) 쉘이 부여되어 있으면 양호" >> $CREATE_FILE 2>&1
echo "■ 현황" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
if [ -f /etc/passwd ]
  then
    cat /etc/passwd | egrep "^daemon|^bin|^sys|^adm|^listen|^nobody|^nobody4|^noaccess|^diag|^listen|^operator|^games|^gopher" | grep -v "admin" >> $CREATE_FILE 2>&1
  else
    echo "/etc/passwd 파일이 없습니다." >> $CREATE_FILE 2>&1
fi

if [ `cat /etc/passwd | egrep "^daemon|^bin|^sys|^adm|^listen|^nobody|^nobody4|^noaccess|^diag|^listen|^operator|^games|^gopher" | grep -v "admin" | egrep -v 'false|nologin' | wc -l` -eq 0 ]
  then
    echo "● 1.08 결과 : 양호" >> $CREATE_FILE 2>&1
  else
    echo "● 1.08 결과 : 취약" >> $CREATE_FILE 2>&1
fi

echo " " >> $CREATE_FILE 2>&1
echo "########################################################################################################" >> $CREATE_FILE 2>&1
echo "========================================================================================================" >> $CREATE_FILE 2>&1
echo "1.08 END" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1




echo "1.09 START" >> $CREATE_FILE 2>&1
echo "############################ 1.계정관리 - 1.9 su 제한 ##################################################"
echo "############################ 1.계정관리 - 1.9 su 제한 ##################################################" >> $CREATE_FILE 2>&1
echo "--------------------------------------------------------------------------------------------------------" >> $CREATE_FILE 2>&1
echo "■ 기준 : /etc/pam.d/su 파일에 auth  required pam_wheel.so use_uid 라인에 주석(#)이 없고 /etc/group 파일의 wheel그룹에 계정이 제한되어 있으면 양호" >> $CREATE_FILE 2>&1
echo "■ 현황" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
if [ -f /etc/pam.d/su ]
  then
    echo "① /etc/pam.d/su 파일" >> $CREATE_FILE 2>&1
    cat /etc/pam.d/su  >> $CREATE_FILE 2>&1
  else
    echo "/etc/pam.d/su 파일이 없습니다. " >> $CREATE_FILE 2>&1
fi
echo " " >> $CREATE_FILE 2>&1

echo "② /etc/group 파일" >> $CREATE_FILE 2>&1
cat /etc/group >> $CREATE_FILE 2>&1

echo " " >> $CREATE_FILE 2>&1

if [ `cat /etc/pam.d/su | grep -v 'trust' | grep 'pam_wheel.so' | grep 'use_uid' | grep -v '^#' | wc -l` -eq 0 ]
 then
      echo "● 1.09 결과 : 취약" >> $CREATE_FILE 2>&1
 else
      echo "● 1.09 결과 : 양호" >> $CREATE_FILE 2>&1
fi
echo " " >> $CREATE_FILE 2>&1
echo "########################################################################################################" >> $CREATE_FILE 2>&1
echo "========================================================================================================" >> $CREATE_FILE 2>&1
echo "1.09 END" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1



echo "1.10 START" >> $CREATE_FILE 2>&1
echo "############################ 1.계정관리 - 1.10 shadow 파일 권한 설정 ####################################"
echo "############################ 1.계정관리 - 1.10 shadow 파일 권한 설정 ####################################" >> $CREATE_FILE 2>&1
echo "--------------------------------------------------------------------------------------------------------" >> $CREATE_FILE 2>&1
echo "■ 기준 : /etc/shadow 파일 권한이 400이면 양호" >> $CREATE_FILE 2>&1
echo "■ 현황" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
if [ -f /etc/shadow ]
  then
    ls -alL /etc/shadow >> $CREATE_FILE 2>&1
  else
    echo "/etc/shadow 파일이 없습니다." >> $CREATE_FILE 2>&1
fi

if [ `ls -alL /etc/shadow | awk '{print $1}' | grep ".r--------" | wc -l` -eq 1 ]
  then
    echo "● 1.10 결과 : 양호" >> $CREATE_FILE 2>&1
  else
    echo "● 1.10 결과 : 취약" >> $CREATE_FILE 2>&1
fi

echo " " >> $CREATE_FILE 2>&1
echo "########################################################################################################" >> $CREATE_FILE 2>&1
echo "========================================================================================================" >> $CREATE_FILE 2>&1
echo "1.10 END" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1



echo "1.11 START" >> $CREATE_FILE 2>&1
echo "############################ 1.계정관리 - 1.11 Trivial Password #########################################"
echo "############################ 1.계정관리 - 1.11 Trivial Password #########################################" >> $CREATE_FILE 2>&1
echo "--------------------------------------------------------------------------------------------------------" >> $CREATE_FILE 2>&1
echo "■ 기준 : John the Ripper를 이용해서 크랙킹되는 패스워드가 없으면 양호" >> $CREATE_FILE 2>&1
echo "■ 현황" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
if [ -f /etc/passwd ]
  then
    echo "① /etc/passwd 파일 " >> $CREATE_FILE 2>&1
    echo "* Acc_Start " >> $CREATE_FILE 2>&1
    cat /etc/passwd >> $CREATE_FILE 2>&1
    echo "* Acc_End " >> $CREATE_FILE 2>&1
  else
    echo " /etc/passwd 파일이 없습니다. " >> $CREATE_FILE 2>&1
fi

echo " " >> $CREATE_FILE 2>&1

if [ -f /etc/shadow ]
  then
    echo "② /etc/shadow 파일 " >> $CREATE_FILE 2>&1
    cat /etc/shadow >> $CREATE_FILE 2>&1
  else
    echo " /etc/shadow 파일이 없습니다. " >> $CREATE_FILE 2>&1
fi

#echo "① /etc/passwd 파일 " > `hostname`_password.txt
#cat /etc/passwd >> `hostname`_password.txt
#echo " " >> `hostname`_password.txt

#echo "② /etc/shadow 파일 " >> `hostname`_password.txt
#cat /etc/shadow >> `hostname`_password.txt
#echo " " >> `hostname`_password.txt

echo " " >> $CREATE_FILE 2>&1
echo "● 1.11 결과 : 미점검" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo "########################################################################################################" >> $CREATE_FILE 2>&1
echo "========================================================================================================" >> $CREATE_FILE 2>&1
echo "1.11 END" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1


echo "1.12 START" >> $CREATE_FILE 2>&1
echo "############################ 1.계정관리 - 1.12 계정이 존재하지 않는 GID 금지 #########################################"
echo "############################ 1.계정관리 - 1.12 계정이 존재하지 않는 GID 금지 #########################################" >> $CREATE_FILE 2>&1
echo "--------------------------------------------------------------------------------------------------------" >> $CREATE_FILE 2>&1
echo "■ 기준 : 계정이 없는 그룹이 존재하지 않으면 양호" >> $CREATE_FILE 2>&1
echo "■ 현황" >> $CREATE_FILE 2>&1
cat /etc/group >> $CREATE_FILE 2>&1

echo " " >> $CREATE_FILE 2>&1
echo "● 1.12 결과 : 미점검" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " "
echo "########################################################################################################" >> $CREATE_FILE 2>&1
echo "========================================================================================================" >> $CREATE_FILE 2>&1
echo "1.12 END" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1



echo "1.13 START" >> $CREATE_FILE 2>&1
echo "############################ 1.계정관리 - 1.13 계정잠금 임계값 설정 #########################################"
echo "############################ 1.계정관리 - 1.13 계정잠금 임계값 설정 #########################################" >> $CREATE_FILE 2>&1
echo "--------------------------------------------------------------------------------------------------------" >> $CREATE_FILE 2>&1
echo "■ 기준 : 계정잠금 임계값이 5이하일 경우 양호" >> $CREATE_FILE 2>&1
echo "■ 현황" >> $CREATE_FILE 2>&1
cat /etc/pam.d/system-auth >> $CREATE_FILE 2>&1

echo " " >> $CREATE_FILE 2>&1
cat /etc/pam.d/system-auth >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo "########################################################################################################" >> $CREATE_FILE 2>&1
echo "========================================================================================================" >> $CREATE_FILE 2>&1
echo "1.13 END" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1



echo "2.01 START" >> $CREATE_FILE 2>&1
echo "############################ 2.파일시스템 - 2.1 UMASK 설정 #############################################"
echo "############################ 2.파일시스템 - 2.1 UMASK 설정 #############################################" >> $CREATE_FILE 2>&1
echo "--------------------------------------------------------------------------------------------------------" >> $CREATE_FILE 2>&1
echo "■ 기준 : /etc/bashrc 또는 /etc/profile에 UMASK 값이 022 또는 027이면 양호" >> $CREATE_FILE 2>&1
echo "■ 현황" >> $CREATE_FILE 2>&1
echo "  " >> $CREATE_FILE 2>&1
echo "① /etc/bashrc 파일   " >> $CREATE_FILE 2>&1
if [ -f /etc/bashrc ]
 then
   cat /etc/bashrc | grep -i umask >> $CREATE_FILE 2>&1
 else
   echo "/etc/bashrc 파일이 없습니다." >> $CREATE_FILE 2>&1
fi

echo "  " >> $CREATE_FILE 2>&1

echo "② /etc/profile 파일  " >> $CREATE_FILE 2>&1
if [ -f /etc/profile ]
 then
   cat /etc/profile | grep -i umask >> $CREATE_FILE 2>&1
 else
   echo "/etc/profile 파일이 없습니다." >> $CREATE_FILE 2>&1
fi

echo " " > mask.txt

if [ `cat /etc/bashrc | grep -i "umask" | grep -v "#" | awk -F"0" '$2 >= "22"' | wc -l` -gt 0 ]
  then
    echo "● 2.01 결과 : 양호" >> mask.txt
  else
    echo "● 2.01 결과 : 취약" >> mask.txt
fi

if [ `cat /etc/profile | grep -i "umask" | grep -v "#" | awk -F"0" '$2 >= "22"' | wc -l` -gt 0 ]
  then
    echo "● 2.01 결과 : 양호" >> mask.txt
  else
    echo "● 2.01 결과 : 취약" >> mask.txt
fi


if [ `cat mask.txt | grep "취약" | wc -l` -eq 2 ]
 then
  echo "● 2.01 결과 : 취약" >> $CREATE_FILE 2>&1
 else
  echo "● 2.01 결과 : 양호" >> $CREATE_FILE 2>&1
fi

rm -rf mask.txt

echo "  " >> $CREATE_FILE 2>&1
echo "########################################################################################################" >> $CREATE_FILE 2>&1
echo "========================================================================================================" >> $CREATE_FILE 2>&1
echo "2.01 END" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1





echo "2.02 START" >> $CREATE_FILE 2>&1
echo "############################ 2.파일시스템 - 2.2 Setuid, Setgid 설정 ####################################"
echo "############################ 2.파일시스템 - 2.2 Setuid, Setgid 설정 ####################################" >> $CREATE_FILE 2>&1
echo "--------------------------------------------------------------------------------------------------------" >> $CREATE_FILE 2>&1
echo "■ 기준 : 불필요한 setuid, setgid 파일이 존재하지 않으면 양호" >> $CREATE_FILE 2>&1
echo "■ 현황" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
FILES="/usr/dt/bin/dtaction /usr/dt/bin/dtterm /usr/bin/X11/xlock /usr/sbin/mount /usr/sbin/lchangelv /opt/perf/bin/glance /usr/dt/bin/dtprintinfo /opt/perf/bin/gpm /usr/sbin/arp /opt/video/lbin/camServer /usr/sbin/lanadmin /usr/bin/at /usr/sbin/landiag /usr/bin/lpalt /usr/sbin/lpsched /usr/bin/mediainit /usr/sbin/swacl /usr/bin/newgrp /usr/sbin/swconfig /usr/bin/rdist /usr/sbin/swinstall /usr/contrib/bin/traceroute /usr/sbin/swmodify /usr/dt/bin/dtappgather /usr/sbin/swpackage /usr/sbin/swreg /usr/sbin/swremove /sbin/dump /usr/bin/lpq-lpd /usr/bin/newgrp /sbin/restore /usr/bin/lpr /usr/sbin/lpc /sbin/unix_chkpwd /usr/bin/lpr-lpd /usr/sbin/lpc-lpd /usr/bin/at /usr/bin/lprm /usr/sbin/traceroute /usr/bin/lpq /usr/bin/lprm-lpd /usr/bin/admintool /usr/bin/at /usr/bin/atq /usr/bin/atrm /usr/bin/lpset /usr/bin/newgrp /usr/bin/nispasswd /usr/bin/rdist /usr/bin/yppasswd /usr/dt/bin/dtappgather /usr/dt/bin/dtprintinfo /usr/dt/bin/sdtcm_convert /usr/lib/fs/ufs/ufsdump /usr/lib/fs/ufs/ufsrestore /usr/lib/lp/bin/netpr /usr/openwin/bin/ff.core /usr/openwin/bin/kcms_calibrate /usr/openwin/bin/kcms_configure /usr/openwin/bin/xlock /usr/platform/sun4u/sbin/prtdiag /usr/sbin/arp /usr/sbin/lpmove /usr/sbin/prtconf /usr/sbin/sysdef /usr/sbin/sparcv7/prtconf /usr/sbin/sparcv7/sysdef /usr/sbin/sparcv9/prtconf /usr/sbin/sparcv9/sysdef"

for check_file in $FILES
 do
  if [ -f $check_file ]
   then
        if [ -g $check_file -o -u $check_file ]
          then
            echo `ls -alL $check_file` >> $CREATE_FILE 2>&1
        else
        :
        fi
      else
        echo $check_file "이 없습니다" >> $CREATE_FILE 2>&1
    fi
done

echo "setuid " > set.txt
FILES="/usr/dt/bin/dtaction /usr/dt/bin/dtterm /usr/bin/X11/xlock /usr/sbin/mount /usr/sbin/lchangelv /opt/perf/bin/glance /usr/dt/bin/dtprintinfo /opt/perf/bin/gpm /usr/sbin/arp /opt/video/lbin/camServer /usr/sbin/lanadmin /usr/bin/at /usr/sbin/landiag /usr/bin/lpalt /usr/sbin/lpsched /usr/bin/mediainit /usr/sbin/swacl /usr/bin/newgrp /usr/sbin/swconfig /usr/bin/rdist /usr/sbin/swinstall /usr/contrib/bin/traceroute /usr/sbin/swmodify /usr/dt/bin/dtappgather /usr/sbin/swpackage /usr/sbin/swreg /usr/sbin/swremove /sbin/dump /usr/bin/lpq-lpd /usr/bin/newgrp /sbin/restore /usr/bin/lpr /usr/sbin/lpc /sbin/unix_chkpwd /usr/bin/lpr-lpd /usr/sbin/lpc-lpd /usr/bin/at /usr/bin/lprm /usr/sbin/traceroute /usr/bin/lpq /usr/bin/lprm-lpd /usr/bin/admintool /usr/bin/at /usr/bin/atq /usr/bin/atrm /usr/bin/lpset /usr/bin/newgrp /usr/bin/nispasswd /usr/bin/rdist /usr/bin/yppasswd /usr/dt/bin/dtappgather /usr/dt/bin/dtprintinfo /usr/dt/bin/sdtcm_convert /usr/lib/fs/ufs/ufsdump /usr/lib/fs/ufs/ufsrestore /usr/lib/lp/bin/netpr /usr/openwin/bin/ff.core /usr/openwin/bin/kcms_calibrate /usr/openwin/bin/kcms_configure /usr/openwin/bin/xlock /usr/platform/sun4u/sbin/prtdiag /usr/sbin/arp /usr/sbin/lpmove /usr/sbin/prtconf /usr/sbin/sysdef /usr/sbin/sparcv7/prtconf /usr/sbin/sparcv7/sysdef /usr/sbin/sparcv9/prtconf /usr/sbin/sparcv9/sysdef"

for check_file in $FILES
  do
     if [ -f $check_file ]
      then
       if [ `ls -alL $check_file | awk '{print $1}' | grep -i 's' | wc -l` -gt 0 ]
           then
              ls -alL $check_file |awk '{print $1}' | grep -i 's' >> set.txt
           else
              echo " " >> set.txt
       fi
     fi
done

if [ `cat set.txt | awk '{print $1}' | grep -i 's' | wc -l` -gt 1 ]
    then
           echo "● 2.02 결과 : 취약" >> $CREATE_FILE 2>&1
    else
           echo "● 2.02 결과 : 양호" >> $CREATE_FILE 2>&1
fi
rm -rf set.txt

echo " " >> $CREATE_FILE 2>&1
find / -type f \( -perm -04000 -o -perm -02000 \) \-exec ls -lg {} \; >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo "########################################################################################################" >> $CREATE_FILE 2>&1
echo "========================================================================================================" >> $CREATE_FILE 2>&1
echo "2.02 END" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1




echo "2.03 START" >> $CREATE_FILE 2>&1
echo "############################ 2.파일시스템 - 2.3 inetd.conf 파일 권한 설정 ##############################"
echo "############################ 2.파일시스템 - 2.3 inetd.conf 파일 권한 설정 ##############################" >> $CREATE_FILE 2>&1
echo "--------------------------------------------------------------------------------------------------------" >> $CREATE_FILE 2>&1
echo "■ 기준 : /etc/inetd.conf의 권한에 타사용자 쓰기권한이 없으면 양호" >> $CREATE_FILE 2>&1
echo "■ 현황" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
if [ -f /etc/xinetd.conf ]
  then
    ls -alL /etc/xinetd.conf >> $CREATE_FILE 2>&1
  else
    echo " /etc/xinetd.conf 파일이 없습니다." >> $CREATE_FILE 2>&1
fi
echo " " >> $CREATE_FILE 2>&1

if [ -f /etc/inetd.conf ]
  then
    ls -alL /etc/inetd.conf >> $CREATE_FILE 2>&1
  else
    echo " /etc/inetd.conf 파일이 없습니다." >> $CREATE_FILE 2>&1
fi
echo " " >> $CREATE_FILE 2>&1

echo " " > inetd.txt

if [ -f /etc/inetd.conf ]
then
if [ `ls -alL /etc/inetd.conf | awk '{print $1}' | grep '........-.'| wc -l` -eq 1 ]
  then
    echo "● 2.03 결과 : 양호" >> inetd.txt
  else
    echo "● 2.03 결과 : 취약" >> inetd.txt
fi
else
 echo "● 2.03 결과 : 양호" >> inetd.txt
fi


if [ -f /etc/xinetd.conf ]
 then
  if [ `ls -alL /etc/xinetd.conf | awk '{print $1}' | grep '........-.' | wc -l` -eq 1 ]
   then
     echo "● 2.03 결과 : 양호" >> inetd.txt
   else
     echo "● 2.03 결과 : 취약" >> inetd.txt
  fi
 else
 echo "● 2.03 결과 : 양호" >> inetd.txt
fi

if [ `cat inetd.txt | grep "취약" | wc -l` -eq 0 ]
 then
  echo "● 2.03 결과 : 양호" >> $CREATE_FILE 2>&1
 else
  echo "● 2.03 결과 : 취약" >> $CREATE_FILE 2>&1
fi

rm -rf inetd.txt
echo " " >> $CREATE_FILE 2>&1
echo "########################################################################################################" >> $CREATE_FILE 2>&1
echo "========================================================================================================" >> $CREATE_FILE 2>&1
echo "2.03 END" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1



echo "2.04 START" >> $CREATE_FILE 2>&1
echo "############################ 2.파일시스템 - 2.4 .sh_history 파일 권한 설정 ################################"
echo "############################ 2.파일시스템 - 2.4 .sh_history 파일 권한 설정 ################################" >> $CREATE_FILE 2>&1
echo "--------------------------------------------------------------------------------------------------------" >> $CREATE_FILE 2>&1
echo "■ 기준 : .sh_history, .bash_history의 권한에 타사용자 쓰기권한이 없으면 양호" >> $CREATE_FILE 2>&1
echo "■ 현황" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
HOMEDIRS=`cat /etc/passwd | awk -F":" 'length($6) > 0 {print $6}' | sort -u | grep -v '/bin/false' | grep -v 'nologin' | grep -v "#"`
FILES="/.sh_history /.bash_history /.history"

for file in $FILES
  do
    FILE=$file
    if [ -f $FILE ]
      then
        ls -alL $FILE >> $CREATE_FILE 2>&1
    fi
  done

FILES2="/.sh_history /.bash_history /.history"
for dir in $HOMEDIRS
do
  for file in $FILES2
  do
    FILE=$dir$file
    if [ -f $FILE ]
      then
        ls -alL $FILE >> $CREATE_FILE 2>&1
    fi
  done
done

echo " " >> $CREATE_FILE 2>&1

echo " " > homesh.txt

HOMEDIRS=`cat /etc/passwd | awk -F":" 'length($6) > 0 {print $6}' | sort -u | grep -v '/bin/false' | grep -v 'nologin' | grep -v "#"`
FILES="/.sh_history /.bash_history /.history"

for file in $FILES
          do
            if [ -f $file ]
             then
             if [ `ls -al $file | awk '{print $1}' | grep "........-." | wc -l` -eq 1 ]
              then
                echo "● 2.04 결과 : 양호" >> homesh.txt
              else
                echo "● 2.04 결과 : 취약" >> homesh.txt
             fi
            else
              echo "● 2.04 결과 : 양호" >> homesh.txt
            fi
         done

FILES2=".sh_history .bash_history .history"
 for dir in $HOMEDIRS
    do
       for file in $FILES2
          do
            if [ -f $dir/$file ]
             then
             if [ `ls -dal $dir/$file | awk '{print $1}' | grep "........-." | wc -l` -eq 1 ]
              then
                echo "● 2.04 결과 : 양호" >> homesh.txt
              else
                echo "● 2.04 결과 : 취약" >> homesh.txt
             fi
            else
              echo "● 2.04 결과 : 양호" >> home2.txt
            fi
         done
    done

if [ `cat homesh.txt | grep "취약" | wc -l` -eq 0 ]
 then
  echo "● 2.04 결과 : 양호" >> $CREATE_FILE 2>&1
 else
  echo "● 2.04 결과 : 취약" >> $CREATE_FILE 2>&1
fi

rm -rf homesh.txt

echo " " >> $CREATE_FILE 2>&1
echo "########################################################################################################" >> $CREATE_FILE 2>&1
echo "========================================================================================================" >> $CREATE_FILE 2>&1
echo "2.04 END" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1




echo "2.05 START" >> $CREATE_FILE 2>&1
echo "############################ 2.파일시스템 - 2.5 Crontab 관련 파일의 접근 제한 ##########################"
echo "############################ 2.파일시스템 - 2.5 Crontab 관련 파일의 접근 제한 ##########################" >> $CREATE_FILE 2>&1
echo "--------------------------------------------------------------------------------------------------------" >> $CREATE_FILE 2>&1
echo "■ 기준 : Crontab 관련 파일에 타사용자에게 쓰기권한이 없으면 양호" >> $CREATE_FILE 2>&1
echo "■ 현황" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
cro="/etc/crontab /etc/cron.daily/* /etc/cron.hourly/* /etc/cron.monthly/* /etc/cron.weekly/* /var/spool/cron/*"

for check_dir in $cro
do
  if [ -f $check_dir ]
    then
      ls -alL $check_dir >> $CREATE_FILE 2>&1
    else
      echo $check_dir " 이 없습니다" >> $CREATE_FILE 2>&1
  fi
done
echo " " >> $CREATE_FILE 2>&1

cro="/etc/crontab /etc/cron.daily/* /etc/cron.hourly/* /etc/cron.monthly/* /etc/cron.weekly/* /var/spool/cron/*"

echo " " > crontab.txt
for check_dir in $cro
do

  if [  `ls -alL $check_dir | awk '{print $1}' |grep  '........w.' | wc -l` -eq 0 ]
    then
      echo "● 2.05 결과 : 양호" >> crontab.txt
    else
      echo "● 2.05 결과 : 취약" >> crontab.txt
  fi
done

if [ `cat crontab.txt | grep "취약" | wc -l` -eq 0 ]
 then
  echo "● 2.05 결과 : 양호" >> $CREATE_FILE 2>&1
 else
  echo "● 2.05 결과 : 취약" >> $CREATE_FILE 2>&1
fi

rm -rf crontab.txt
echo "########################################################################################################" >> $CREATE_FILE 2>&1
echo "========================================================================================================" >> $CREATE_FILE 2>&1
echo "2.05 END" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1




echo "2.06 START" >> $CREATE_FILE 2>&1
echo "############################ 2.파일시스템 - 2.6 Crontab 관리 ###########################################"
echo "############################ 2.파일시스템 - 2.6 Crontab 관리 ###########################################" >> $CREATE_FILE 2>&1
echo "--------------------------------------------------------------------------------------------------------" >> $CREATE_FILE 2>&1
echo "■ 기준 : Crontab에 설정된 파일에 타사용자 쓰기권한이 없으면 양호" >> $CREATE_FILE 2>&1
echo "■ 현황" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1

crontab -l >> $CREATE_FILE 2>&1

echo " " >> $CREATE_FILE 2>&1
echo "● 2.06 결과 : 미점검" >> $CREATE_FILE 2>&1
echo "########################################################################################################" >> $CREATE_FILE 2>&1
echo "========================================================================================================" >> $CREATE_FILE 2>&1
echo "2.06 END" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1



echo "2.07 START" >> $CREATE_FILE 2>&1
echo "############################ 2.파일시스템 - 2.7 profile 파일 권한 설정 #################################"
echo "############################ 2.파일시스템 - 2.7 profile 파일 권한 설정 #################################" >> $CREATE_FILE 2>&1
echo "--------------------------------------------------------------------------------------------------------" >> $CREATE_FILE 2>&1
echo "■ 기준 : /etc/profile의 권한에 타사용자 쓰기권한이 없으면 양호" >> $CREATE_FILE 2>&1
echo "■ 현황" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
if [ -f /etc/profile ]
  then
    ls -alL /etc/profile >> $CREATE_FILE 2>&1
  else
    echo " /etc/profile 파일이 없습니다." >> $CREATE_FILE 2>&1
fi
echo " " >> $CREATE_FILE 2>&1

if [ -f /etc/profile ]
then
if [ `ls -alL /etc/profile | awk '{print $1}' | grep '........-.' | wc -l` -eq 1 ]
  then
     echo "● 2.07 결과 : 양호" >> $CREATE_FILE 2>&1
  else
     echo "● 2.07 결과 : 취약" >> $CREATE_FILE 2>&1
fi
else
 echo "● 2.07 결과 : 양호" >> $CREATE_FILE 2>&1
fi
echo "#########################################################################################################" >> $CREATE_FILE 2>&1
echo "=========================================================================================================" >> $CREATE_FILE 2>&1
echo "2.07 END" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1




echo "2.08 START" >> $CREATE_FILE 2>&1
echo "############################ 2.파일시스템 - 2.8 hosts 파일 권한 설정 ###################################"
echo "############################ 2.파일시스템 - 2.8 hosts 파일 권한 설정 ###################################" >> $CREATE_FILE 2>&1
echo "--------------------------------------------------------------------------------------------------------" >> $CREATE_FILE 2>&1
echo "■ 기준 : /etc/hosts의 권한에 타사용자 쓰기권한이 없으면 양호" >> $CREATE_FILE 2>&1
echo "■ 현황" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
if [ -f /etc/hosts ]
  then
    ls -alL /etc/hosts >> $CREATE_FILE 2>&1
  else
    echo "/etc/hosts 파일이 없습니다." >> $CREATE_FILE 2>&1
fi
echo " " >> $CREATE_FILE 2>&1
if [ -f /etc/hosts ]
then
if [ `ls -alL /etc/hosts | awk '{print $1}' | grep '........-.' | wc -l` -eq 1 ]
  then
    echo "● 2.08 결과 : 양호" >> $CREATE_FILE 2>&1
  else
    echo "● 2.08 결과 : 취약" >> $CREATE_FILE 2>&1
fi
else
 echo "● 2.08 결과 : 양호" >> $CREATE_FILE 2>&1
fi
echo "#########################################################################################################" >> $CREATE_FILE 2>&1
echo "=========================================================================================================" >> $CREATE_FILE 2>&1
echo "2.08 END" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1


echo "2.09 START" >> $CREATE_FILE 2>&1
echo "############################ 2.파일시스템 - 2.9 issue 파일 권한 설정 ###################################"
echo "############################ 2.파일시스템 - 2.9 issue 파일 권한 설정 ###################################" >> $CREATE_FILE 2>&1
echo "--------------------------------------------------------------------------------------------------------" >> $CREATE_FILE 2>&1
echo "■ 기준 : /etc/issue의 권한에 타사용자 쓰기권한이 없으면 양호" >> $CREATE_FILE 2>&1
echo "■ 현황" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
if [ -f /etc/issue ]
  then
    ls -alL /etc/issue >> $CREATE_FILE 2>&1
   else
    echo "☞ /etc/issue 파일이 없습니다." >> $CREATE_FILE 2>&1
fi
echo " " >> $CREATE_FILE 2>&1

if [ -f /etc/issue ]
then
if [ `ls -alL /etc/issue | awk '{print $1}' | grep '........-.' | wc -l` -eq 1 ]
  then
    echo "● 2.09 결과 : 양호" >> $CREATE_FILE 2>&1
  else
    echo "● 2.09 결과 : 취약" >> $CREATE_FILE 2>&1
fi
else
 echo "● 2.09 결과 : 양호" >> $CREATE_FILE 2>&1
fi
echo "########################################################################################################" >> $CREATE_FILE 2>&1
echo "========================================================================================================" >> $CREATE_FILE 2>&1
echo "2.09 END" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1




echo "2.10 START" >> $CREATE_FILE 2>&1
echo "############################ 2.파일시스템 - 2.10 홈 디렉터리 권한 설정 #################################"
echo "############################ 2.파일시스템 - 2.10 홈 디렉터리 권한 설정 #################################" >> $CREATE_FILE 2>&1
echo "--------------------------------------------------------------------------------------------------------" >> $CREATE_FILE 2>&1
echo "■ 기준 : 홈 디렉터리에 타사용자 쓰기권한 없으면 양호" >> $CREATE_FILE 2>&1
echo "■ 현황" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
HOMEDIRS=`cat /etc/passwd | awk -F":" 'length($6) > 0 {print $6}' | sort -u | grep -v "#" | grep -v "/tmp" | grep -v "uucppublic" | uniq`

         for dir in $HOMEDIRS
          do
            ls -dal $dir | grep '\d.........' >> $CREATE_FILE 2>&1
         done
echo " " >> $CREATE_FILE 2>&1

echo " " > home.txt
HOMEDIRS=`cat /etc/passwd | awk -F":" 'length($6) > 0 {print $6}' | sort -u | grep -v "#" | grep -v "/tmp" | grep -v "uucppublic" | uniq`
         for dir in $HOMEDIRS
          do
               if [ -d $dir ]
               then
                if [ `ls -dal $dir | awk '{print $1}' | grep "........-." | wc -l` -eq 1 ]
                then
                  echo "● 2.10 결과 : 양호" >> home.txt
                 else
                  echo "● 2.10 결과 : 취약" >> home.txt
                fi
              else
                echo "● 2.10 결과 : 양호" >> home.txt
              fi
         done

if [ `cat home.txt | grep "취약" | wc -l` -eq 0 ]
 then
  echo "● 2.10 결과 : 양호" >> $CREATE_FILE 2>&1
 else
  echo "● 2.10 결과 : 취약" >> $CREATE_FILE 2>&1
fi

rm -rf home.txt
echo "#########################################################################################################" >> $CREATE_FILE 2>&1
echo "=========================================================================================================" >> $CREATE_FILE 2>&1
echo "2.10 END" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1






echo "2.11 START" >> $CREATE_FILE 2>&1
echo "############################ 2.파일시스템 - 2.11 홈디렉토리 환경변수 파일 권한 설정 ####################"
echo "############################ 2.파일시스템 - 2.11 홈디렉토리 환경변수 파일 권한 설정 ####################" >> $CREATE_FILE 2>&1
echo "--------------------------------------------------------------------------------------------------------" >> $CREATE_FILE 2>&1
echo "■ 기준 : 홈디렉토리 환경변수 파일이 타사용자에게 쓰기 권한이 없으면 양호" >> $CREATE_FILE 2>&1
echo "■ 현황" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
HOMEDIRS=`cat /etc/passwd | awk -F":" 'length($6) > 0 {print $6}' | sort -u | grep -v '/bin/false' | grep -v 'nologin' | grep -v "#"`
FILES=".profile .cshrc .kshrc .login .bash_profile .bashrc .bash_login .exrc .netrc .history .sh_history .bash_history .dtprofile"

for file in $FILES
  do
    FILE=$file
    if [ -f $FILE ]
      then
        ls -alL $FILE >> $CREATE_FILE 2>&1
    fi
  done

for dir in $HOMEDIRS
do
  for file in $FILES
  do
    FILE=$dir/$file
    if [ -f $FILE ]
      then
        ls -alL $FILE >> $CREATE_FILE 2>&1
    fi
  done
done
echo " " >> $CREATE_FILE 2>&1

echo " " > home2.txt

HOMEDIRS=`cat /etc/passwd | awk -F":" 'length($6) > 0 {print $6}' | sort -u | grep -v '/bin/false' | grep -v 'nologin' | grep -v "#"`
FILES=".profile .cshrc .kshrc .login .bash_profile .bashrc .bash_login .exrc .netrc .history .sh_history .bash_history .dtprofile"

for file in $FILES
          do
            if [ -f $file ]
             then
             if [ `ls -alL $file | awk '{print $1}' | grep "........-."| wc -l` -eq 1 ]
              then
                echo "● 2.11 결과 : 양호" >> home2.txt
              else
                echo "● 2.11 결과 : 취약" >> home2.txt
             fi
            else
              echo "● 2.11 결과 : 양호" >> home2.txt
            fi
         done

 for dir in $HOMEDIRS
    do
         for file in $FILES
          do
            if [ -f $dir/$file ]
             then
             if [ `ls -dal $dir/$file | awk '{print $1}' | grep "........-." | wc -l` -eq 1 ]
              then
                echo "● 2.11 결과 : 양호" >> home2.txt
              else
                echo "● 2.11 결과 : 취약" >> home2.txt
             fi
            else
              echo "● 2.11 결과 : 양호"  >> home2.txt
            fi
         done
    done

if [ `cat home2.txt | grep "취약" | wc -l` -eq 0 ]
 then
  echo "● 2.11 결과 : 양호" >> $CREATE_FILE 2>&1
 else
  echo "● 2.11 결과 : 취약" >> $CREATE_FILE 2>&1
fi

rm -rf home2.txt
echo "#########################################################################################################" >> $CREATE_FILE 2>&1
echo "=========================================================================================================" >> $CREATE_FILE 2>&1
echo "2.11 END" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1


echo "2.12 START" >> $CREATE_FILE 2>&1
echo "############################ 2.파일시스템 - 2.12 주요 디렉토리 파일 권한 설정 ##########################"
echo "############################ 2.파일시스템 - 2.12 주요 디렉토리 파일 권한 설정 ##########################" >> $CREATE_FILE 2>&1
echo "--------------------------------------------------------------------------------------------------------" >> $CREATE_FILE 2>&1
echo "■ 기준 : 주요 디렉터리(/sbin, /etc, /bin, /usr/bin, /usr/sbin, /usr/lbin)에 타사용자 쓰기권한이 없으면 양호" >> $CREATE_FILE 2>&1
echo "■ 현황" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
HOMEDIRS="/sbin /etc /bin /usr/bin /usr/sbin /usr/lbin"

         for dir in $HOMEDIRS
          do
            ls -dal $dir | grep '\d.........' >> $CREATE_FILE 2>&1
         done
echo " " >> $CREATE_FILE 2>&1

echo " " > home.txt
HOMEDIRS="/sbin /etc /bin /usr/bin /usr/sbin /usr/lbin"
         for dir in $HOMEDIRS
          do
               if [ -d $dir ]
               then
                if [ `ls -dal $dir | awk '{print $1}' | grep "........-." | wc -l` -eq 1 ]
                then
                  echo "● 2.12 결과 : 양호" >> home.txt
                 else
                  echo "● 2.12 결과 : 취약" >> home.txt
                fi
              else
                echo "● 2.12 결과 : 양호" >> home.txt
              fi
         done

if [ `cat home.txt | grep "취약" | wc -l` -eq 0 ]
 then
  echo "● 2.12 결과 : 양호" >> $CREATE_FILE 2>&1
 else
  echo "● 2.12 결과 : 취약" >> $CREATE_FILE 2>&1
fi

rm -rf home.txt
echo "########################################################################################################" >> $CREATE_FILE 2>&1
echo "========================================================================================================" >> $CREATE_FILE 2>&1
echo "2.12 END" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1




echo "2.13 START" >> $CREATE_FILE 2>&1
echo "############################ 2.파일시스템 - 2.13 PATH 환경변수 설정 ####################################"
echo "############################ 2.파일시스템 - 2.13 PATH 환경변수 설정 ####################################" >> $CREATE_FILE 2>&1
echo "--------------------------------------------------------------------------------------------------------" >> $CREATE_FILE 2>&1
echo "■ 기준 : 현재 위치를 의미하는 . 이 없거나, PATH 맨 뒤에 존재하면 양호" >> $CREATE_FILE 2>&1
echo "■ 현황" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo $PATH >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1

if [ `echo $PATH | grep "\.:" | wc -l` -eq 0 ]
  then
    echo "● 2.13 결과 : 양호" >> $CREATE_FILE 2>&1
  else
    echo "● 2.13 결과 : 취약" >> $CREATE_FILE 2>&1
fi
echo "########################################################################################################" >> $CREATE_FILE 2>&1
echo "========================================================================================================" >> $CREATE_FILE 2>&1
echo "2.13 END" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1



echo "2.14 START" >> $CREATE_FILE 2>&1
echo "############################ 2.파일시스템 - 2.14 FTP 접근제어 파일 권한 설정 ###########################"
echo "############################ 2.파일시스템 - 2.14 FTP 접근제어 파일 권한 설정 ###########################" >> $CREATE_FILE 2>&1
echo "--------------------------------------------------------------------------------------------------------" >> $CREATE_FILE 2>&1
echo "■ 기준 : ftpusers 파일이 타사용자 쓰기권한이 없으면 양호" >> $CREATE_FILE 2>&1
echo "■ 현황" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1

if [ -f /etc/ftpd/ftpusers ]
  then
   ls -alL /etc/ftpd/ftpusers  >> $CREATE_FILE 2>&1
  else
   echo "☞ /etc/ftpd/ftpusers 파일이 없습니다."  >> $CREATE_FILE 2>&1
fi

echo " " >> $CREATE_FILE 2>&1

if [ -f /etc/ftpusers ]
  then
   ls -alL /etc/ftpusers  >> $CREATE_FILE 2>&1
  else
   echo "☞ /etc/ftpusers 파일이 없습니다."  >> $CREATE_FILE 2>&1
fi
echo " " >> $CREATE_FILE 2>&1

if [ -f /etc/vsftpd/ftpusers ]
  then
   ls -alL /etc/vsftpd/ftpusers  >> $CREATE_FILE 2>&1
  else
   echo "☞ /etc/vsftpd/ftpusers 파일이 없습니다."  >> $CREATE_FILE 2>&1
fi

echo " " >> $CREATE_FILE 2>&1

if [ -f /etc/vsftpd/user_list ]
  then
   ls -alL /etc/vsftpd/user_list >> $CREATE_FILE 2>&1
  else
   echo "☞ /etc/vsftpd/user_list 파일이 없습니다."  >> $CREATE_FILE 2>&1
fi
echo " " >> $CREATE_FILE 2>&1

echo "  " > ftpusers.txt

if [ -f /etc/ftpd/ftpusers ]
      then
        if [ `ls -alL /etc/ftpd/ftpusers | awk '{print $1}' | grep '........-.' | wc -l` -eq 0 ]
          then
             echo "● 2.14 결과 : 취약" >> ftpusers.txt
          else
             echo "● 2.14 결과 : 양호" >> ftpusers.txt
        fi
      else
        if [ -f /etc/ftpusers ]
          then
            if [ `ls -alL /etc/ftpusers | awk '{print $1}' | grep '........-.'| wc -l` -eq 0 ]
              then
                echo "● 2.14 결과 : 취약" >> ftpusers.txt
              else
                echo "● 2.14 결과 : 양호" >> ftpusers.txt
            fi
          else
            echo "● 2.14 결과 : 양호"  >> ftpusers.txt
        fi
fi


if [ `ls -alL /etc/vsftpd/ftpusers | awk '{print $1}' | grep '........-.' | wc -l` -eq 0 ]
  then
    echo "● 2.14 결과 : 취약" >> ftpusers.txt
  else
    echo "● 2.14 결과 : 양호" >> ftpusers.txt
fi

if [ `ls -alL /etc/vsftpd/user_list | awk '{print $1}' | grep '........-.' | wc -l` -eq 0 ]
  then
    echo "● 2.14 결과 : 취약" >> ftpusers.txt
  else
    echo "● 2.14 결과 : 양호" >> ftpusers.txt
fi


if [ `cat ftpusers.txt | grep "양호" | wc -l` -gt 0 ]
 then
  echo "● 2.14 결과 : 양호" >> $CREATE_FILE 2>&1
 else
  echo "● 2.14 결과 : 취약" >> $CREATE_FILE 2>&1
fi

rm -rf ftpusers.txt
echo "########################################################################################################" >> $CREATE_FILE 2>&1
echo "========================================================================================================" >> $CREATE_FILE 2>&1
echo "2.14 END" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1




echo "2.15 START" >> $CREATE_FILE 2>&1
echo "############################ 2.파일시스템 - 2.15 root 원격 접근제어 파일 권한 설정  ####################"
echo "############################ 2.파일시스템 - 2.15 root 원격 접근제어 파일 권한 설정  ####################" >> $CREATE_FILE 2>&1
echo "--------------------------------------------------------------------------------------------------------" >> $CREATE_FILE 2>&1
echo "■ 기준 : /etc/pam.d/login 파일에 타사용자 쓰기권한이 없으면 양호" >> $CREATE_FILE 2>&1
echo "■ 현황" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
if [ -f /etc/pam.d/login ]
  then
   ls -alL /etc/pam.d/login  >> $CREATE_FILE 2>&1
  else
   echo " /etc/pam.d/login 파일이 없습니다."  >> $CREATE_FILE 2>&1
fi
echo " " >> $CREATE_FILE 2>&1

if [ -f /etc/pam.d/login ]
  then
    if [ `ls -alL /etc/pam.d/login | awk '{print $1}' | grep '........-.' | wc -l` -eq 0 ]
       then
          echo "● 2.15 결과 : 취약" >> $CREATE_FILE 2>&1
       else
          echo "● 2.15 결과 : 양호" >> $CREATE_FILE 2>&1
    fi
  else
   echo "● 2.15 결과 : 양호"  >> $CREATE_FILE 2>&1
fi
echo "########################################################################################################" >> $CREATE_FILE 2>&1
echo "========================================================================================================" >> $CREATE_FILE 2>&1
echo "2.15 END" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1



echo "2.16 START" >> $CREATE_FILE 2>&1
echo "############################ 2.파일시스템 - 2.16 NFS 접근제어 파일 권한 설정 ###########################"
echo "############################ 2.파일시스템 - 2.16 NFS 접근제어 파일 권한 설정 ###########################" >> $CREATE_FILE 2>&1
echo "--------------------------------------------------------------------------------------------------------" >> $CREATE_FILE 2>&1
echo "■ 기준 : /etc/exports 파일에  타사용자 쓰기권한 없으면 양호" >> $CREATE_FILE 2>&1
echo "■ 현황" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
if [ -f  /etc/exports ]
  then
   ls -alL /etc/exports  >> $CREATE_FILE 2>&1
  else
   echo " /etc/exports 파일이 없습니다"  >> $CREATE_FILE 2>&1
fi
echo " " >> $CREATE_FILE 2>&1
if [ -f /etc/exports ]
  then
   if [ `ls -alL /etc/exports | awk '{print $1}' | grep '........-.' | wc -l` -eq 1 ]
       then
          echo "● 2.16 결과 : 양호" >> $CREATE_FILE 2>&1
       else
          echo "● 2.16 결과 : 취약" >> $CREATE_FILE 2>&1
   fi
  else
   echo "● 2.16 결과 : 양호" >> $CREATE_FILE 2>&1
fi
echo "########################################################################################################" >> $CREATE_FILE 2>&1
echo "========================================================================================================" >> $CREATE_FILE 2>&1
echo "2.16 END" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1




echo "2.17 START" >> $CREATE_FILE 2>&1
echo "############################ 2.파일시스템 - 2.17 서비스 파일 권한 설정 #################################"
echo "############################ 2.파일시스템 - 2.17 서비스 파일 권한 설정 #################################" >> $CREATE_FILE 2>&1
echo "--------------------------------------------------------------------------------------------------------" >> $CREATE_FILE 2>&1
echo "■ 기준 : /etc/services 파일에 타사용자에게 쓰기권한이 없으면 양호" >> $CREATE_FILE 2>&1
echo "■ 현황" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
if [ -f /etc/services ]
  then
   ls -alL /etc/services  >> $CREATE_FILE 2>&1
  else
   echo " /etc/services 파일이 없습니다"  >> $CREATE_FILE 2>&1
fi
echo " " >> $CREATE_FILE 2>&1

if [ -f /etc/services ]
 then
  if [ `ls -alL /etc/services | awk '{print $1}' | grep '........-.' | wc -l` -eq 1 ]
      then
        echo "● 2.17 결과 : 양호" >> $CREATE_FILE 2>&1
      else
        echo "● 2.17 결과 : 취약" >> $CREATE_FILE 2>&1
  fi
 else
  echo "● 2.17 결과 : 양호" >> $CREATE_FILE 2>&1
fi
echo "########################################################################################################" >> $CREATE_FILE 2>&1
echo "========================================================================================================" >> $CREATE_FILE 2>&1
echo "2.17 END" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1




echo "2.18 START" >> $CREATE_FILE 2>&1
echo "############################ 2.파일시스템 - 2.18 기타 중요파일 권한 설정 ###############################"
echo "############################ 2.파일시스템 - 2.18 기타 중요파일 권한 설정 ###############################" >> $CREATE_FILE 2>&1
echo "--------------------------------------------------------------------------------------------------------" >> $CREATE_FILE 2>&1
echo "■ 기준 : 기타 중요파일에 타사용자에게 쓰기권한이 없으면 양호" >> $CREATE_FILE 2>&1
echo "■ 현황" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1

DIR744="/etc/rc*.d/* /etc/inittab /etc/syslog.conf /etc/snmp/conf/snmpd.conf"

for check_dir in $DIR744
do

  if [ -f $check_dir ]
    then
      ls -alL $check_dir >> $CREATE_FILE 2>&1
    else
      echo $check_dir " 이 없습니다" >> $CREATE_FILE 2>&1
  fi
done
echo " " >> $CREATE_FILE 2>&1

DIR744="/etc/rc*.d/* /etc/inittab /etc/syslog.conf /etc/snmp/conf/snmpd.conf"

echo " " >> etcfiles.txt 2>&1
for check_dir in $DIR744
do

  if [  `ls -alL $check_dir | awk '{print $1}' | grep  '........w.' | wc -l` -eq 0 ]
    then
      echo "● 2.18 결과 : 양호" >> etcfiles.txt 2>&1
    else
      echo "● 2.18 결과 : 취약" >> etcfiles.txt 2>&1
  fi
done

if [ `cat etcfiles.txt | grep "취약" | wc -l` -eq 0 ]
 then
  echo "● 2.18 결과 : 양호" >> $CREATE_FILE 2>&1
 else
  echo "● 2.18 결과 : 취약" >> $CREATE_FILE 2>&1
fi

rm -rf etcfiles.txt
echo "########################################################################################################" >> $CREATE_FILE 2>&1
echo "========================================================================================================" >> $CREATE_FILE 2>&1
echo "2.18 END" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1


echo "2.19 START" >> $CREATE_FILE 2>&1
echo "############################ 2.파일시스템 - 2.19 at 관련 파일의 접근제한 ###############################"
echo "############################ 2.파일시스템 - 2.19 at 관련 파일의 접근제한 ###############################" >> $CREATE_FILE 2>&1
echo "--------------------------------------------------------------------------------------------------------" >> $CREATE_FILE 2>&1
echo "■ 기준 : /etc/cron/at.deny 파일의 소유자가 root 이고 퍼미션이 640 이하일 경우" >> $CREATE_FILE 2>&1
echo "■ 현황" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
if [ -f /etc/cron/at.deny ]
  then
   ls -alL /etc/cron/at.deny  >> $CREATE_FILE 2>&1
  else
   echo " /etc/cron/at.deny 파일이 없습니다"  >> $CREATE_FILE 2>&1
fi

echo " " >> $CREATE_FILE 2>&1
ls -al /etc/cron/at.deny >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1


if [ `ls -alL /etc/cron/at.deny | awk '{print $1}' | grep ".rw-r-----" | wc -l` -eq 1 -a `ls -al /etc/cron/at.deny | grep "root" | wc -l` -eq 1 -o `ls -al /etc/cron/at.deny | wc -l` -eq 0 ]
  then
    echo "● 2.19 결과 : 양호" >> $CREATE_FILE 2>&1
  else
    echo "● 2.19 결과 : 취약" >> $CREATE_FILE 2>&1
fi

echo "########################################################################################################" >> $CREATE_FILE 2>&1
echo "========================================================================================================" >> $CREATE_FILE 2>&1
echo "2.19 END" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1



echo "3.01 START" >> $CREATE_FILE 2>&1
echo "############################ 3.네트워크 서비스 - 3.1 RPC 서비스 설정 ###################################"
echo "############################ 3.네트워크 서비스 - 3.1 RPC 서비스 설정 ###################################" >> $CREATE_FILE 2>&1
echo "--------------------------------------------------------------------------------------------------------" >> $CREATE_FILE 2>&1
echo "■ 기준 : 불필요한 rpc 관련 서비스가 존재하지 않으면 양호" >> $CREATE_FILE 2>&1
echo "■ 현황" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
SERVICE_INETD="rpc.cmsd|rpc.ttdbserverd|sadmind|rusersd|walld|sprayd|rstatd|rpc.nisd|rpc.pcnfsd|rpc.statd|rpc.ypupdated|rpc.rquotad|kcms_server|cachefsd|rexd"

if [ -d /etc/xinetd.d ]
  then
    if [ `ls -alL /etc/xinetd.d | egrep $SERVICE_INETD | wc -l` -eq 0 ]
      then
        echo "☞ /etc/xinetd.d 디렉토리에 불필요한 서비스가 없습니다." >> $CREATE_FILE 2>&1
      else
        ls -alL /etc/xinetd.d | egrep $SERVICE_INETD >> $CREATE_FILE 2>&1
    fi
  else
     echo "☞ /etc/xinetd.d 디렉토리가 존재하지 않습니다. " >> $CREATE_FILE 2>&1
fi

echo " " >> $CREATE_FILE 2>&1

if [ -f /etc/inetd.conf ]
  then
    cat /etc/inetd.conf | grep -v '^ *#' | egrep $SERVICE_INETD >> $CREATE_FILE 2>&1
  else
    echo "☞ /etc/inetd.conf 파일이 존재하지 않습니다. " >> $CREATE_FILE 2>&1
fi
echo " " >> $CREATE_FILE 2>&1

echo " " > rpc.txt

SERVICE_INETD="rpc.cmsd|rpc.ttdbserverd|sadmind|rusersd|walld|sprayd|rstatd|rpc.nisd|rpc.pcnfsd|rpc.statd|rpc.ypupdated|rpc.rquotad|kcms_server|cachefsd|rexd"

if [ -d /etc/xinetd.d ]
  then
   if [ `ls -alL /etc/xinetd.d | egrep $SERVICE_INETD | wc -l` -gt 0 ]
    then
       for VVV in `ls -alL /etc/xinetd.d | egrep $SERVICE_INETD`
        do
        if [ `cat $VVV | grep -i "disable" | grep -i "no" | wc -l` -gt 0 ]
          then
           echo "● 3.01 결과 : 취약" >> rpc.txt
          else
           echo "● 3.01 결과 : 양호" >> rpc.txt
        fi
        done
    else
      echo "● 3.01 결과 : 양호" >> rpc.txt
    fi
elif [ -f /etc/inetd.conf ]
  then
    if [ `cat /etc/inetd.conf | grep -v '^ *#' | egrep $SERVICE_INETD | wc -l` -eq 0 ]
              then
                 echo "● 3.01 결과 : 양호" >> rpc.txt
              else
                 echo "● 3.01 결과 : 취약" >> rpc.txt
    fi
  else
   :
fi


if [ `cat rpc.txt | grep "취약" | wc -l` -eq 0 ]
 then
  echo "● 3.01 결과 : 양호" >> $CREATE_FILE 2>&1
 else
  echo "● 3.01 결과 : 취약" >> $CREATE_FILE 2>&1
fi

rm -rf rpc.txt
echo "########################################################################################################" >> $CREATE_FILE 2>&1
echo "========================================================================================================" >> $CREATE_FILE 2>&1
echo "3.01 END" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1




echo "3.02 START" >> $CREATE_FILE 2>&1
echo "############################ 3.네트워크 서비스 - 3.2 NFS 설정  #########################################"
echo "############################ 3.네트워크 서비스 - 3.2 NFS 설정  #########################################" >> $CREATE_FILE 2>&1
echo "--------------------------------------------------------------------------------------------------------" >> $CREATE_FILE 2>&1
echo "■ 기준 : 파일 시스템에 대한 호스트별 권한 설정이 되어 있거나 NFS 서비스가 운영되지 않거나 /etc/exports !=everyone 일 경우에 양호" >> $CREATE_FILE 2>&1
echo "■ 현황" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo "① NFS 데몬(nfsd)확인" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
if [ `ps -ef | grep "nfsd" | egrep -v "statdaemon|automountd|emi" | grep -v "grep" | wc -l` -gt 0 ]
 then
   ps -ef | grep "nfsd" | egrep -v "statdaemon|automountd|emi" | grep -v "grep"  >> $CREATE_FILE 2>&1
 else
   echo "☞ NFS 서비스가 비실행중입니다."  >> $CREATE_FILE 2>&1
fi
echo " " >> $CREATE_FILE 2>&1

if [ `ls -al /etc/rc*.d/* | grep -i nfs | grep "/S" | wc -l` -gt 0 ]
 then
   ls -al /etc/rc*.d/* | grep -i nfs | grep "/S"  >> $CREATE_FILE 2>&1
 else
   echo "☞ 시작스크립트 파일이 없습니다."  >> $CREATE_FILE 2>&1
fi
echo " " >> $CREATE_FILE 2>&1

echo "② /etc/exports 파일 내용" >> $CREATE_FILE 2>&1
if [ -f /etc/exports ]
  then
    grep -v '^ *#' /etc/exports  >> $CREATE_FILE 2>&1
  else
    echo "☞ /etc/exports 파일이 존재하지 않습니다."  >> $CREATE_FILE 2>&1
fi

echo " " >> $CREATE_FILE 2>&1

if [ `ps -ef | egrep "nfsd" | egrep -v "statdaemon|automountd|emi" | grep -v "grep" | wc -l` -eq 0 ]
 then
  echo "● 3.02 결과 : 양호" >> $CREATE_FILE 2>&1
 else
  if [ -f /etc/exports ]
    then
     if [ `cat /etc/exports | grep everyone | grep -v "#" | wc -l` -eq 0 ]
       then
         echo "● 3.02 결과 : 양호" >> $CREATE_FILE 2>&1
       else
         echo "● 3.02 결과 : 미점검" >> $CREATE_FILE 2>&1
     fi
    else
     echo "● 3.02 결과 : 양호"  >> $CREATE_FILE 2>&1
  fi
fi
echo "########################################################################################################" >> $CREATE_FILE 2>&1
echo "========================================================================================================" >> $CREATE_FILE 2>&1
echo "3.02 END" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1




echo "3.03 START" >> $CREATE_FILE 2>&1
echo "############################ 3.네트워크 서비스 - 3.3 원격 마운트 시스템 확인 ###########################"
echo "############################ 3.네트워크 서비스 - 3.3 원격 마운트 시스템 확인 ###########################" >> $CREATE_FILE 2>&1
echo "--------------------------------------------------------------------------------------------------------" >> $CREATE_FILE 2>&1
echo "■ 기준 : NFS 가 중지되어 있거나 원격에서 마운트하고 있는 시스템이 인가된 시스템일 경우이면 양호" >> $CREATE_FILE 2>&1
echo "■ 현황" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo "① NFS 데몬(nfsd)확인" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
if [ `ps -ef | grep "nfsd" | egrep -v "statdaemon|automountd|emi" | grep -v "grep" | wc -l` -gt 0 ]
  then
    ps -ef | grep "nfsd" | egrep -v "statdaemon|automountd|emi" | grep -v "grep"  >> $CREATE_FILE 2>&1
  else
    echo "☞ NFS 서비스가 비실행중입니다."  >> $CREATE_FILE 2>&1
fi
echo " " >> $CREATE_FILE 2>&1

if [ `ps -ef | grep nfsd | egrep -v "statdaemon|automountd|emi" | grep -v "grep" | wc -l` -gt 0 ]
 then
   echo "② NFS를 원격에서 mount하고 있는 시스템을 확인 " >> $CREATE_FILE 2>&1
   showmount  >> $CREATE_FILE 2>&1
 else
   echo "☞ NFS를 원격에서 mount하고 있는 시스템이 없습니다. " >> $CREATE_FILE 2>&1
fi
echo " " >> $CREATE_FILE 2>&1

if [ `ps -ef | grep "nfsd" | egrep -v "statdaemon|automountd|emi" | grep -v "grep" | wc -l` -eq 0 ]
  then
    echo "● 3.03 결과 : 양호" >> $CREATE_FILE 2>&1
  else
    echo "● 3.03 결과 : 미점검" >> $CREATE_FILE 2>&1
fi
echo "########################################################################################################" >> $CREATE_FILE 2>&1
echo "========================================================================================================" >> $CREATE_FILE 2>&1
echo "3.03 END" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1



echo "3.04 START" >> $CREATE_FILE 2>&1
echo "############################ 3.네트워크 서비스 - 3.4 statd, lockd 제거  ################################"
echo "############################ 3.네트워크 서비스 - 3.4 statd, lockd 제거  ################################" >> $CREATE_FILE 2>&1
echo "--------------------------------------------------------------------------------------------------------" >> $CREATE_FILE 2>&1
echo "■ 기준 : statd 및 lockd 데몬이 없거나 시작 스크립트 파일이 없으면 양호" >> $CREATE_FILE 2>&1
echo "■ 현황" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo "① NFS 데몬(statd,lockd)확인" >> $CREATE_FILE 2>&1
if [ `ps -ef | egrep "statd|lockd" | egrep -v "grep|rpc|statdaemon|emi|kblockd" | wc -l` -gt 0 ]
   then
       ps -ef | egrep "statd|lockd" | egrep -v "grep|rpc|statdaemon|emi|kblockd" >> $CREATE_FILE 2>&1
  else
    echo "☞ NFS 데몬(statd,lockd)이 비실행중입니다. " >> $CREATE_FILE 2>&1
fi
echo " " >> $CREATE_FILE 2>&1

echo "② nfs.client 서비스 시작 스크립트 확인" >> $CREATE_FILE 2>&1
if [ `ls -alL /etc/rc2.d | grep "\<S.*nfs.client" | wc -l` -eq 0 ]
 then
   echo "☞ 시작 스크립트가 없습니다. " >> $CREATE_FILE 2>&1
 else
   ls -alL /etc/rc2.d | grep "\<S.*nfs.client" >> $CREATE_FILE 2>&1
fi
echo " " >> $CREATE_FILE 2>&1
if [ `ps -ef | egrep "statd|lockd" | egrep -v "grep|rpc|statdaemon|emi|kblockd"| wc -l` -eq 0 ]
  then
    echo "● 3.04 결과 : 양호" >> $CREATE_FILE 2>&1
  else
    echo "● 3.04 결과 : 취약" >> $CREATE_FILE 2>&1
fi
echo "########################################################################################################" >> $CREATE_FILE 2>&1
echo "========================================================================================================" >> $CREATE_FILE 2>&1
echo "3.04 END" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1




echo "3.05 START" >> $CREATE_FILE 2>&1
echo "############################ 3.네트워크 서비스 - 3.5 Automountd 중지 ###################################"
echo "############################ 3.네트워크 서비스 - 3.5 Automountd 중지 ###################################" >> $CREATE_FILE 2>&1
echo "--------------------------------------------------------------------------------------------------------" >> $CREATE_FILE 2>&1
echo "■ 기준 : automount 서비스가 구동중이지 않을 경우에 양호" >> $CREATE_FILE 2>&1
echo "■ 현황" >> $CREATE_FILE 2>&1
echo "  " >> $CREATE_FILE 2>&1
echo "☞ Automount 데몬 확인 " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
if [ `ps -ef | grep automount | egrep -v "grep|rpc|statdaemon|emi" | wc -l` -gt 0 ]
  then
    ps -ef | grep automount | egrep -v "grep|rpc|statdaemon|emi" >> $CREATE_FILE 2>&1
  else
    echo "☞ Automount 서비스가 비실행중입니다. " >> $CREATE_FILE 2>&1
fi
echo " " >> $CREATE_FILE 2>&1

if [ `ls -al /etc/rc*.d/* | grep -i auto | grep "/S" | wc -l` -gt 0 ]
 then
   ls -al /etc/rc*.d/* | grep -i auto | grep "/S" | grep -v autoinstall  >> $CREATE_FILE 2>&1
 else
   echo "☞ Automount 서비스가 비실행중입니다. "  >> $CREATE_FILE 2>&1
fi
echo " " >> $CREATE_FILE 2>&1

if [ `ps -ef | grep automount | egrep -v "grep|rpc|statdaemon|emi" | wc -l` -eq 0 ]
  then
     echo "● 3.05 결과 : 양호" >> $CREATE_FILE 2>&1
  else
     echo "● 3.05 결과 : 취약" >> $CREATE_FILE 2>&1
fi

echo "########################################################################################################" >> $CREATE_FILE 2>&1
echo "========================================================================================================" >> $CREATE_FILE 2>&1
echo "3.05 END" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1




echo "3.06 START" >> $CREATE_FILE 2>&1
echo "############################ 3.네트워크 서비스 - 3.6 NIS, NIS+ 점검 ####################################"
echo "############################ 3.네트워크 서비스 - 3.6 NIS, NIS+ 점검 ####################################" >> $CREATE_FILE 2>&1
echo "--------------------------------------------------------------------------------------------------------" >> $CREATE_FILE 2>&1
echo "■ 기준 : NIS, NIS+ 서비스가 구동중이지 않을 경우에 양호" >> $CREATE_FILE 2>&1
echo "■ 현황" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
SERVICE="ypserv|ypbind|ypxfrd|rpc.yppasswdd|rpc.ypupdated"

if [ `ps -ef | egrep $SERVICE | grep -v "grep" | wc -l` -eq 0 ]
   then
    echo "☞ NIS, NIS+ 서비스가 비실행중입니다." >> $CREATE_FILE 2>&1
   else
    ps -ef | egrep $SERVICE | grep -v "grep" >> $CREATE_FILE 2>&1
fi

echo " " >> $CREATE_FILE 2>&1

SERVICE="ypserv|ypbind|ypxfrd|rpc.yppasswdd|rpc.ypupdated"

if [ `ps -ef | egrep $SERVICE | grep -v "grep" | wc -l` -eq 0 ]
     then
        echo "● 3.06 결과 : 양호" >> $CREATE_FILE 2>&1
     else
        echo "● 3.06 결과 : 취약" >> $CREATE_FILE 2>&1
fi

echo "########################################################################################################" >> $CREATE_FILE 2>&1
echo "========================================================================================================" >> $CREATE_FILE 2>&1
echo "3.06 END" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1



echo "3.07 START" >> $CREATE_FILE 2>&1
echo "############################ 3.네트워크 서비스 - 3.7 ‘r’ commands 설정 #################################"
echo "############################ 3.네트워크 서비스 - 3.7 ‘r’ commands 설정 #################################" >> $CREATE_FILE 2>&1
echo "--------------------------------------------------------------------------------------------------------" >> $CREATE_FILE 2>&1
echo "■ 기준 : login, shell, exec 서비스가 구동중이지 않을 경우" >> $CREATE_FILE 2>&1
echo "■ 현황" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
SERVICE_INETD="rsh|rlogin|rexec"
echo " " >> $CREATE_FILE 2>&1

echo "☞ /etc/xinetd.d 내용 " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
if [ `ls -alL /etc/xinetd.d | egrep $SERVICE_INETD | wc -l` -gt 0 ]
  then
     for VVV in `ls -alL /etc/xinetd.d | egrep $SERVICE_INETD | grep -v "ssf" | awk '{print $9}'`
        do
         echo " $VVV 파일" >> $CREATE_FILE 2>&1
         cat /etc/xinetd.d/$VVV | grep -i "disable" >> $CREATE_FILE 2>&1
         echo "   " >> $CREATE_FILE 2>&1
        done
  else
      echo " xinetd.d에 파일이 없습니다" >> $CREATE_FILE 2>&1
fi

echo " " >> $CREATE_FILE 2>&1

if [ -d /etc/xinetd.d ]
  then
   SERVICE_INETD="rsh|rlogin|rexec"
   if [ `ls -alL /etc/xinetd.d | egrep $SERVICE_INETD | wc -l` -gt 0 ]
    then
       for VVV in `ls -alL /etc/xinetd.d | egrep $SERVICE_INETD | awk '{print $9}'`
        do
        if [ `cat /etc/xinetd.d/$VVV | grep -i "disable" | grep -i "no" | wc -l` -gt 0 ]
          then
           echo "● 3.07 결과 : 취약" >> $CREATE_FILE 2>&1
          else
           echo "● 3.07 결과 : 양호" >> $CREATE_FILE 2>&1
        fi
        done
    else
      echo "● 3.07 결과 : 양호" >> $CREATE_FILE 2>&1
    fi
 elif [ -f /etc/inetd.conf ]
  then
    if [ `cat /etc/inetd.conf | grep -v '^ *#' | egrep $SERVICE_INETD | egrep -v "grep|klogin|kshell|kexec" |wc -l` -eq 0 ]
     then
        echo "● 3.07 결과 : 양호" >> $CREATE_FILE 2>&1
     else
        echo "● 3.07 결과 : 취약" >> $CREATE_FILE 2>&1
    fi
  else
     echo "● 3.07 결과 : 양호" >> $CREATE_FILE 2>&1
fi
echo "########################################################################################################" >> $CREATE_FILE 2>&1
echo "========================================================================================================" >> $CREATE_FILE 2>&1
echo "3.07 END" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1




echo "3.08 START" >> $CREATE_FILE 2>&1
echo "############################ 3.네트워크 서비스 - 3.8 신뢰관계 설정 #####################################"
echo "############################ 3.네트워크 서비스 - 3.8 신뢰관계 설정 #####################################" >> $CREATE_FILE 2>&1
echo "--------------------------------------------------------------------------------------------------------" >> $CREATE_FILE 2>&1
echo "■ 기준 : r 서비스가 구동중이지 않거나 설정 파일에 + 가 존재하지 않으면 양호" >> $CREATE_FILE 2>&1
echo "■ 현황" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
HOMEDIRS=`cat /etc/passwd | awk -F":" 'length($6) > 0 {print $6}' | sort -u`
FILES="/.rhosts"

if [ -s r_temp ]
then
 if [ -f /etc/hosts.equiv ]
 then
  echo "① /etc/hosts.equiv 파일 설정 내용" >> $CREATE_FILE 2>&1
  cat /etc/hosts.equiv >> $CREATE_FILE 2>&1
 else
  echo "① /etc/hosts.equiv 파일 설정 내용" >> $CREATE_FILE 2>&1
  echo " ☞ /etc/hosts.equiv 파일이 없습니다." >> $CREATE_FILE 2>&1
 fi
 echo " " >> $CREATE_FILE 2>&1

 echo "② 사용자 home directory .rhosts 설정 내용" >> $CREATE_FILE 2>&1

   for dir in $HOMEDIRS
   do
     for file in $FILES
     do
       if [ -f $dir$file ]
       then
        echo "☞ $dir$file 설정 내용" >> $CREATE_FILE 2>&1
        cat $dir$file | grep -v "#" >> $CREATE_FILE 2>&1
        echo " " >> $CREATE_FILE 2>&1
       fi
      done
   done
else
 echo "☞ 'r' command 서비스가 구동중이지 않습니다." >> $CREATE_FILE 2>&1
fi

echo " " >> $CREATE_FILE 2>&1
echo " " > trust.txt

if [ -f /etc/inetd.conf ]
  then
  if [ -s r_temp ]
   then
       if [ -f /etc/hosts.equiv ]
       then
              if [ `cat /etc/hosts.equiv | grep "+" | grep -v "grep" | grep -v "#" | wc -l ` -eq 0 ]
               then
                 echo "● 3.08 결과 : 양호" >> trust.txt
               else
                 echo "● 3.08 결과 : 취약" >> trust.txt
              fi
        else
         echo "● 3.08 결과 : 양호" >> trust.txt
        fi

	for dir in $HOMEDIRS
	do
	  for file in $FILES
	  do
	    if [ -f $dir$file ]
	      then
	        if [ `cat $dir$file | grep "+" | grep -v "grep" | grep -v "#" |wc -l ` -eq 0 ]
	         then
	          echo "● 3.08 결과 : 양호" >> trust.txt
	         else
	          echo "● 3.08 결과 : 취약" >> trust.txt
	        fi
	      else
	      echo "● 3.08 결과 : 양호" >> trust.txt
	    fi
	  done
	done
    else
     echo "● 3.08 결과 : 양호" >> trust.txt
    fi
  else
  echo "● 3.08 결과 : 양호" >> trust.txt
fi

if [ `cat trust.txt | grep "취약" | wc -l` -eq 0 ]
 then
  echo "● 3.08 결과 : 양호" >> $CREATE_FILE 2>&1
 else
  echo "● 3.08 결과 : 취약" >> $CREATE_FILE 2>&1
fi

rm -rf trust.txt r_temp
echo "#########################################################################################################" >> $CREATE_FILE 2>&1
echo "=========================================================================================================" >> $CREATE_FILE 2>&1
echo "3.08 END" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1




echo "3.09 START" >> $CREATE_FILE 2>&1
echo "############################ 3.네트워크 서비스 - 3.9 hosts.equiv 파일 권한 설정 ########################" 
echo "############################ 3.네트워크 서비스 - 3.9 hosts.equiv 파일 권한 설정 ########################" >> $CREATE_FILE 2>&1
echo "--------------------------------------------------------------------------------------------------------" >> $CREATE_FILE 2>&1
echo "■ 기준 : /etc/hosts.equiv의 파일권한이 400 또는 600이면 양호 " >> $CREATE_FILE 2>&1
echo "■ 현황" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
if [ -f /etc/hosts.equiv ]
then
 ls -al /etc/hosts.equiv >> $CREATE_FILE 2>&1
else
 echo "☞ /etc/hosts.equiv 파일이 없습니다." >> $CREATE_FILE 2>&1
fi
echo " " >> $CREATE_FILE 2>&1

if [ -f /etc/hosts.equiv ]
then
    if [ `ls -al /etc/hosts.equiv | awk '{print $1}' | grep '...-------' | wc -l ` -eq 1 ]
     then
       echo "● 3.09 결과 : 양호" >> $CREATE_FILE 2>&1
     else
       if [ `ls -al /etc/hosts.equiv | grep '\/dev\/null' | wc -l` -eq 1 ]
          then
           echo "● 3.09 결과 : 양호" >> $CREATE_FILE 2>&1
          else
           echo "● 3.09 결과 : 취약" >> $CREATE_FILE 2>&1
       fi
    fi
else
  echo "● 3.09 결과 : 양호" >> $CREATE_FILE 2>&1
fi
echo "########################################################################################################" >> $CREATE_FILE 2>&1
echo "========================================================================================================" >> $CREATE_FILE 2>&1
echo "3.09 END" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1




echo "3.10 START" >> $CREATE_FILE 2>&1
echo "############################ 3.네트워크 서비스 - 3.10 .rhosts 파일 권한 설정 ###########################"
echo "############################ 3.네트워크 서비스 - 3.10 .rhosts 파일 권한 설정 ###########################" >> $CREATE_FILE 2>&1
echo "--------------------------------------------------------------------------------------------------------" >> $CREATE_FILE 2>&1
echo "■ 기준 : .rhost의 파일권한이 400 또는 600 이거나 존재하지 않을 경우 양호 " >> $CREATE_FILE 2>&1
echo "■ 현황" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
HOMEDIRS=`cat /etc/passwd | awk -F":" 'length($6) > 0 {print $6}' | sort -u`
FILES="/.rhosts"

for dir in $HOMEDIRS
   do
     for file in $FILES
     do
       if [ -f $dir$file ]
       then
        echo "☞ $dir/.rhosts 파일 권한" >> $CREATE_FILE 2>&1
        ls -al $dir$file  >> $CREATE_FILE 2>&1
        echo " " >> $CREATE_FILE 2>&1
       fi
      done
   done
   
echo "  " > rhosts.txt

for dir in $HOMEDIRS
do
  for file in $FILES
  do
    if [ -f $dir$file ]
     then
       if [ `ls -al $dir$file | awk '{print $1}' | grep '...-------' | wc -l` -eq 1 ]
       then
         echo "● 3.10 결과 : 양호" >> rhosts.txt
       else
         if [ `ls -al $dir$file | grep '\/dev\/null' | wc -l` -eq 1 ]
          then
           echo "● 3.10 결과 : 양호" >> rhosts.txt
          else
           echo "● 3.10 결과 : 취약" >> rhosts.txt
         fi
       fi
     else
       echo "● 3.10 결과 : 양호" >> rhosts.txt
     fi
  done
done


if [ `cat rhosts.txt | grep "취약" | wc -l` -gt 0 ]
 then
  echo "● 3.10 결과 : 취약" >> $CREATE_FILE 2>&1
 else
  echo "● 3.10 결과 : 양호" >> $CREATE_FILE 2>&1
fi

rm -rf rhosts.txt
echo "########################################################################################################" >> $CREATE_FILE 2>&1
echo "========================================================================================================" >> $CREATE_FILE 2>&1
echo "3.10 END" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1





echo "3.11 START" >> $CREATE_FILE 2>&1
echo "############################ 3.네트워크 서비스 - 3.11 기타 서비스 설정 #################################"
echo "############################ 3.네트워크 서비스 - 3.11 기타 서비스 설정 #################################" >> $CREATE_FILE 2>&1
echo "--------------------------------------------------------------------------------------------------------" >> $CREATE_FILE 2>&1
echo "■ 기준 : 불필요한 서비스가 사용되고 있지 않으면 양호 " >> $CREATE_FILE 2>&1
echo "■ 현황" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
SERVICE_INETD="echo|discard|daytime|chargen|time|tftp|finger|sftp|uucp-path|nntp|ntp|netbios_ns|netbios_dgm|netbios_ssn|bftp|ldap|printer|talk|ntalk|uucp|pcserver|ldaps|ingreslock|www-ldap-gw|nfsd|dtspcd"

echo "☞ /etc/inetd.conf 내용" >> $CREATE_FILE 2>&1
echo "-----------------------" >> $CREATE_FILE 2>&1
if cat /etc/inetd.conf | grep -v '^#' | egrep '^echo|^discard|^daytime|^chargen|^time|^tftp|^finger|^sftp|^uucp-path|^nntp|^ntp|^netbios_ns|^netbios_dgm|^netbios_ssn|^bftp|^ldap|^printer|^talk|^ntalk|^uucp|^pcserver|^ldaps|^ingreslock|^www-ldap-gw|^nfsd|^dtspcd' ; then
 cat /etc/inetd.conf | grep -v '^#' | egrep '^echo|^discard|^daytime|^chargen|^time|^tftp|^finger|^sftp|^uucp-path|^nntp|^ntp|^netbios_ns|^netbios_dgm|^netbios_ssn|^bftp|^ldap|^printer|^talk|^ntalk|^uucp|^pcserver|^ldaps|^ingreslock|^www-ldap-gw|^nfsd|^dtspcd' >> $CREATE_FILE 2>&1
else
 echo "☞ 불필요한 서비스가 존재하지 않습니다." >> $CREATE_FILE 2>&1
fi
echo " " >> $CREATE_FILE 2>&1
echo "☞ /etc/xinetd.d 내용 " >> $CREATE_FILE 2>&1
echo "--------------------- " >> $CREATE_FILE 2>&1
if [ `ls -alL /etc/xinetd.d | egrep $SERVICE_INETD | wc -l` -gt 0 ]
  then
     for VVV in `ls -alL /etc/xinetd.d | egrep $SERVICE_INETD | grep -v "ssf" | awk '{print $9}'`
        do
         echo " $VVV 파일" >> $CREATE_FILE 2>&1
         cat /etc/xinetd.d/$VVV | grep -i "disable" >> $CREATE_FILE 2>&1
         echo "   " >> $CREATE_FILE 2>&1
        done
  else
      echo "☞ xinetd.d에 파일이 없습니다" >> $CREATE_FILE 2>&1
fi

echo " " >> $CREATE_FILE 2>&1

echo " " > service.txt

if [ -f /etc/inetd.conf ]
 then
  if [ `cat /etc/inetd.conf | grep -v '^ *#' | egrep $SERVICE_INETD | wc -l ` -eq 0 ]
      then
       echo "● 3.11 결과 : 양호" >> service.txt
      else
       echo "● 3.11 결과 : 취약" >> service.txt
  fi
 else
  echo "● 3.11 결과 : 양호" >> service.txt
fi

if [ -d /etc/xinetd.d ]
  then
   if [ `ls -alL /etc/xinetd.d | egrep $SERVICE_INETD | wc -l` -gt 0 ]
    then
       for VVV in `ls -alL /etc/xinetd.d | egrep $SERVICE_INETD | grep -v "ssf" | awk '{print $9}'`
        do
        if [ `cat /etc/xinetd.d/$VVV | grep -i "disable" | grep -i "no" | wc -l` -gt 0 ]
          then
           echo "● 3.11 결과 : 취약" >> service.txt
          else
           echo "● 3.11 결과 : 양호" >> service.txt
        fi
        done
    else
      echo "● 3.11 결과 : 양호" >> service.txt
    fi
  else
    echo "● 3.11 결과 : 양호" >> service.txt
fi

if [ `cat service.txt | grep "취약" | wc -l` -eq 0 ]
 then
  echo "● 3.11 결과 : 양호" >> $CREATE_FILE 2>&1
 else
  echo "● 3.11 결과 : 취약" >> $CREATE_FILE 2>&1
fi

rm -rf service.txt
echo "########################################################################################################" >> $CREATE_FILE 2>&1
echo "========================================================================================================" >> $CREATE_FILE 2>&1
echo "3.11 END" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1





echo "3.12 START" >> $CREATE_FILE 2>&1
echo "############################ 3.네트워크 서비스 - 3.12 서비스 Banner 관리 ###############################"
echo "############################ 3.네트워크 서비스 - 3.12 서비스 Banner 관리 ###############################" >> $CREATE_FILE 2>&1
echo "--------------------------------------------------------------------------------------------------------" >> $CREATE_FILE 2>&1
echo "■ 기준 : Telnet, FTP, SMTP, DNS가 구동 중이지 않거나 배너에 O/S 및 버전 정보가 없을 경우 양호" >> $CREATE_FILE 2>&1
echo "■ 현황" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1

if [ `rpm -qa | grep telnet | wc -l` -eq 0 -a `ps -ef | grep bind | grep -v "grep" | wc -l` -eq 0 -a `ps -ef | grep ftp | grep -v "grep" | wc -l` -eq 0 -a `ps -ef | grep sendmail | grep -v "grep" | wc -l` -eq 0 ]
  then
    echo "Telnet, FTP, SMTP, DNS 서비스가 사용중이지 않습니다" >> $CREATE_FILE 2>&1
	echo "● 3.12 결과 : 양호" >> $CREATE_FILE 2>&1
  else
    if [ `netstat -anp | grep ":23" | wc -l` -gt 0 -o `rpm -qa | grep telnet | wc -l` -gt 0 ]
	  then
	    ps -ef | grep telnet | grep -v "grep" >> $CREATE_FILE 2>&1
		echo " " >> $CREATE_FILE 2>&1
		echo "☞ Telnet 서비스가 사용중입니다." >> $CREATE_FILE 2>&1
		  if [ -f /etc/issue.net ]
		    then
			  echo "■ TELNET 배너" >> $CREATE_FILE 2>&1
              echo "-------------" >> $CREATE_FILE 2>&1
		      cat /etc/issue.net >> $CREATE_FILE 2>&1
			else
			  echo " " >> $CREATE_FILE 2>&1
			  echo "☞ /etc/issue 파일이 없습니다." >> $CREATE_FILE 2>&1
		  fi
	  else
	    echo "☞ Telnet 서비스가 사용중이지 않습니다." >> $CREATE_FILE 2>&1
	fi
    echo " " >> $CREATE_FILE 2>&1
	
	if [ `ps -ef | grep ftp | grep -v "grep" | wc -l` -gt 0 ]
	  then
	    ps -ef | grep ftp | grep -v "grep" >> $CREATE_FILE 2>&1
		echo " " >> $CREATE_FILE 2>&1
		echo "☞ FTP 서비스가 사용중입니다." >> $CREATE_FILE 2>&1
		  if [ -f /etc/welcome.msg ]
			then
			  echo "■ FTP 배너" >> $CREATE_FILE 2>&1
              echo "-------------" >> $CREATE_FILE 2>&1
			  cat /etc/welcome.msg >> $CREATE_FILE 2>&1
		    else
			  echo "☞ /etc/welcome.msg 파일이 없습니다." >> $CREATE_FILE 2>&1
		  fi
	  else
	    echo "☞ FTP 서비스가 사용중이지 않습니다." >> $CREATE_FILE 2>&1
	fi
fi
echo " " >> $CREATE_FILE 2>&1
echo "  " > banner.txt
if [ `ps -ef | grep telnetd | grep -v grep | wc -l` -gt 0 ]
 then
   if [ -f /etc/issue.net ]
     then
       if [ `cat /etc/issue.net | grep -i "banner" | wc -l` -eq 0 ]
         then
           echo "● 3.12 결과 : 취약" >> banner.txt
         else
           echo "● 3.12 결과 : 양호" >> banner.txt
       fi
     else
       echo "● 3.12 결과 : 취약" >> banner.txt
   fi
 else
   echo "● 3.12 결과 : 양호" >> banner.txt
fi

echo " " >> $CREATE_FILE 2>&1

if [ `ps -ef | grep ftpd | grep -v grep | wc -l` -gt 0 ]
 then
   if [ -f /etc/welcome.msg ]
    then
     if [ `cat /etc/welcome.msg | grep -i "banner" | wc -l` -eq 0 ]
      then
        echo "● 3.12 결과 : 취약" >> banner.txt
      else
        echo "● 3.12 결과 : 양호" >> banner.txt
     fi
    else
     echo "● 3.12 결과 : 취약" >> banner.txt
   fi
 else
  echo "● 3.12 결과 : 양호" >> banner.txt
fi

if [ `cat banner.txt | grep "취약" | wc -l` -eq 0 ]
 then
  echo "● 3.12 결과 : 양호" >> $CREATE_FILE 2>&1
 else
  echo "● 3.12 결과 : 취약" >> $CREATE_FILE 2>&1
fi

rm -rf banner.txt
echo "########################################################################################################" >> $CREATE_FILE 2>&1
echo "========================================================================================================" >> $CREATE_FILE 2>&1
echo "3.12 END" >> $CREATE_FILE 2>&1
echo "  " >> $CREATE_FILE 2>&1
echo "  " >> $CREATE_FILE 2>&1
echo "  " >> $CREATE_FILE 2>&1
echo "  " >> $CREATE_FILE 2>&1
echo "  " >> $CREATE_FILE 2>&1
echo "  " >> $CREATE_FILE 2>&1




echo "3.13 START" >> $CREATE_FILE 2>&1
echo "############################ 3.네트워크 서비스 - 3.13 session timeout 설정 #############################"
echo "############################ 3.네트워크 서비스 - 3.13 session timeout 설정 #############################" >> $CREATE_FILE 2>&1
echo "--------------------------------------------------------------------------------------------------------" >> $CREATE_FILE 2>&1
echo "■ 기준 : /etc/profile 파일에 TMOUT이 300으로 설정되어 있으면 양호" >> $CREATE_FILE 2>&1
echo "■ 현황" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
if [ -f /etc/profile ]
 then
    cat /etc/profile | grep -i 'TMOUT' | grep "="  >> $CREATE_FILE 2>&1
 else
  echo "☞ /etc/profile 파일이 없습니다." >> $CREATE_FILE 2>&1
fi
echo " " >> $CREATE_FILE 2>&1
if [ -f /etc/profile ]
 then
  if [ `cat /etc/profile |  grep -v "#" | grep 'TMOUT.*[0-9]' | wc -l ` -eq 1 ]
      then
       echo "● 3.13 결과 : 양호" >> $CREATE_FILE 2>&1
      else
       echo "● 3.13 결과 : 취약" >> $CREATE_FILE 2>&1
  fi
 else
  echo "● 3.13 결과 : 취약" >> $CREATE_FILE 2>&1
fi
echo "########################################################################################################" >> $CREATE_FILE 2>&1
echo "========================================================================================================" >> $CREATE_FILE 2>&1
echo "3.13 END" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1



echo "3.14 START" >> $CREATE_FILE 2>&1
echo "############################ 3.네트워크 서비스 - 3.14 root 계정의 telnet 제한 ##########################"
echo "############################ 3.네트워크 서비스 - 3.14 root 계정의 telnet 제한 ##########################" >> $CREATE_FILE 2>&1
echo "--------------------------------------------------------------------------------------------------------" >> $CREATE_FILE 2>&1
echo "■ 기준 : /etc/pam.d/login에서 auth required /lib/security/pam_securetty.so 라인에 주석(#) 이 없으면 양호 " >> $CREATE_FILE 2>&1
echo "■ 현황" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
if [ `cat /etc/pam.d/login | grep "pam_securetty.so" | grep -v "#" | wc -l` -gt 0 ]
  then
    cat /etc/pam.d/login | grep "pam_securetty.so" | grep -v "#" >> $CREATE_FILE 2>&1
  else
    echo "☞ /etc/pam.d/login 파일에 설정값이 없습니다." >> $CREATE_FILE 2>&1
fi
echo " " >> $CREATE_FILE 2>&1
if [ -f /etc/pam.d/login ]
 then
  if [ `grep "pam_securetty.so" /etc/pam.d/login | grep -v '#' | wc -l ` -eq 1 ]
      then
       echo "● 3.14 결과 : 양호" >> $CREATE_FILE 2>&1
      else
       echo "● 3.14 결과 : 취약" >> $CREATE_FILE 2>&1
  fi
 else
  echo "● 3.14 결과 : 취약" >> $CREATE_FILE 2>&1
fi
echo "########################################################################################################" >> $CREATE_FILE 2>&1
echo "========================================================================================================" >> $CREATE_FILE 2>&1
echo "3.14 END" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1




echo "4.01 START" >> $CREATE_FILE 2>&1
echo "############################ 4.로그관리 - 4.1 Su 로그 설정 #############################################"
echo "############################ 4.로그관리 - 4.1 Su 로그 설정 #############################################" >> $CREATE_FILE 2>&1
echo "--------------------------------------------------------------------------------------------------------" >> $CREATE_FILE 2>&1
echo "■ 기준 : /etc/login.defs - SULOG_FILE  /var/log/sulog 또는 /etc/syslog.conf - authpriv.*  /var/log/secure이 설정되어 있으면 양호 " >> $CREATE_FILE 2>&1
echo "■ 현황" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
if [ `cat /etc/login.defs | grep SULOG_FILE | wc -l` -gt 0 ]
 then
   echo "① /etc/login.defs 설정 : `cat /etc/login.defs | grep SULOG_FILE`" >> $CREATE_FILE 2>&1
 else
   echo "① /etc/login.defs 설정 : 설정값이 없습니다." >> $CREATE_FILE 2>&1
fi
echo " " >> $CREATE_FILE 2>&1

if [ `cat /etc/syslog.conf | grep authpriv.* | grep /var/log/secure | wc -l` -gt 0 ]
  then
   echo "② /etc/syslog.conf 설정 : `cat /etc/syslog.conf | grep authpriv.* | grep /var/log/secure`" >> $CREATE_FILE 2>&1
  else
   echo "② /etc/syslog.conf 설정 : 설정값 없습니다." >> $CREATE_FILE 2>&1
fi
echo " " >> $CREATE_FILE 2>&1
if [ -f /etc/login.defs ]
   then
     if [ `cat /etc/login.defs | grep -i "SULOG_FILE" | grep -i "/var/log/sulog" | grep -v "#" | wc -l` -gt 0 ]
       then
         echo "● 4.01 결과 : 양호" >> $CREATE_FILE 2>&1
        else
          if [ -f /etc/syslog.conf ]
            then
              if [ `cat /etc/syslog.conf | grep "\<authpriv" | grep -i "/var/log/secure" | wc -l` -eq 0 ]
                then
                  echo "● 4.01 결과 : 취약" >> $CREATE_FILE 2>&1
                else
                  echo "● 4.01 결과 : 양호" >> $CREATE_FILE 2>&1
              fi
            else
              echo "● 4.01 결과 : 취약" >> $CREATE_FILE 2>&1
          fi
     fi
   else
     echo "● 4.01 결과 : 취약" >> $CREATE_FILE 2>&1
fi

echo "########################################################################################################" >> $CREATE_FILE 2>&1
echo "========================================================================================================" >> $CREATE_FILE 2>&1
echo "4.01 END" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1



echo "4.02 START" >> $CREATE_FILE 2>&1
echo "############################ 4.로그관리 - 4.2 Syslog 설정 ##############################################"
echo "############################ 4.로그관리 - 4.2 Syslog 설정 ##############################################" >> $CREATE_FILE 2>&1
echo "--------------------------------------------------------------------------------------------------------" >> $CREATE_FILE 2>&1
echo "■ 기준 : alert,info에 대해서 파일에 로그가 남도록 설정되어 있다면 양호(자세한 설정은 가이드라인 참조) " >> $CREATE_FILE 2>&1
echo "■ 현황" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo "☞ syslog 프로세스" >> $CREATE_FILE 2>&1
ps -ef | grep 'syslog' | grep -v grep >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1

echo "☞ 시스템 로깅 설정" >> $CREATE_FILE 2>&1
if [ -f /etc/syslog.conf ] ; then
  cat /etc/syslog.conf | grep -v "#" >> $CREATE_FILE 2>&1
 else
  echo "/etc/syslog.conf 파일이 없습니다." >> $CREATE_FILE 2>&1
fi

echo " " >> $CREATE_FILE 2>&1

echo " " > syslog.txt

if [ `cat /etc/syslog.conf | egrep "info|alert|notice|debug" | egrep "var|log" | wc -l` -gt 0 ]
     then
       echo "● 4.02 결과 : 양호" >> syslog.txt
     else
       echo "● 4.02 결과 : 취약" >> syslog.txt
fi

if [ `cat /etc/syslog.conf | egrep "alert|err|crit" | egrep "console|sysmsg" | wc -l` -gt 0 ]
     then
       echo "● 4.02 결과 : 양호" >> syslog.txt
     else
       echo "● 4.02 결과 : 취약" >> syslog.txt
fi

if [ `cat /etc/syslog.conf | grep "emerg" | grep "\*" | wc -l` -gt 0 ]
     then
       echo "● 4.02 결과 : 양호" >> syslog.txt
     else
       echo "● 4.02 결과 : 취약" >> syslog.txt
fi


if [ `cat syslog.txt | grep "취약" | wc -l` -eq 0 ]
 then
  echo "● 4.02 결과 : 양호" >> $CREATE_FILE 2>&1
 else
  echo "● 4.02 결과 : 취약" >> $CREATE_FILE 2>&1
fi

rm -rf syslog.txt

echo "########################################################################################################" >> $CREATE_FILE 2>&1
echo "========================================================================================================" >> $CREATE_FILE 2>&1
echo "4.02 END" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1




echo "4.03 START" >> $CREATE_FILE 2>&1
echo "############################ 4.로그관리 - 4.3 로그 파일 권한 설정 ######################################"
echo "############################ 4.로그관리 - 4.3 로그 파일 권한 설정 ######################################" >> $CREATE_FILE 2>&1
echo "--------------------------------------------------------------------------------------------------------" >> $CREATE_FILE 2>&1
echo "■ 기준 : 로그 파일의 권한중 타사용자에 쓰기권한이 부여되어 있지 않을 경우 양호(자세한 내용은 가이드라인 참조) " >> $CREATE_FILE 2>&1
echo "■ 현황 " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
FILES="/var/log/wtmp /var/wtmp /var/run/utmp /var/utmp /var/log/btmp /var/log/pacct /var/log/messages /var/log/lastlog /var/log/secure"

for file in $FILES
do
  if [ -f $file ]
    then
      ls -alL $file >> $CREATE_FILE 2>&1
  fi
done

echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1

echo " " > logfiles.txt

FILES="/var/log/wtmp /var/wtmp /var/run/utmp /var/utmp /var/log/btmp /var/log/pacct /var/log/messages /var/log/lastlog /var/log/secure"

for file in $FILES
   do
        if [ -f $file ]
         then
          if [ `ls -alL $file | awk '{print $1}' | grep '........w.' | wc -l` -gt 0 ]
          then
           echo "● 4.03 결과 : 취약" >> logfiles.txt 2>&1
          else
           echo "● 4.03 결과 : 양호" >> logfiles.txt 2>&1
          fi
        else
          echo "● 4.03 결과 : 양호" >> logfiles.txt 2>&1
        fi
done

if [ `cat logfiles.txt | grep "취약" | wc -l` -eq 0 ]
 then
  echo "● 4.03 결과 : 양호" >> $CREATE_FILE 2>&1
 else
  echo "● 4.03 결과 : 취약" >> $CREATE_FILE 2>&1
fi

rm -rf logfiles.txt
echo "########################################################################################################" >> $CREATE_FILE 2>&1
echo "========================================================================================================" >> $CREATE_FILE 2>&1
echo "4.03 END" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1








echo "5.01 START" >> $CREATE_FILE 2>&1
echo "############################ 5.주요 응용 설정 - 5.1 FTP 서비스 사용자 제한 #############################"
echo "############################ 5.주요 응용 설정 - 5.1 FTP 서비스 사용자 제한 #############################" >> $CREATE_FILE 2>&1
echo "--------------------------------------------------------------------------------------------------------" >> $CREATE_FILE 2>&1
echo "■ 기준 : FTP 사용시 root로 접속이 불가능하도록 설정되어 있는 경우 " >> $CREATE_FILE 2>&1
echo "■ 현황" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1

if [ -f /etc/ftpd/ftpusers ]
   then
     echo "☞ /etc/ftpd/ftpusers 파일 내용" >> $CREATE_FILE 2>&1
     grep -v '^ *#' /etc/ftpd/ftpusers  >> $CREATE_FILE 2>&1
   else
     echo "☞ /etc/ftpd/ftpusers 파일이 없습니다." >> $CREATE_FILE 2>&1
fi

echo " " >> $CREATE_FILE 2>&1

if [ -f /etc/ftpusers ]
   then
    echo "☞ /etc/ftpusers 파일 내용" >> $CREATE_FILE 2>&1
    grep -v '^ *#' /etc/ftpusers  >> $CREATE_FILE 2>&1
   else
    echo "☞ /etc/ftpusers 파일이 없습니다." >> $CREATE_FILE 2>&1
  fi

echo " " >> $CREATE_FILE 2>&1

if [ -f /etc/vsftpd/ftpusers ]
   then
      echo "☞ /etc/vsftpd/ftpusers 파일 내용" >> $CREATE_FILE 2>&1
      cat /etc/vsftpd/ftpusers | grep root | grep -v '#' >> $CREATE_FILE 2>&1
   else
      if [ -f /etc/vsftpd/user_list ]
         then
            echo "☞ /etc/vsftpd/user_list 파일 내용" >> $CREATE_FILE 2>&1
            echo cat /etc/vsftpd/user_list | grep root | grep -v '#' >> $CREATE_FILE 2>&1
         else
             echo "☞ /etc/vsftpd/user_list 파일이 없습니다. " >> $CREATE_FILE 2>&1
      fi
fi


echo " " >> $CREATE_FILE 2>&1

echo " " > ftp.txt

for V in `ls /etc/xinetd.d/* | grep ftp`
do
 if [ `cat $V | grep -i "disable" | grep -i "no" | wc -l` -gt 0 ]
  then
    for VVV in `ls /etc/*ftpusers*`
    do
     if [ `cat $VVV | grep root | grep -v "#" | wc -l` -gt 0 ]
       then
           echo "● 5.01 결과 : 양호" >> ftp.txt
       else
           echo "● 5.01 결과 : 취약" >> ftp.txt
     fi
     done
 else
  echo "● 5.01 결과 : 양호" >> ftp.txt
 fi
done

if [ -f /etc/inetd.conf ]
 then
if [ -f /etc/ftpd/ftpusers ]
then
    if [ `cat /etc/ftpd/ftpusers | grep root | grep -v "#"| wc -l` -eq 1 ]
          then
           echo "● 5.01 결과 : 양호" >> ftp.txt
          else
          if [ -f /etc/ftpusers ]
           then
            if [ `cat /etc/ftpusers | grep root | grep -v "#"| wc -l` -eq 1 ]
             then
              echo "● 5.01 결과 : 양호" >> ftp.txt
             else
              echo "● 5.01 결과 : 취약" >> ftp.txt
            fi
           else
            echo "● 5.01 결과 : 취약" >> ftp.txt
          fi
     fi
else
     if [ -f /etc/ftpusers ]
         then
            if [ `cat /etc/ftpusers | grep root | grep -v "#" | wc -l` -eq 1 ]
             then
              echo "● 5.01 결과 : 양호" >> ftp.txt
             else
              echo "● 5.01 결과 : 취약" >> ftp.txt
            fi
         else
           echo "● 5.01 결과 : 취약" >> ftp.txt
     fi
fi
else
echo "● 5.01 결과 : /etc/inetd.conf 파일 없음 " >> ftp.txt
fi


if [ -f /etc/vsftpd/ftpusers ]
  then
    if [ `cat /etc/vsftpd/ftpusers | grep root | grep -v "#"| wc -l` -eq 1 ]
      then
        echo "● 5.01 결과 : 양호" >> ftp.txt
      else
        echo "● 5.01 결과 : 취약" >> ftp.txt
    fi
  else
     echo "● 5.01 결과 : 양호" >> ftp.txt
fi


if [ -f /etc/vsftpd/user_list ]
  then
    if [ `cat /etc/vsftpd/user_list | grep root | grep -v "#"| wc -l` -eq 1 ]
      then
        echo "● 5.01 결과 : 양호" >> ftp.txt
      else
        echo "● 5.01 결과 : 취약" >> ftp.txt
    fi
  else
        echo "● 5.01 결과 : 양호" >> ftp.txt
fi




if [ `cat ftp.txt | grep "취약" | wc -l` -eq 0 ]
 then
  echo "● 5.01 결과 : 양호" >> $CREATE_FILE 2>&1
 else
  echo "● 5.01 결과 : 취약" >> $CREATE_FILE 2>&1
fi

rm -rf ftp.txt
echo "########################################################################################################" >> $CREATE_FILE 2>&1
echo "========================================================================================================" >> $CREATE_FILE 2>&1
echo "5.01 END" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1


echo "5.02 START" >> $CREATE_FILE 2>&1
echo "############################ 5.주요 응용 설정 - 5.2 FTP Shell 제한 #####################################"
echo "############################ 5.주요 응용 설정 - 5.2 FTP Shell 제한 #####################################" >> $CREATE_FILE 2>&1
echo "--------------------------------------------------------------------------------------------------------" >> $CREATE_FILE 2>&1
echo "■ 기준 : FTP를 서비스가 비활성화 되었거나 /etc/passwd에서 ftp 계정에 shell 제한이 설정되어 있는 경우 양호 " >> $CREATE_FILE 2>&1
echo "■ 현황" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
if [ `ps -ef | grep ftp | grep -v "grep" | wc -l` -eq 0 ]
  then
    echo "FTP 서비스를 사용중이지 않습니다." >> $CREATE_FILE 2>&1
  else
    echo "FTP 서비스를 사용중입니다." >> $CREATE_FILE 2>&1
	cat /etc/passwd >> $CREATE_FILE 2>&1
	echo " " >> $CREATE_FILE 2>&1
    echo "※ ftp 계정의 쉘 부분 확인" >> $CREATE_FILE 2>&1
fi
echo " " >> $CREATE_FILE 2>&1


echo "########################################################################################################" >> $CREATE_FILE 2>&1
echo "========================================================================================================" >> $CREATE_FILE 2>&1
echo "5.02 END" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1





echo "5.03 START" >> $CREATE_FILE 2>&1
echo "############################ 5.주요 응용 설정 - 5.3 FTP UMASK 설정 #####################################"
echo "############################ 5.주요 응용 설정 - 5.3 FTP UMASK 설정 #####################################" >> $CREATE_FILE 2>&1
echo "--------------------------------------------------------------------------------------------------------" >> $CREATE_FILE 2>&1
echo "■ 기준 : FTP 사용시 FTP UMASK가 077로 설정되어 있으면 양호 " >> $CREATE_FILE 2>&1
echo "■ 현황" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1

if [ -f /etc/ftpd.conf ]
   then
     echo "☞ /etc/ftpd.conf 파일 " >> $CREATE_FILE 2>&1
     grep -v '^ *#' /etc/ftpd.conf | grep -i "umask" >> $CREATE_FILE 2>&1
   else
     echo "☞ /etc/ftpd.conf 파일 " >> $CREATE_FILE 2>&1
     echo " /etc/ftpd.conf 파일이 없습니다." >> $CREATE_FILE 2>&1
fi

echo " " >> $CREATE_FILE 2>&1


if [ -f /etc/vsftpd/vsftpd.conf ]
   then
      echo "☞ /etc/vsftpd/vsftpd.conf 파일 " >> $CREATE_FILE 2>&1
      grep -v '^ *#' /etc/vsftpd/vsftpd.conf | grep -i "umask" >> $CREATE_FILE 2>&1
   else
      echo "☞ /etc/vsftpd/vsftpd.conf 파일 " >> $CREATE_FILE 2>&1
      echo " /etc/vsftpd/vsftpd.conf 파일이 없습니다. " >> $CREATE_FILE 2>&1
fi

echo " " >> $CREATE_FILE 2>&1

if [ -f /etc/proftpd.conf ]
   then
      echo "☞ /etc/proftpd.conf 파일 " >> $CREATE_FILE 2>&1
      grep -v '^ *#' /etc/proftpd.conf | grep -i "umask" >> $CREATE_FILE 2>&1
   else
      echo "☞ /etc/proftpd.conf 파일 " >> $CREATE_FILE 2>&1
      echo " /etc/proftpd.conf 파일이 없습니다. " >> $CREATE_FILE 2>&1
fi
echo " " >> $CREATE_FILE 2>&1

echo " " > ftp2.txt

if [ -f /etc/vsftpd/vsftpd.conf ]
  then
    if [ `cat /etc/vsftpd/vsftpd.conf | grep -i ".*umask.*077.*" | grep -v "#" | wc -l` -eq 0 ]
      then
        echo "● 5.03 결과 : 취약" >> ftp2.txt
      else
        echo "● 5.03 결과 : 양호" >> ftp2.txt
    fi
  else
     echo "● 5.03 결과 : 양호" >> ftp2.txt
fi

if [ -f /etc/proftpd.conf ]
 then
   if [ `cat /etc/proftpd.conf | grep -i ".*umask.*077.*" | grep -v "#" | wc -l` -eq 0 ]
     then
        echo "● 5.03 결과 : 취약" >> ftp2.txt
     else
        echo "● 5.03 결과 : 양호" >> ftp2.txt
   fi
 else
   echo "● 5.03 결과 : 양호" >> ftp2.txt
fi


if [ -f /etc/ftpd.conf ]
  then
   if [ `cat /etc/ftpd.conf | grep -i '.*umask.*077.*' | grep -v '#'|wc -l` -eq 0 ]
      then
           echo "● 5.03 결과 : 취약" >> ftp2.txt
      else
           echo "● 5.03 결과 : 양호" >> ftp2.txt
   fi
  else
   echo "● 5.03 결과 : 양호" >> ftp2.txt
fi

for V in `ls /etc/xinetd.d/* | grep ftp`
do
 if [ `cat $V | grep -i "disable" | grep -i "no" | wc -l` -gt 0 ]
  then
     FN=`ls $V | awk -F"/" '{print $4}'`
     if [ ` grep umask /etc/$FN.conf | grep -v "#" | awk -F= '{print $2}' | grep 77 | wc -l` -gt 0 ]
       then
           echo "● 5.03 결과 : 양호" >> ftp2.txt
       else
          echo "● 5.03 결과 : 취약" >> ftp2.txt
     fi

 else
  echo "● 5.03 결과 : 양호" >> ftp2.txt
 fi
done

if [ `cat ftp2.txt | grep "취약" | wc -l` -eq 0 ]
 then
  echo "● 5.03 결과 : 양호" >> $CREATE_FILE 2>&1
 else
  echo "● 5.03 결과 : 취약" >> $CREATE_FILE 2>&1
fi

rm -rf ftp2.txt
echo "########################################################################################################" >> $CREATE_FILE 2>&1
echo "========================================================================================================" >> $CREATE_FILE 2>&1
echo "5.03 END" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1





echo "5.04 START" >> $CREATE_FILE 2>&1
echo "############################ 5.주요 응용 설정 - 5.4 Anonymous FTP 제한 #################################"
echo "############################ 5.주요 응용 설정 - 5.4 Anonymous FTP 제한 #################################" >> $CREATE_FILE 2>&1
echo "--------------------------------------------------------------------------------------------------------" >> $CREATE_FILE 2>&1
echo "■ 기준 : ftp를 사용하지 않거나 vsftpd.conf 파일에서 anonymous_enable=NO일 경우 양호" >> $CREATE_FILE 2>&1
echo "■ 현황" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
if [ `ps -ef | grep ftp | grep -v "grep" | wc -l` -eq 0 ]
  then
    echo "☞ FTP를 사용중이지 않습니다." >> $CREATE_FILE 2>&1
	echo "● 5.04 결과 : 양호" >> $CREATE_FILE 2>&1
  else
    if [ -f /etc/passwd ]
      then
        grep -v "^ *#" /etc/passwd | grep "ftp:" | grep -v "tftp:" >> $CREATE_FILE 2>&1
    else
      echo " /etc/passwd 파일이 없습니다. " >> $CREATE_FILE 2>&1
    fi
    echo " " >> $CREATE_FILE 2>&1

    if [ -f /etc/vsftpd/vsftpd.conf ]
      then
        echo "☞ /etc/vsftpd/vsftpd.conf 파일 " >> $CREATE_FILE 2>&1
        cat /etc/vsftpd/vsftpd.conf | grep -i 'anonymous_enable' >> $CREATE_FILE 2>&1
		if [ `cat /etc/vsftpd/vsftpd.conf | grep -i 'anonymous_enable' | grep -i 'yes' | grep -v '#' | wc -l` -eq 0 ]
		  then
            echo "● 5.04 결과 : 양호" >> $CREATE_FILE 2>&1
          else
            echo "● 5.04 결과 : 취약" >> $CREATE_FILE 2>&1
        fi
    else
      echo " /etc/vsftpd/vsftpd.conf 파일이 없습니다. " >> $CREATE_FILE 2>&1
	  echo "● 5.04 결과 : 취약" >> $CREATE_FILE 2>&1
    fi

    echo " " >> $CREATE_FILE 2>&1
fi

echo " " >> $CREATE_FILE 2>&1

echo "########################################################################################################" >> $CREATE_FILE 2>&1
echo "========================================================================================================" >> $CREATE_FILE 2>&1
echo "5.04 END" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1



echo "5.05 START" >> $CREATE_FILE 2>&1
echo "############################ 5.주요 응용 설정 - 5.5 접속 IP 및 포트 제한 ###################################"
echo "############################ 5.주요 응용 설정 - 5.5 접속 IP 및 포트 제한 ###################################" >> $CREATE_FILE 2>&1
echo "--------------------------------------------------------------------------------------------------------" >> $CREATE_FILE 2>&1
echo "■ 기준 : TCP Wrapper 프로토콜이 설치되어 있고 /etc/hosts.allow 와 /etc/hosts.deny에 IP와 포트에 대해 접근통제를 하고 있는 경우 양호" >> $CREATE_FILE 2>&1
echo "■ 현황" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
if [ `rpm -qa | grep wrapper | wc -l` -eq 0 ]
  then
    echo "☞ TCP Wrapper가 설치되어 있지 않습니다." >> $CREATE_FILE 2>&1
	echo "① /etc/hosts.allow 파일" >> $CREATE_FILE 2>&1
	cat /etc/hosts.allow >> $CREATE_FILE 2>&1
	echo " " >> $CREATE_FILE 2>&1
	echo "② /etc/hosts.deny 파일" >> $CREATE_FILE 2>&1
	cat /etc/hosts.deny >> $CREATE_FILE 2>&1
  else
    echo "☞ TCP Wrapper가 설치되어 있습니다." >> $CREATE_FILE 2>&1
	echo "① /etc/hosts.allow 파일" >> $CREATE_FILE 2>&1
	cat /etc/hosts.allow >> $CREATE_FILE 2>&1
	echo " " >> $CREATE_FILE 2>&1
	echo "② /etc/hosts.deny 파일" >> $CREATE_FILE 2>&1
	cat /etc/hosts.deny >> $CREATE_FILE 2>&1
fi
echo " " >> $CREATE_FILE 2>&1
echo "########################################################################################################" >> $CREATE_FILE 2>&1
echo "========================================================================================================" >> $CREATE_FILE 2>&1
echo "5.05 END" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
	




echo "5.06 START" >> $CREATE_FILE 2>&1
echo "############################ 5.주요 응용 설정 - 5.6 SNMP 서비스 설정 ###################################"
echo "############################ 5.주요 응용 설정 - 5.6 SNMP 서비스 설정 ###################################" >> $CREATE_FILE 2>&1
echo "--------------------------------------------------------------------------------------------------------" >> $CREATE_FILE 2>&1
echo "■ 기준 : SNMP 서비스를 사용하지 않거나 Community String 이 public, private 이 아닐 경우 양호" >> $CREATE_FILE 2>&1
echo "■ 현황" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo "① SNMP 서비스 여부 " >> $CREATE_FILE 2>&1
if [ `ps -ef | grep snmp | egrep -v "dmi|osnmp" | grep -v "grep" | wc -l` -eq 0 ]
 then
   echo "☞ SNMP가 비실행중입니다."  >> $CREATE_FILE 2>&1
 else
   ps -ef | grep snmp | egrep -v "dmi|osnmp" | grep -v "grep"  >> $CREATE_FILE 2>&1
fi
echo " " >> $CREATE_FILE 2>&1

echo "② /etc/snmp/snmpd.conf 파일 " >> $CREATE_FILE 2>&1
if [ -f /etc/snmp/snmpd.conf ]
        then
           grep -v '^ *#' /etc/snmp/snmpd.conf | egrep -i "public|private" >> $CREATE_FILE 2>&1
        else
          echo " /etc/snmp/snmpd.conf 파일이 존재하지 않습니다. " >> $CREATE_FILE 2>&1
fi
echo " " >> $CREATE_FILE 2>&1

if [ `ps -ef | grep snmp | egrep -v "dmi|osnmp|cma" | grep -v "grep" | wc -l` -eq 0 ]
  then
     echo "● 5.06 결과 : 양호" >> $CREATE_FILE 2>&1
  else
     if [ `cat /etc/snmp/snmpd.conf | egrep -i "public|private" | grep -v "#" | wc -l ` -eq 0 ]
       then
         echo "● 5.06 결과 : 양호" >> $CREATE_FILE 2>&1
       else
         echo "● 5.06 결과 : 취약" >> $CREATE_FILE 2>&1
     fi
fi
echo "########################################################################################################" >> $CREATE_FILE 2>&1
echo "========================================================================================================" >> $CREATE_FILE 2>&1
echo "5.06 END" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1






echo "5.07 START" >> $CREATE_FILE 2>&1
echo "############################ 5.주요 응용 설정 - 5.7 SMTP Abuse 방지 ####################################"
echo "############################ 5.주요 응용 설정 - 5.7 SMTP Abuse 방지 ####################################" >> $CREATE_FILE 2>&1
echo "--------------------------------------------------------------------------------------------------------" >> $CREATE_FILE 2>&1
echo "■ 기준 : SMTP 서비스를 사용하지 않거나 noexpn, novrfy 옵션이 설정되어 있을 경우 양호" >> $CREATE_FILE 2>&1
echo "■ 현황" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo "① Sendmail 프로세스 확인" >> $CREATE_FILE 2>&1
if [ `ps -ef | grep sendmail | grep -v "grep" | wc -l` -eq 0 ]
 then
  echo "☞ Sendmail 서비스를 사용하지 않습니다." >> $CREATE_FILE 2>&1
 else
  ps -ef | grep sendmail | grep -v "grep" >> $CREATE_FILE 2>&1
fi
echo " " >> $CREATE_FILE 2>&1

echo "② /etc/mail/sendmail.cf 파일의 옵션 확인" >> $CREATE_FILE 2>&1
if [ -f /etc/mail/sendmail.cf ]
  then
    grep -v '^ *#' /etc/mail/sendmail.cf | grep PrivacyOptions >> $CREATE_FILE 2>&1
  else
    echo "☞ /etc/mail/sendmail.cf 파일이 없습니다." >> $CREATE_FILE 2>&1
fi

if [ `ps -ef | grep sendmail | grep -v "grep" | wc -l` -eq 0 ]
  then
     echo "● 5.07 결과 : 양호" >> $CREATE_FILE 2>&1
  else
     if [ -f /etc/mail/sendmail.cf ]
      then
      if [ `cat /etc/mail/sendmail.cf | grep -i "O PrivacyOptions" | grep -i "noexpn" | grep -i "novrfy" |grep -v "#" | wc -l ` -eq 1 ]
       then
         echo "● 5.07 결과 : 양호" >> $CREATE_FILE 2>&1
       else
         echo "● 5.07 결과 : 취약" >> $CREATE_FILE 2>&1
      fi
      else
        echo "● 5.07 결과 : 미점검" >> $CREATE_FILE 2>&1
     fi
fi

echo " " >> $CREATE_FILE 2>&1
echo "########################################################################################################" >> $CREATE_FILE 2>&1
echo "========================================================================================================" >> $CREATE_FILE 2>&1
echo "5.07 END" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1



echo "5.08 START" >> $CREATE_FILE 2>&1
echo "############################ 5.주요 응용 설정 - 5.8 SMTP 서버의 릴레이 방지 ####################"
echo "############################ 5.주요 응용 설정 - 5.8 SMTP 서버의 릴레이 방지 ####################" >> $CREATE_FILE 2>&1
echo "--------------------------------------------------------------------------------------------------------" >> $CREATE_FILE 2>&1
echo "■ 기준 : SMTP 서비스를 사용하지 않거나 릴레이 제한이 설정되어 있을 경우" >> $CREATE_FILE 2>&1
echo "■ 현황" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
if [ `ps -ef | grep sendmail | grep -v "grep" | wc -l` -eq 0 ]
  then
    echo "☞ SMTP 서비스를 사용하지 않습니다." >> $CREATE_FILE 2>&1
    echo "● 5.08 결과 : 양호" >> $CREATE_FILE 2>&1
  else
    echo "① sendmail.cf 옵션" >> $CREATE_FILE 2>&1
    cat /etc/mail/sendmail.cf | grep "550 Relaying denied" >> $CREATE_FILE 2>&1
	echo " " >> $CREATE_FILE 2>&1
	echo "② access 파일" >> $CREATE_FILE 2>&1
	cat /etc/mail/access >> $CREATE_FILE 2>&1
fi
echo " " >> $CREATE_FILE 2>&1
echo "########################################################################################################" >> $CREATE_FILE 2>&1
echo "========================================================================================================" >> $CREATE_FILE 2>&1
echo "5.08 END" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1





echo "5.09 START" >> $CREATE_FILE 2>&1
echo "############################ 5.주요 응용 설정 - 5.9 일반사용자의 Sendmail 실행 방지 ####################"
echo "############################ 5.주요 응용 설정 - 5.9 일반사용자의 Sendmail 실행 방지 ####################" >> $CREATE_FILE 2>&1
echo "--------------------------------------------------------------------------------------------------------" >> $CREATE_FILE 2>&1
echo "■ 기준 : SMTP 서비스를 사용하지 않거나 restrictqrun 옵션이 설정되어 있을 경우 양호" >> $CREATE_FILE 2>&1
echo "■ 현황" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo "① Sendmail 프로세스 확인" >> $CREATE_FILE 2>&1
if [ `ps -ef | grep sendmail | grep -v "grep" | wc -l` -eq 0 ]
 then
  echo "☞ Sendmail 서비스를 사용하지 않습니다." >> $CREATE_FILE 2>&1
 else
  ps -ef | grep sendmail | grep -v "grep" >> $CREATE_FILE 2>&1
fi
echo " " >> $CREATE_FILE 2>&1
ls -al /etc/rc*.d/* | grep -i sendmail | grep "/S" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1


echo "② /etc/mail/sendmail.cf 파일의 옵션 확인" >> $CREATE_FILE 2>&1
if [ -f /etc/mail/sendmail.cf ]
  then
    grep -v '^ *#' /etc/mail/sendmail.cf | grep PrivacyOptions >> $CREATE_FILE 2>&1
  else
    echo "☞ /etc/mail/sendmail.cf 파일이 없습니다." >> $CREATE_FILE 2>&1
fi
echo " " >> $CREATE_FILE 2>&1

if [ `ps -ef | grep sendmail | grep -v "grep" | wc -l` -eq 0 ]
  then
     echo "● 5.09 결과 : 양호" >> $CREATE_FILE 2>&1
  else
    if [ -f /etc/mail/sendmail.cf ]
     then
     if [ `cat /etc/mail/sendmail.cf | grep -i "O PrivacyOptions" | grep -i "restrictqrun" | grep -v "#" | wc -l ` -eq 1 ]
       then
         echo "● 5.09 결과 : 양호" >> $CREATE_FILE 2>&1
       else
         echo "● 5.09 결과 : 취약" >> $CREATE_FILE 2>&1
     fi
     else
      echo "● 5.09 결과  : 미점검" >> $CREATE_FILE 2>&1
    fi
fi
echo "########################################################################################################" >> $CREATE_FILE 2>&1
echo "========================================================================================================" >> $CREATE_FILE 2>&1
echo "5.09 END" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1





echo "5.10 START" >> $CREATE_FILE 2>&1
echo "############################ 5.주요 응용 설정 - 5.10 Sendmail 버전 점검 #################################"
echo "############################ 5.주요 응용 설정 - 5.10 Sendmail 버전 점검 #################################" >> $CREATE_FILE 2>&1
echo "--------------------------------------------------------------------------------------------------------" >> $CREATE_FILE 2>&1
echo "■ 기준 : sendmail 버전이 8.14.4 이상이면 양호" >> $CREATE_FILE 2>&1
echo "■ 현황" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo "① Sendmail 프로세스 확인" >> $CREATE_FILE 2>&1
if [ `ps -ef | grep sendmail | grep -v "grep" | wc -l` -eq 0 ]
 then
  echo "☞ Sendmail 서비스를 사용하지 않습니다." >> $CREATE_FILE 2>&1
 else
  ps -ef | grep sendmail | grep -v "grep" >> $CREATE_FILE 2>&1
fi
echo " " >> $CREATE_FILE 2>&1

echo "② sendmail 버전확인" >> $CREATE_FILE 2>&1
if [ -f /etc/mail/sendmail.cf ]
   then
     grep -v '^ *#' /etc/mail/sendmail.cf | grep DZ >> $CREATE_FILE 2>&1
   else
     echo "☞ /etc/mail/sendmail.cf 파일이 없습니다." >> $CREATE_FILE 2>&1
fi
echo " " >> $CREATE_FILE 2>&1

if [ `ps -ef | grep sendmail | grep -v "grep" | wc -l` -eq 0 ]
  then
     echo "● 5.10 결과 : 양호" >> $CREATE_FILE 2>&1
  else
    if [ -f /etc/mail/sendmail.cf ]
     then
     if [ `grep -v '^ *#' /etc/mail/sendmail.cf | egrep "DZ8.13.8|DZ8.14.0|DZ8.14.1|DZ8.14.2|DZ8.14.3|DZ8.14.4" | wc -l ` -eq 1 ]
       then
         echo "● 5.10 결과 : 양호" >> $CREATE_FILE 2>&1
       else
         echo "● 5.10 결과 : 취약" >> $CREATE_FILE 2>&1
     fi
     else
      echo "● 5.10 결과 : 미점검" >> $CREATE_FILE 2>&1
     fi
fi
echo "########################################################################################################" >> $CREATE_FILE 2>&1
echo "========================================================================================================" >> $CREATE_FILE 2>&1
echo "5.10 END" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1





echo "5.11 START" >> $CREATE_FILE 2>&1
echo "############################ 5.주요 응용 설정 - 5.11 DNS Zone Transfer 설정 #############################"
echo "############################ 5.주요 응용 설정 - 5.11 DNS Zone Transfer 설정 #############################" >> $CREATE_FILE 2>&1
echo "--------------------------------------------------------------------------------------------------------" >> $CREATE_FILE 2>&1
echo "■ 기준 : DNS 서비스를 사용하지 않거나 Zone Transfer 가 제한되어 있을 경우 양호" >> $CREATE_FILE 2>&1
echo "■ 현황" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo "① DNS 프로세스 확인 " >> $CREATE_FILE 2>&1
if [ `ps -ef | grep named | grep -v "grep" | wc -l` -eq 0 ]
  then
    echo "☞ DNS 서비스를 사용하지 않습니다." >> $CREATE_FILE 2>&1
  else
    ps -ef | grep named | grep -v "grep" >> $CREATE_FILE 2>&1
fi
echo " " >> $CREATE_FILE 2>&1
ls -al /etc/rc*.d/* | grep -i named | grep "/S" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1

echo "② /etc/named.conf 파일의 allow-transfer 확인" >> $CREATE_FILE 2>&1
   if [ -f /etc/named.conf ]
     then
      cat /etc/named.conf | grep 'allow-transfer' >> $CREATE_FILE 2>&1
     else
      echo "☞ /etc/named.conf 파일이 없습니다." >> $CREATE_FILE 2>&1
   fi

echo " " >> $CREATE_FILE 2>&1

echo "③ /etc/named.boot 파일의 xfrnets 확인" >> $CREATE_FILE 2>&1
   if [ -f /etc/named.boot ]
     then
       cat /etc/named.boot | grep "\xfrnets" >> $CREATE_FILE 2>&1
     else
       echo "☞ /etc/named.boot 파일이 없습니다." >> $CREATE_FILE 2>&1
   fi

echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1

if [ `ps -ef | grep named | grep -v "grep" | wc -l` -eq 0 ]
  then
     echo "● 5.11 결과 : 양호" >> $CREATE_FILE 2>&1
  else
     if [ -f /etc/named.conf ]
       then
         if [ `cat /etc/named.conf | grep "\allow-transfer.*[0-256].[0-256].[0-256].[0-256].*" | grep -v "#" | wc -l` -eq 0 ]
            then
               echo "● 5.11 결과 : 취약" >> $CREATE_FILE 2>&1
            else
               echo "● 5.11 결과 : 양호" >> $CREATE_FILE 2>&1
          fi
        else
          if [ -f /etc/named.boot ]
           then
             if [ `cat /etc/named.boot | grep "\xfrnets.*[0-256].[0-256].[0-256].[0-256].*" | grep -v "#" | wc -l` -eq 0 ]
            then
               echo "● 5.11 결과 : 취약" >> $CREATE_FILE 2>&1
            else
               echo "● 5.11 결과 : 양호" >> $CREATE_FILE 2>&1
            fi
           else
              echo "● 5.11 결과 : 미점검" >> $CREATE_FILE 2>&1
          fi

     fi
fi
echo "########################################################################################################" >> $CREATE_FILE 2>&1
echo "========================================================================================================" >> $CREATE_FILE 2>&1
echo "5.11 END" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1




echo "5.12 START" >> $CREATE_FILE 2>&1
echo "############################ 5.주요 응용 설정 - 5.12 DNS 보안 버전 패치 #################################"
echo "############################ 5.주요 응용 설정 - 5.12 DNS 보안 버전 패치 #################################" >> $CREATE_FILE 2>&1
echo "--------------------------------------------------------------------------------------------------------" >> $CREATE_FILE 2>&1
echo "■ 기준 : DNS 서비스를 사용하지 않거나, 양호한 버전을 사용하고 있을 경우에 양호(8.4.6, 8.4.7, 9.2.8-P1, 9.3.4-P1, 9.4.1-P1, 9.5.0a6)" >> $CREATE_FILE 2>&1
echo "■ 현황" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
DNSPR=`ps -ef | grep named | grep -v "grep" | awk 'BEGIN{ OFS="\n"} {i=1; while(i<=NF) {print $i; i++}}'| grep "/" | uniq`
DNSPR=`echo $DNSPR | awk '{print $1}'`
if [ `ps -ef | grep named | grep -v grep | wc -l` -gt 0 ]
 then
  if [ -f $DNSPR ]
   then
    echo "BIND 버전 확인" >> $CREATE_FILE 2>&1
    echo "--------------" >> $CREATE_FILE 2>&1
    $DNSPR -v | grep BIND >> $CREATE_FILE 2>&1
   else
    echo "☞ $DNSPR 파일이 없습니다." >> $CREATE_FILE 2>&1
  fi
 else
  echo "☞ DNS 서비스를 사용하지 않습니다. " >> $CREATE_FILE 2>&1
fi

echo " " >> $CREATE_FILE 2>&1

if [ `ps -ef | grep named | grep -v "grep" | wc -l` -eq 0 ]
    then
        echo "● 5.12 결과 : 양호" >> $CREATE_FILE 2>&1
    else
     if [ -f $DNSPR ]
      then
        if [ `$DNSPR -v | grep BIND | egrep '8.4.6 | 8.4.7 | 9.2.8-P1 | 9.3.4-P1 | 9.4.1-P1 | 9.5.0a6' | wc -l` -gt 0 ]
          then
            echo "● 5.12 결과 : 양호" >> $CREATE_FILE 2>&1
          else
            echo "● 5.12 결과 : 취약" >> $CREATE_FILE 2>&1
        fi
     else
       echo "● 5.12 결과 : 미점검" >> $CREATE_FILE 2>&1
    fi
fi
echo "########################################################################################################" >> $CREATE_FILE 2>&1
echo "========================================================================================================" >> $CREATE_FILE 2>&1
echo "5.12 END" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1




echo "5.13 START" >> $CREATE_FILE 2>&1
echo "############################ 5.주요 응용 설정 - 5.13 SWAT 강제공격 방지 ################################"
echo "############################ 5.주요 응용 설정 - 5.13 SWAT 강제공격 방지 ################################" >> $CREATE_FILE 2>&1
echo "--------------------------------------------------------------------------------------------------------" >> $CREATE_FILE 2>&1
echo "■ 기준 : /etc/inetd.conf 파일에 SWAT 서비스가 활성화 되어 있지 않으면 양호" >> $CREATE_FILE 2>&1
echo "■ 현황" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
if [ -f /etc/inetd.conf ]
  then
    cat /etc/inetd.conf | grep swat >> $CREATE_FILE 2>&1
  else
    echo "☞ /etc/inetd.conf 파일이 없습니다." >> $CREATE_FILE 2>&1
fi
echo " " >> $CREATE_FILE 2>&1
if [ `ps -ef | grep swat | grep -v "grep"| wc -l` -eq 0 ]
  then
    if [ `cat /etc/inetd.conf | grep -i swat | grep -v '#' | grep -v "grep" | wc -l` -eq 1 ]
      then
        echo "● 5.13 결과 : 취약" >> $CREATE_FILE 2>&1
      else
        echo "● 5.13 결과 : 양호" >> $CREATE_FILE 2>&1
    fi
   else
    if [ `cat /etc/inetd.conf | grep -i swat | grep -v '#' |grep -v "grep" | wc -l` -eq 1 ]
      then
        echo "● 5.13 결과 : 취약" >> $CREATE_FILE 2>&1
      else
        echo "● 5.13 결과 : 양호" >> $CREATE_FILE 2>&1
    fi
fi

echo "########################################################################################################" >> $CREATE_FILE 2>&1
echo "========================================================================================================" >> $CREATE_FILE 2>&1
echo "5.13 END" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1





echo "5.14 START" >> $CREATE_FILE 2>&1
echo "############################ 5.주요 응용 설정 - 5.14 Samba 버전 점검 ###################################"
echo "############################ 5.주요 응용 설정 - 5.14 Samba 버전 점검 ###################################" >> $CREATE_FILE 2>&1
echo "--------------------------------------------------------------------------------------------------------" >> $CREATE_FILE 2>&1
echo "■ 기준 : Samba 서비스를 사용하지 않거나 주기적으로 패치를 관리하고 있을 경우 양호" >> $CREATE_FILE 2>&1
echo "■ 현황" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
SMBPR=`ps -ef | grep smb | grep -v "grep" | awk 'BEGIN{ OFS="\n"} {i=1; while(i<=NF) {print $i; i++}}'| grep "/" | uniq`

if [ `ps -ef | grep smbd | grep -v grep | wc -l` -gt 0 ]
 then
  ps -ef | grep smbd | grep -v "grep" >> $CREATE_FILE 2>&1
  $SMBPR -V  >> $CREATE_FILE 2>&1
 else
  echo "☞ Samba 서비스를 사용하지 않습니다." >> $CREATE_FILE 2>&1
fi
echo " " >> $CREATE_FILE 2>&1
if [ `ps -ef | grep smbd | grep -v "grep" | wc -l` -eq 0 ]
  then
    echo "● 5.14 결과 : 양호" >> $CREATE_FILE 2>&1
  else
    echo "● 5.14 결과 : 취약" >> $CREATE_FILE 2>&1
fi
echo "########################################################################################################" >> $CREATE_FILE 2>&1
echo "========================================================================================================" >> $CREATE_FILE 2>&1
echo "5.14 END" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1



echo "5.15 START" >> $CREATE_FILE 2>&1
echo "############################ 5.주요 응용 설정 - 5.15 Open SSH Challenge Response 버퍼오버플로 #####################################"
echo "############################ 5.주요 응용 설정 - 5.15 Open SSH Challenge Response 버퍼오버플로 #####################################" >> $CREATE_FILE 2>&1
echo "--------------------------------------------------------------------------------------------------------" >> $CREATE_FILE 2>&1
echo "■ 기준 : SSH 서비스를 사용하지 않거나 주기적으로 패치를 관리하고 있으면 양호(4.3 이상 양호)" >> $CREATE_FILE 2>&1
echo "■ 현황" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
if [ `ps -ef | grep sshd | grep -v "grep" | wc -l` -eq 0 ]
  then
    echo "☞ SSH 서비스가 실행중이지 않습니다." >> $CREATE_FILE 2>&1
	echo "● 5.15 결과 : 양호" >> $CREATE_FILE 2>&1
  else
    echo "☞ SSH 서비스가 실행중입니다." >> $CREATE_FILE 2>&1
	echo "① SSH 버전 확인(3.4 버전 이상이면 양호)" >> $CREATE_FILE 2>&1
	ssh -V  >> $CREATE_FILE 2>&1
	echo " " >> $CREATE_FILE 2>&1
	echo "② SSH 설정 확인(2.3.1 ~ 3.3 버전)" >> $CREATE_FILE 2>&1
	if [ `cat /etc/ssh/sshd_config | grep KbdInteractiveAuthentication | wc -l` -gt 0 ]
	  then
	  	echo "▶ OpenSSH 2.3.1 ~ 2.9 버전" >> $CREATE_FILE 2>&1
	    cat /etc/ssh/sshd_config | grep KbdInteractiveAuthentication >> $CREATE_FILE 2>&1
	  else
	    if [ `cat /etc/ssh/sshd_config | grep PAMAuthenticationViaKbdInt | wc -l` -gt 0 -a `cat /etc/ssh/sshd_config | grep ChallengeResponseAuthentication | wc -l` -gt 0 ]
		  then
		  	echo "▶ OpenSSH 2.9.p1 이후 버전" >> $CREATE_FILE 2>&1
	        cat /etc/ssh/sshd_config | grep PAMAuthenticationViaKbdInt >> $CREATE_FILE 2>&1
	        cat /etc/ssh/sshd_config | grep ChallengeResponseAuthentication >> $CREATE_FILE 2>&1
		  else
		    echo "☞ 설정값이 존재하지 않습니다." >> $CREATE_FILE 2>&1
	    fi
	fi
fi
echo " " >> $CREATE_FILE 2>&1
echo "########################################################################################################" >> $CREATE_FILE 2>&1
echo "========================================================================================================" >> $CREATE_FILE 2>&1
echo "5.15 END" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1	



echo "5.16 START" >> $CREATE_FILE 2>&1
echo "############################ 5.주요 응용 설정 - 5.16 Open SSH 버전 점검 #####################################"
echo "############################ 5.주요 응용 설정 - 5.16 Open SSH 버전 점검 #####################################" >> $CREATE_FILE 2>&1
echo "--------------------------------------------------------------------------------------------------------" >> $CREATE_FILE 2>&1
echo "■ 기준 : SSH 서비스를 사용하지 않거나 주기적으로 패치를 관리하고 있으면 양호(4.5 이상 양호)" >> $CREATE_FILE 2>&1
echo "■ 현황" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
SSHPR=`ps -ef | grep sshd | grep -v "grep" | awk 'BEGIN{ OFS="\n"} {i=1; while(i<=NF) {print $i; i++}}'| grep "/sshd" | uniq`

echo "① SSH 서비스 확인 " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
if [ `ps -ef | grep sshd | grep -v "grep" | wc -l` -eq 0 ]
  then
   echo "☞ SSH 서비스가 비실행중입니다." >> $CREATE_FILE 2>&1
   echo "● 5.16 결과 : 양호" >> $CREATE_FILE 2>&1
  else
   ps -ef | grep sshd | grep -v "grep" >> $CREATE_FILE 2>&1
fi

echo " " >> $CREATE_FILE 2>&1

echo "② SSH 버전 확인(4.5 이상 양호)" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
if [ `ps -ef | grep sshd | grep -v "grep" | wc -l`  -eq 0 ]
  then
   echo "☞ SSH 서비스가 비실행중입니다." >> $CREATE_FILE 2>&1
  else
   ssh -V >> $CREATE_FILE 2>&1
fi
echo " " >> $CREATE_FILE 2>&1

ssh -V >> ssh_version.txt 2>&1

if [ `ps -ef | grep sshd | grep -v "grep" | wc -l` -eq 0  ]
   then
     echo "● 5.15 결과 : 양호" >> $CREATE_FILE 2>&1
   else
    if [ `cat ssh_version.txt | grep -i "OpenSSH" | wc -l` -gt 0  ]
    then
      if [ `cat ssh_version.txt | egrep "4.3|4.6" | wc -l` -gt 0  ]
      then
        echo "● 5.15 결과 : 양호" >> $CREATE_FILE 2>&1
      else
        echo "● 5.15 결과 : 취약" >> $CREATE_FILE 2>&1
      fi
    else
    echo "● 5.15 결과 : 미점검" >> $CREATE_FILE 2>&1
    fi
fi

rm -rf ssh_version.txt

echo "########################################################################################################" >> $CREATE_FILE 2>&1
echo "========================================================================================================" >> $CREATE_FILE 2>&1
echo "5.16 END" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1



echo "5.17 START" >> $CREATE_FILE 2>&1
echo "############################ 5.주요 응용 설정 - 5.17 'xhost +' 설정 ####################################"
echo "############################ 5.주요 응용 설정 - 5.17 'xhost +' 설정 ####################################" >> $CREATE_FILE 2>&1
echo "--------------------------------------------------------------------------------------------------------" >> $CREATE_FILE 2>&1
echo "■ 기준 : 자동 실행 파일에 “xhost +” 설정이 존재하지 않으면 양호" >> $CREATE_FILE 2>&1
echo "■ 현황" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
HOMEDIRS=`cat /etc/passwd | awk -F":" 'length($6) > 0 {print $6}' | sort -u| grep -vw "/"`
FILES="/.profile /.cshrc /.kshrc /.login /.bash_profile /.bashrc /.bash_login /.xinitrc /.xsession"

for file in $FILES
  do
    if [ -f $file ]
      then
        echo " cat $file " >> $CREATE_FILE 2>&1
        echo " ------------" >> $CREATE_FILE 2>&1
        grep -v '^ *#' $file | grep "xhost +" >> $CREATE_FILE 2>&1
      else
        echo $file " 파일이 없습니다." >> $CREATE_FILE 2>&1
    fi
done

for dir in $HOMEDIRS
do
  for file in $FILES
  do
    if [ -f $dir$file ]
      then
        echo " cat $dir$file " >> $CREATE_FILE 2>&1
        echo "----------------" >> $CREATE_FILE 2>&1
        grep -v '^ *#' $dir$file | grep "xhost +" >> $CREATE_FILE 2>&1
      else
       echo $dir$file " 파일이 없습니다." >> $CREATE_FILE 2>&1
    fi
  done
done

echo " " >> $CREATE_FILE 2>&1

echo " " > xhost.txt
HOMEDIRS=`cat /etc/passwd | awk -F":" 'length($6) > 0 {print $6}' | sort -u| grep -vw "/"`
FILES="/.profile /.cshrc /.kshrc /.login /.bash_profile /.bashrc /.bash_login /.xinitrc /.xsession"

for file in $FILES
  do
    if [ -f $file ]
      then
        if [ `cat $file | grep "xhost.*+" | wc -l` -eq 0 ]
          then
             echo "● 5.17 결과 : 양호" >> xhost.txt
          else
             echo "● 5.17 결과 : 취약" >> xhost.txt
        fi
      else
       echo "  " >> xhost.txt
      echo "● 5.17 결과 : 양호" >> xhost.txt
    fi
done

for dir in $HOMEDIRS
do
  for file in $FILES
  do
    if [ -f $dir$file ]
      then
        if [ `cat $dir$file | grep "xhost.*+" | wc -l` -eq 0 ]
          then
             echo "● 5.17 결과 : 양호" >> xhost.txt
          else
             echo "● 5.17 결과 : 취약" >> xhost.txt
        fi
      else
       echo "● 5.17 결과 : 양호" >> xhost.txt
    fi
  done
done

if [ `cat xhost.txt | grep "취약" | wc -l` -eq 0 ]
 then
  echo "● 5.17 결과 : 양호" >> $CREATE_FILE 2>&1
 else
  echo "● 5.17 결과 : 취약" >> $CREATE_FILE 2>&1
fi

rm -rf xhost.txt
echo "########################################################################################################" >> $CREATE_FILE 2>&1
echo "========================================================================================================" >> $CREATE_FILE 2>&1
echo "5.17 END" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1



echo "6.01 START" >> $CREATE_FILE 2>&1
echo "############################ 6.보안패치 - 6.1 보안패치 #################################################"
echo "############################ 6.보안패치 - 6.1 보안패치 #################################################" >> $CREATE_FILE 2>&1
echo "--------------------------------------------------------------------------------------------------------" >> $CREATE_FILE 2>&1
echo "■ 패치 적용 정책을 수립하여 주기적으로 패치를 관리하고 있으면 양호 " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo "☞ 현재 설치되어 있는 패치" >> $CREATE_FILE 2>&1
echo "--------------------------" >> $CREATE_FILE 2>&1
rpm -qa | sort >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1

echo "● 6.01 결과 : 양호" >> $CREATE_FILE 2>&1
echo "########################################################################################################" >> $CREATE_FILE 2>&1
echo "========================================================================================================" >> $CREATE_FILE 2>&1
echo "6.01 END" >> $CREATE_FILE 2>&1



unset HOMEDIRS
rm -rf ftp_temp
rm -rf ftp2_temp
rm -rf log_temp
rm -rf svc

echo "************************************************** END **************************************************" >> $CREATE_FILE 2>&1
date >> $CREATE_FILE 2>&1
echo "************************************************** END **************************************************"


echo "1.01 Default 계정 삭제" > list.txt
echo "1.02 root group 관리" >> list.txt
echo "1.03 passwd 파일 권한 설정" >> list.txt
echo "1.04 group 파일 권한 설정" >> list.txt
echo "1.05 패스워드 최소길이 설정" >> list.txt
echo "1.06 패스워드 최대 사용기간 설정" >> list.txt
echo "1.07 패스워드 최소 사용기간 설정" >> list.txt
echo "1.08 shell 제한" >> list.txt
echo "1.09 su 제한" >> list.txt
echo "1.10 shadow 파일 권한 설정" >> list.txt
echo "1.11 Trivial Password" >> list.txt
echo "1.12 계정이 존재하지 않는 GID 금지" >> list.txt
echo "1.13 계정잠금 임계값 설정" >> list.txt
echo "2.01 UMASK 설정" >> list.txt
echo "2.02 Setuid, Setgid 설정" >> list.txt
echo "2.03 inetd.conf 파일 권한 설정" >> list.txt
echo "2.04 .sh_history 파일 권한 설정" >> list.txt
echo "2.05 Crontab 관련 파일의 접근 제한" >> list.txt
echo "2.06 Crontab 관리" >> list.txt
echo "2.07 profile 파일 권한 설정" >> list.txt
echo "2.08 hosts 파일 권한 설정" >> list.txt
echo "2.09 issue 파일 권한 설정" >> list.txt
echo "2.10 홈 디렉터리 권한 설정" >> list.txt
echo "2.11 홈디렉토리 환경변수 파일 권한 설정" >> list.txt
echo "2.12 주요 디렉토리 파일 권한 설정" >> list.txt
echo "2.13 PATH 환경변수 설정" >> list.txt
echo "2.14 FTP 접근제어 파일 권한 설정" >> list.txt
echo "2.15 root 원격 접근제어 파일 권한 설정" >> list.txt
echo "2.16 NFS 접근제어 파일 권한 설정" >> list.txt
echo "2.17 서비스 파일 권한 설정" >> list.txt
echo "2.18 기타 중요파일 권한 설정" >> list.txt
echo "2.19 at 관련 파일의 접근제한" >> list.txt
echo "3.01 RPC 서비스 설정" >> list.txt
echo "3.02 NFS 설정" >> list.txt
echo "3.03 원격 마운트 시스템 확인" >> list.txt
echo "3.04 statd, lockd 제거" >> list.txt
echo "3.05 Automountd 제거" >> list.txt
echo "3.06 NIS, NIS+ 점검" >> list.txt
echo "3.07 ‘r’ commands 설정" >> list.txt
echo "3.08 신뢰관계 설정" >> list.txt
echo "3.09 hosts.equiv 파일 권한 설정" >> list.txt
echo "3.10 .rhosts 파일 권한 설정" >> list.txt
echo "3.11 기타 서비스 설정" >> list.txt
echo "3.12 서비스 Banner 관리" >> list.txt
echo "3.13 Session timeout 설정" >> list.txt
echo "3.14 root 계정의 telnet 제한" >> list.txt
echo "4.01 Su 로그 설정" >> list.txt
echo "4.02 Syslog 설정" >> list.txt
echo "4.03 로그 파일 권한 설정" >> list.txt
echo "5.01 FTP 서비스 사용자 제한" >> list.txt
echo "5.02 FTP Shell 제한" >> list.txt
echo "5.03 FTP UMASK 설정" >> list.txt
echo "5.04 Anonymous FTP 제한" >> list.txt
echo "5.05 접속 IP 및 포트 제한" >> list.txt
echo "5.06 SNMP 서비스 설정" >> list.txt
echo "5.07 SMTP Abuse 방지" >> list.txt
echo "5.08 SMTP 서버의 릴레이 방지" >> list.txt
echo "5.09 일반사용자의 Sendmail 실행 방지" >> list.txt
echo "5.10 Sendmail 버전 점검" >> list.txt
echo "5.11 DNS Zone Transfer 설정" >> list.txt
echo "5.12 DNS 보안 버전 패치" >> list.txt
echo "5.13 SWAT 강제공격 방지" >> list.txt
echo "5.14 Samba 버전 점검" >> list.txt
echo "5.15 Open SSH Challenge Response 버퍼오버플로" >> list.txt
echo "5.16 Open 버전 점검" >> list.txt
echo "5.17 'xhost +' 설정" >> list.txt
echo "6.01 보안패치" >> list.txt




echo "***************************************  전체 결과물 파일 생성 시작  ************************************"
CREATE_FILE_RESULT=`hostname`"_"`date +%m%d%k%M`.txt
echo > $CREATE_FILE_RESULT

echo " "

awk '/INFO_CHKSTART/,/INFO_CHKEND/' $CREATE_FILE > result_temp.txt 2>&1

cat $CREATE_FILE | grep "END" | awk '{print $1}' > VUL1.txt

for vul in `uniq VUL1.txt`
        do
           awk '/'"$vul"' START/,/'"$vul"' END/' $CREATE_FILE >> result_temp.txt 2>&1
           echo >> result_temp.txt 2>&1
        done

rm -Rf VUL1.txt
echo "***************************************  전체 결과물 파일 생성 끝 **************************************"
echo "***************************************   취약한 항목 출력 시작 ****************************************"
echo > vul5.txt 2>&1

echo "******************************** ■  edited by security@C.A.S.co.kr  ■  ***************************" >> vul5.txt 2>&1
echo " " >> vul5.txt 2>&1
echo " " >> vul5.txt 2>&1
echo "********************************  Ⅰ. 취약 & 미점검 항목 출력   ****************************************" >> vul5.txt 2>&1
echo " " >> vul5.txt 2>&1
echo "********************************  Ⅱ. 전체 결과물 출력   ***********************************************" >> vul5.txt 2>&1
echo " " >> vul5.txt 2>&1
echo " " >> vul5.txt 2>&1
echo " " >> vul5.txt 2>&1

cat result_temp.txt | egrep "취약" | grep -v "컨설턴트" | awk '{print $2}' > VUL1.txt 2>&1
cat result_temp.txt | egrep "미점검" | grep -v "컨설턴트" | awk '{print $2}' > VUL2.txt 2>&1

echo "Ⅰ. 취약 & 미점검 항목 출력" >> vul5.txt 2>&1
echo " " >> vul5.txt 2>&1
echo "* Vul_Start " >> vul5.txt 2>&1
echo "===========================================" >> vul5.txt 2>&1
echo "☞ 취약 항목" >> vul5.txt 2>&1
echo "===========================================" >> vul5.txt 2>&1

for LIST in `uniq VUL1.txt`
 do
  cat list.txt | grep -w $LIST  >> vul5.txt 2>&1
done
echo "* Vul_End " >> vul5.txt 2>&1
echo " " >> vul5.txt 2>&1

echo "* Nocheck_Start " >> vul5.txt 2>&1
echo "===========================================" >> vul5.txt 2>&1
echo "☞ 미점검 항목" >> vul5.txt 2>&1
echo "===========================================" >> vul5.txt 2>&1
for LIST in `uniq VUL2.txt`
 do
  cat list.txt | grep -w $LIST  >> vul5.txt 2>&1
done
echo "* Nocheck_End " >> vul5.txt 2>&1
echo " " >> vul5.txt 2>&1
echo " " >> vul5.txt 2>&1
echo "===========================================" >> vul5.txt 2>&1
echo "☞ 취약 & 미점검 항목에 대한 세부내용" >> vul5.txt 2>&1
echo "===========================================" >> vul5.txt 2>&1
echo >> vul5.txt 2>&1
if [ ` cat result_temp.txt | grep "취약" | wc -l` -eq 0 ]
  then
    echo >> vul5.txt 2>&1
  else
      for vul in `uniq VUL1.txt`
        do
           awk '/'"$vul"' START/,/'"$vul"' END/' $CREATE_FILE >> vul5.txt 2>&1
           echo >> vul5.txt 2>&1
           echo >> vul5.txt 2>&1
        done
fi

if [ ` cat result_temp.txt | grep "미점검" | wc -l` -eq 0 ]
  then
    echo >> vul5.txt 2>&1
  else
      for vul in `uniq VUL2.txt`
        do
           awk '/'"$vul"' START/,/'"$vul"' END/' $CREATE_FILE >> vul5.txt 2>&1
           echo >> vul5.txt 2>&1
           echo >> vul5.txt 2>&1
        done
fi

echo "********************************************************************************************************" >> vul5.txt 2>&1
cat vul5.txt > result_temp2.txt 2>&1
rm -Rf vul5.txt
cat result_temp2.txt >> $CREATE_FILE_RESULT 2>&1
cat result_temp.txt >> $CREATE_FILE_RESULT 2>&1

rm -Rf result_temp.txt
rm -Rf result_temp2.txt
rm -Rf VUL.txt
rm -Rf VUL1.txt
rm -Rf VUL2.txt
rm -Rf list.txt
echo "**************************************** 취약한 항목만 출력 끝 *****************************************"


rm -Rf $CREATE_FILE 2>&1


echo " "
echo " "
echo " "
echo " "
echo "☞ Security Check Success!!"
echo " "
echo " "
echo " "
echo " "
