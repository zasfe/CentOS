#!/bin/sh

LANG=C
export LANG
touch centos.txt
clear

	echo "input your server password. ( It will not be saved. ) : "
	read -s passwd
	echo " "
	length=`expr length $passwd`

	alphabet=0
	number=0
	special_character=0
	null=0

	i=1
	# 입력받은 패스워드 쪼개기
	for i in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20;
		do
			tmp_passwd[i]=`grep -i "$" <<< $passwd | cut -c $i`
	done

	# 문자, 숫자, 특수문자 판별
	for i in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20;
		do
			if [ `echo ${tmp_passwd[i]} | egrep -i "[a-z]" | wc -l` -ge 1 ]
				then
					alphabet=`expr $alphabet + 1`
			else
				if [ `echo ${tmp_passwd[i]} | egrep -i "[0-9]" | wc -l` -ge 1 ]
					then
						number=`expr $number + 1`
				else
					if [ `echo ${tmp_passwd[i]} | grep -v "^ *$" | wc -l` -ge 1 ]
						then
							special_character=`expr $special_character + 1`
					else
						null=`expr $null + 1`
					fi
				fi
			fi
	done

echo "1. Do you use the specific path to record the 'syslogs'? [yes/no] "
read answer

if [ `grep -i "yes" <<< $answer | wc -l` -eq 1 ]
	then
		echo "Type the path. ex) : /var/adm/syslog : "
		echo "- syslog : "
		read answer2
elif [ `grep -i "no" <<< $answer | wc -l` -eq 1 ]
	then
		endif 2> /dev/null
else
	endif 2> /dev/null
fi	

echo "2. Does this server use an FTP service? [yes/no] "
read answer_ftp

echo "3. Is there a internal policy that patch the applications regularly? [yes/no] "
read answer_patch

# Function

  PASSWD=/etc/passwd
  GROUP=/etc/group
  SHADOW=/etc/shadow
  LOGIN_DEFS=/etc/login.defs
  PAM_D_SU=/etc/pam.d/su
  BIN_SU=/bin/su
  SERVICES=/etc/services
  PAM_D_LOGIN=/etc/pam.d/login
  PROFILE=/etc/profile
  VSFTPD_CONF=/etc/vsftpd/vsftpd.conf
  PROFTPD_CONF=/etc/proftpd/conf/proftpd.conf
  CSH_LOGIN=/etc/csh.login
  CSH_CSHRC=/etc/csh.cshrc
  EXPORTS=/etc/exports
  CRONTAB=/etc/crontab
  CRON_DAILY=/etc/cron.daily
  CRON_HOURLY=/etc/cron.hourly
  CRON_MONTHLY=/etc/cron.monthly
  CRON_WEEKLY=/etc/cron.weekly
  CRON=/var/spool/cron
  HOSTS=/etc/hosts
  XINETD_CONF=/etc/xinetd.conf
  XINETD_D=/etc/xinetd.d
  INETD_CONF=/etc/inetd.conf
  HOSTS_EQUIV=/etc/hosts.equiv
  ISSUE=/etc/issue
  ISSUE_NET=/etc/issue.net
  WELCOME_MSG=/etc/welcome.msg
  SENDMAIL_CF=/etc/mail/sendmail.cf
  SNMPD_CONF=/etc/snmp/snmpd.conf
  NAMED_CONF=/etc/named.conf
  SYSLOG_CONF=/etc/syslog.conf
  SULOG=/var/log/sulog
  
  GROUP_GREP=`ls -al $BIN_SU | awk '{print $4}'`

echo "========================================================================"
echo "===                     Linux Checklist Ver 2_1                      ==="
echo "========================================================================"
echo "===        Copyright 2013 Igloosec Co. Ltd. All right Reserved       ==="
echo "========================================================================"
echo " "
echo "========================================================================" >> centos.txt
echo "===                     Linux Checklist Ver 2_1                      ===" >> centos.txt
echo "========================================================================" >> centos.txt
echo "===        Copyright 2013 Igloosec Co. Ltd. All right Reserved       ===" >> centos.txt
echo "========================================================================" >> centos.txt
echo "===        made by ssjun@igloosec.com                                ===" >> centos.txt
echo "========================================================================" >> centos.txt
echo " "                                                                        >> centos.txt
echo "************************** System Information **************************"
echo "========================================================================" >> centos.txt
echo "===                        System Information                        ===" >> centos.txt
echo "========================================================================" >> centos.txt
echo " "                                                                        >> centos.txt

echo "-------------------- Start Time ----------------------------------------" >> centos.txt
date                                                                            >> centos.txt
echo " "                                                                        >> centos.txt

echo "-------------------- System Information Query Start --------------------" >> centos.txt
echo " "                                                                        >> centos.txt

echo "-------------------- uname -a ------------------------------------------" >> centos.txt
uname -a                                                                        >> centos.txt
echo " "                                                                        >> centos.txt

echo "-------------------- df -k ---------------------------------------------" >> centos.txt
df -k                                                                           >> centos.txt
echo " "                                                                        >> centos.txt

echo "-------------------- ifconfig -a ---------------------------------------" >> centos.txt
ifconfig -a                                                                     >> centos.txt
echo " "                                                                        >> centos.txt

echo "-------------------- cat /etc/hosts ------------------------------------" >> centos.txt
cat /etc/hosts                                                                  >> centos.txt
echo " "                                                                        >> centos.txt

echo "-------------------- netstat -rn ---------------------------------------" >> centos.txt
netstat -rn                                                                     >> centos.txt
echo " "                                                                        >> centos.txt

echo "-------------------- cat /etc/passwd -----------------------------------" >> centos.txt
cat /etc/passwd                                                                 >> centos.txt
echo " "                                                                        >> centos.txt

echo "-------------------- netstat -an ---------------------------------------" >> centos.txt
netstat -an | egrep -i "LISTEN"                                                 >> centos.txt
echo " "                                                                        >> centos.txt

echo "-------------------- System Information Query End ----------------------" >> centos.txt
echo " "                                                                        >> centos.txt
echo " "                                                                        >> centos.txt
echo " "                                                                        >> centos.txt

echo "*************************** Checklist  1.1. ****************************"
echo "========================================================================" >> centos.txt
echo "▶▶  Checklist  1.1.                                                " >> centos.txt

echo "=========================================================■   Result : N/A   ■" >> centos.txt
Array_Checklist_1_Result[0]="N/A"

echo "  :: 기준 - 모든 계정에 패스워드가 존재하면 양호                        " >> centos.txt
echo "========================================================================" >> centos.txt
echo " "                                                                        >> centos.txt

echo "[ /etc/shadow ]"                            				>> centos.txt
if [ -f $SHADOW ]
	then
		cat $SHADOW							>> centos.txt
else
	echo "/etc/shadow : File doesn't exist"					>> centos.txt
fi
echo " "                                                                        >> centos.txt 
echo " "                                                                        >> centos.txt 


echo "*************************** Checklist  1.2. ****************************"
echo "========================================================================" >> centos.txt
echo "▶▶  Checklist  1.2.                                                " >> centos.txt

if [ `awk -F: '$3==0 { print $1 }' $PASSWD | grep -v "root" | wc -l` -eq 0 ]
	then
		echo "=========================================================■   Result : 양호   ■" >> centos.txt
		Array_Checklist_1_Result[1]="양호"
else
	echo "=========================================================■   Result : 취약   ■" >> centos.txt
	Array_Checklist_1_Result[1]="취약"
fi

echo "  :: 기준 - uid 가 root 계정만이 0이면 양호                             " >> centos.txt
echo "========================================================================" >> centos.txt
echo " "                                                                        >> centos.txt

echo "[ /etc/passwd ]"                                                          >> centos.txt
if [ -f $PASSWD ]
	then
		awk -F: '$3==0 { print $1 " -> "  $3 }' $PASSWD			>> centos.txt
else
	echo "/etc/passwd : File doesn't exist"					>> centos.txt
fi	
echo " "                                                                        >> centos.txt
echo " "                                                                        >> centos.txt


echo "*************************** Checklist  1.3. ****************************"
echo "========================================================================" >> centos.txt
echo "▶▶  Checklist  1.3.                                                " >> centos.txt

if [ `cat $PASSWD | egrep -i "lp|uucp|nuucp" | wc -l` -eq 0 ]
	then
		echo "=========================================================■   Result : 양호   ■" >> centos.txt
		Array_Checklist_1_Result[2]="양호"
else
	echo "=========================================================■   Result : 취약   ■" >> centos.txt
	Array_Checklist_1_Result[2]="취약"
fi

echo "  :: 기준 - lp, uucp, nuucp가 존재하지 않으면 양호                      " >> centos.txt
echo "========================================================================" >> centos.txt
echo " "                                                                        >> centos.txt

echo "[ /etc/passwd ]"                                                          >> centos.txt
if [ -f $PASSWD ]
	then
		if [ `cat $PASSWD | egrep -i "lp|uucp|nuucp" | wc -l` -gt 0 ]
			then
				cat $PASSWD | egrep -i "lp|uucp|nuucp"		>> centos.txt
		else
			echo "lp, uucp, nuucp account doesn't exist"		>> centos.txt
		fi
else
	echo "/etc/passwd : File doesn't exist"					>> centos.txt
fi
echo " "                                                                        >> centos.txt
echo " "                                                                        >> centos.txt


echo "*************************** Checklist  1.4. ****************************"
echo "========================================================================" >> centos.txt
echo "▶▶  Checklist  1.4.                                                " >> centos.txt

if [ `cat /etc/passwd | grep -i "^daemon" | grep "\/bin\/false" | wc -l` -ge 1 -a `cat /etc/passwd | grep -i "^bin" | grep "\/bin\/false" | wc -l` -ge 1 -a `cat /etc/passwd | grep -i "^sys" | grep "\/bin\/false" | wc -l` -ge 1 -a `cat /etc/passwd | grep -i "^adm" | grep "\/bin\/false" | wc -l` -ge 1 -a `cat /etc/passwd | grep -i "^listen" | grep "\/bin\/false" | wc -l` -ge 1 -a `cat /etc/passwd | grep -i "^nobody" | grep "\/bin\/false" | wc -l` -ge 1 -a `cat /etc/passwd | grep -i "^nobody4" | grep "\/bin\/false" | wc -l` -ge 1 -a `cat /etc/passwd | grep -i "^noaccess" | grep "\/bin\/false" | wc -l` -ge 1 -a `cat /etc/passwd | grep -i "^diag" | grep "\/bin\/false" | wc -l` -ge 1 -a `cat /etc/passwd | grep -i "^operator" | grep "\/bin\/false" | wc -l` -ge 1 -a `cat /etc/passwd | grep -i "^game" | grep "\/bin\/false" | wc -l` -ge 1 -a `cat /etc/passwd | grep -i "^gopher" | grep "\/bin\/false" | wc -l` -ge 1 ]
	then
		echo "=========================================================■   Result : 양호   ■" >> centos.txt
		Array_Checklist_1_Result[3]="양호"
else
	echo "=========================================================■   Result : 취약   ■" >> centos.txt
	Array_Checklist_1_Result[3]="취약"
fi

echo "  :: 기준 - 로그인이 필요없는 계정에 /bin/false가 부여되었으면 양호" >> centos.txt
echo "[daemon, bin, sys, adm, listen, nobody, nobody4, noaccess, diag, listen, operator, games, gopher]" >> centos.txt
echo "========================================================================" >> centos.txt
echo " "                                                                        >> centos.txt

echo "[ /etc/passwd ]"                                                          >> centos.txt
if [ -f $PASSWD ]
	then
	  if [ `cat $PASSWD | egrep -i "^daemon|^bin|^sys|^adm|^listen|^nobody|^nobody4|^noaccess|^diag|^operator|^game|^gopher" | wc -l` -gt 0 ]
	    then
	      cat $PASSWD | egrep "^daemon|^bin|^sys|^adm|^listen|^nobody|^nobody4|^noaccess|^diag|^operator|^games|^gopher" >> centos.txt
	  else
	    echo "daemon, bin, sys, adm, listen, nobody, nobody4, noaccess, diag, listen, operator, games, gopher account doesn't exist"  >> centos.txt
	  fi
else
	echo "/etc/passwd : File doesn't exist"					>> centos.txt
fi
echo " "                                                                        >> centos.txt
echo " "                                                                        >> centos.txt


echo "*************************** Checklist  1.5. ****************************"
echo "========================================================================" >> centos.txt
echo "▶▶  Checklist  1.5.                                                " >> centos.txt

if [ `ls -alL /etc/passwd | awk '{print $1}' | egrep "...x......|.....w....|......x...|........w.|.........x" | wc -l` -ge 1 ]
	then
		echo "=========================================================■   Result : 취약   ■" >> centos.txt
		Array_Checklist_1_Result[4]="취약"
else
	echo "=========================================================■   Result : 양호   ■" >> centos.txt
	Array_Checklist_1_Result[4]="양호"
fi

echo "  :: 기준 - /etc/passwd파일의 퍼미션이 644 또는 444면 양호              " >> centos.txt
echo "========================================================================" >> centos.txt
echo " "                                                                        >> centos.txt

echo "[ /etc/passwd ]"								>> centos.txt
if [ -f $PASSWD ]
	then
		ls -alL $PASSWD							>> centos.txt
else
	echo "/etc/passwd : File doesn't exist"					>> centos.txt
fi
echo " "                                                                        >> centos.txt
echo " "                                                                        >> centos.txt


echo "*************************** Checklist  1.6. ****************************"
echo "========================================================================" >> centos.txt
echo "▶▶  Checklist  1.6.                                                " >> centos.txt

if [ `ls -alL /etc/group | awk '{print $1}' | egrep "...x......|.....w....|......x...|........w.|.........x" | wc -l` -ge 1 ]
	then
		echo "=========================================================■   Result : 취약   ■" >> centos.txt
		Array_Checklist_1_Result[5]="취약"
else
	echo "=========================================================■   Result : 양호   ■" >> centos.txt
	Array_Checklist_1_Result[5]="양호"
fi

echo "  :: 기준 - /etc/group파일의 퍼미션이 644 또는 444면 양호               " >> centos.txt
echo "========================================================================" >> centos.txt
echo " "                                                                        >> centos.txt

echo "[ /etc/group ]"								>> centos.txt
if [ -f $GROUP ]
	then
		ls -alL $GROUP							>> centos.txt
else
	echo "/etc/group : File doesn't exist"					>> centos.txt
fi
echo " "                                                                        >> centos.txt
echo " "                                                                        >> centos.txt


echo "*************************** Checklist  1.7. ****************************"
echo "========================================================================" >> centos.txt
echo "▶▶  Checklist  1.7.                                                " >> centos.txt

if [ `ls -alL /etc/shadow | awk '{print $1}' | egrep "...x......|....r.....|.....w....|......x...|....r.....|........w.|.........x" | wc -l` -ge 1 ]
	then
		echo "=========================================================■   Result : 취약   ■" >> centos.txt
		Array_Checklist_1_Result[6]="취약"
else
	echo "=========================================================■   Result : 양호   ■" >> centos.txt
	Array_Checklist_1_Result[6]="양호"
fi

echo "  :: 기준 - /etc/shadow파일의 퍼미션이 400 또는 600면 양호              " >> centos.txt
echo "========================================================================" >> centos.txt
echo " "                                                                        >> centos.txt

echo "[ /etc/shadow ]"								>> centos.txt
if [ -f $SHADOW ]
	then
		ls -alL $SHADOW							>> centos.txt
else
	echo "/etc/shadow : File doesn't exist"					>> centos.txt
fi	
echo " "                                                                        >> centos.txt
echo " "                                                                        >> centos.txt


echo "*************************** Checklist  1.8. ****************************"
echo "========================================================================" >> centos.txt
echo "▶▶  Checklist  1.8.                                                " >> centos.txt

if [ `cat $LOGIN_DEFS | grep -i "PASS_MIN_LEN" | grep -v "#" | awk '{print $2}'` -ge 8 ]
	then
			echo "=========================================================■   Result : 양호   ■" >> centos.txt
			Array_Checklist_1_Result[7]="양호"
else
        echo "=========================================================■   Result : 취약   ■" >> centos.txt
	Array_Checklist_1_Result[7]="취약"
fi

echo "  :: 기준 - PASS_MIN_LEN이 8이상이면 양호                               " >> centos.txt
echo "========================================================================" >> centos.txt
echo " "									>> centos.txt 

echo "[ /etc/login.defs ]"                                                      >> centos.txt
if [ -f $LOGIN_DEFS ]
	then
		if [ `grep -v '^ *#' $LOGIN_DEFS | grep -i "PASS_MIN_LEN" | wc -l` -gt 0 ]
			then
				grep -v '^ *#' $LOGIN_DEFS | grep -i "PASS_MIN_LEN" >> centos.txt
		else
			echo "PASS_MIN_LEN configuration doesn't exist"		>> centos.txt
		fi
else
	echo "/etc/login.defs : File doesn't exist"				>> centos.txt
fi
echo " "                                                                        >> centos.txt
echo " "                                                                        >> centos.txt


echo "*************************** Checklist  1.9. ****************************"
echo "========================================================================" >> centos.txt
echo "▶▶  Checklist  1.9.                                                " >> centos.txt

if [ `cat $LOGIN_DEFS | grep -i "PASS_MAX_DAY" | grep -v "#" | awk '{print $2}'` -le 90 ]
	then
    echo "=========================================================■   Result : 양호   ■" >> centos.txt
    Array_Checklist_1_Result[8]="양호"
else
  echo "=========================================================■   Result : 취약   ■" >> centos.txt
	Array_Checklist_1_Result[8]="취약"
fi

echo "  :: 기준 - PASS_MAX_DAYS가 90이하이면 양호                             " >> centos.txt
echo "========================================================================" >> centos.txt
echo " "                                                                        >> centos.txt

echo "[ /etc/login.defs ]"                                                      >> centos.txt
if [ -f $LOGIN_DEFS ]
	then
		if [ `grep -v '^ *#' $LOGIN_DEFS | grep -i "PASS_MAX_DAY" | wc -l` -gt 0 ]
			then
				grep -v '^ *#' $LOGIN_DEFS | grep -i "PASS_MAX_DAY" >> centos.txt
		else
			echo "PASS_MAX_DAY configuration doesn't exist"		>> centos.txt
		fi
else
	echo "/etc/login.defs : File doesn't exist"				>> centos.txt
fi
echo " "                                                                        >> centos.txt
echo " "                                                                        >> centos.txt


echo "*************************** Checklist  1.10. ***************************"
echo "========================================================================" >> centos.txt
echo "▶▶  Checklist  1.10.                                               " >> centos.txt

if [ `echo $length` -ge 8 -o `echo $length` -le 9 ]
	then
		if [ `echo $alphabet $number $special_character | grep -w "0" | wc -l` -eq 0 ]
			then
				echo "=========================================================■   Result : 양호   ■" >> centos.txt
				Array_Checklist_1_Result[9]="양호"
		else
		        echo "=========================================================■   Result : 취약   ■" >> centos.txt
			Array_Checklist_1_Result[9]="취약"
		fi
elif  [ `echo $length` -ge 10 ]
	then 
		if [ `echo $alphabet $number $special_character | grep -w "0" | wc -l` -ge 1 ]
			then
				echo "=========================================================■   Result : 취약   ■" >> centos.txt
				Array_Checklist_1_Result[9]="취약"
		else
			echo "=========================================================■   Result : 양호   ■" >> centos.txt
			Array_Checklist_1_Result[9]="양호"
		fi
else
        echo "=========================================================■   Result : 취약   ■" >> centos.txt
	Array_Checklist_1_Result[9]="취약"
fi

echo "  :: 기준 - 사용중인 암호가 8자리 이상 9자리 이하일 때 영대소문자, 숫자, 특수문자 중 3종류 이상으로 구성한 경우 양호" >> centos.txt
echo "            10자리 이상일 때 2종류 이상으로 구성한 경우 양호            " >> centos.txt
echo "========================================================================" >> centos.txt
echo " "                                                                        >> centos.txt

echo "[사용중인 암호 구성]"							>> centos.txt
echo -Length	: $length 자리							>> centos.txt
echo -Alphabet	: $alphabet 자리						>> centos.txt
echo -Number	: $number 자리							>> centos.txt
echo -Special	: $special_character 자리					>> centos.txt
echo " "                                                                        >> centos.txt
echo " "                                                                        >> centos.txt

echo "[ /etc/shadow ]"								>> centos.txt
if [ -f $SHADOW ]
	then
		cat $SHADOW							>> centos.txt
else
	echo "/etc/shadow : File doesn't exist"					>> centos.txt
fi	
echo " "                                                                        >> centos.txt
echo " "                                                                        >> centos.txt


echo "*************************** Checklist  2.1. ****************************"
echo "========================================================================" >> centos.txt
echo "▶▶  Checklist  2.1.                                                " >> centos.txt

if [ `cat $PAM_D_SU | grep "pam_wheel.so" | grep -v "#" | grep -v "trust" |  wc -l` -eq 0 ]
  then
    if [ `ls -alL /bin/su | awk '{print $1}' | egrep ".....w....|.......r..|........w.|.........x" | wc -l` -ge 1 ]
      then
	      echo "=========================================================■   Result : 취약   ■" >> centos.txt
	      Array_Checklist_2_Result[0]="취약"
	  else
        echo "=========================================================■   Result : 양호   ■" >> centos.txt
	Array_Checklist_2_Result[0]="양호"
    fi
else
	echo "=========================================================■   Result : 양호   ■" >> centos.txt
	Array_Checklist_2_Result[0]="양호"
fi

echo "  :: 기준 - /etc/pam.d/su 파일의 설정이 아래와 같을 경우 양호(주석제거) " >> centos.txt
echo " auth       required   /lib/security/pam_wheel.so debug group=wheel     " >> centos.txt
echo " auth       required   /lib/security/\$ISA/pam_wheel.so use_uid         " >> centos.txt
echo "  :: 파일이 없을 경우 /bin/su 권한이 4750이면 양호                      " >> centos.txt
echo "========================================================================" >> centos.txt
echo " "                                                                        >> centos.txt

echo "[ /etc/pam.d/su ]"							>> centos.txt
if [ -f $PAM_D_SU ]
	then
		if [ `cat $PAM_D_SU | grep "pam_wheel.so" | grep -v "trust" | wc -l` -gt 0 ]
			then
				cat $PAM_D_SU | grep "pam_wheel.so" | grep -v "trust" >> centos.txt
		else
			echo "pam_wheel.so configuration doesn't exist"		>> centos.txt
		fi
else
	echo "/etc/pam.d/su : File doesn't exist"				>> centos.txt
fi
echo " "									>> centos.txt
echo " "									>> centos.txt

echo "[ /bin/su ]"								>> centos.txt
if [ -f $BIN_SU ]
	then
		ls -al $BIN_SU 							>> centos.txt
else
	echo "/bin/su : File doesn't exist"				                                    >> centos.txt
fi
echo " "									                                                      >> centos.txt
echo " "									                                                      >> centos.txt

echo "[ /etc/group ]" 								                                          >> centos.txt
if [ -f $GROUP ]
	then
		if [ `cat $GROUP | grep -E "$GROUP_GREP" | wc -l` -gt 0 ]
			then
				cat $GROUP | grep -E "$GROUP_GREP"		                                  >> centos.txt
		else
			echo "configuration doesn't exist"			                                  >> centos.txt
		fi
else
	echo "/etc/group : File doesn't exist"				                                >> centos.txt
fi
echo " "                                                                        >> centos.txt
echo " "									                                                      >> centos.txt


echo "*************************** Checklist  2.2. ****************************"
echo "========================================================================" >> centos.txt
echo "▶▶  Checklist  2.2.                                                " >> centos.txt

if [ `netstat -natp | awk '{print $7}' | grep -i "telnet" | wc -l` -gt 0 ]
  then
    if [ `cat $PAM_D_LOGIN | grep -i "pam_securetty.so" | grep -v "#" | wc -l` -eq 0 ]
      then
	      echo "=========================================================■   Result : 취약   ■" >> centos.txt
      	Array_Checklist_2_Result[1]="취약"
    else
		  echo "=========================================================■   Result : 양호   ■" >> centos.txt
		  Array_Checklist_2_Result[1]="양호"
		fi
else
  echo "=========================================================■   Result : 양호   ■" >> centos.txt
  Array_Checklist_2_Result[1]="양호"
fi

echo "  :: 기준 - pam_securetty.so 주석이 제거되었으면 양호                   " >> centos.txt
echo "========================================================================" >> centos.txt
echo " "                                                                        >> centos.txt

echo "[ Telnet Service ]"							                                          >> centos.txt
if [ `netstat -natp | awk '{print $7}' | grep -i "telnet" | wc -l` -ge 1 ]
	then
		echo "Telnet Service is Activated"	 			                                  >> centos.txt
else
	echo "Telnet Sevice is Inactive"					                                    >> centos.txt
fi
echo " "									                                                      >> centos.txt
echo " "									                                                      >> centos.txt

echo "[ /etc/pam.d/login ]"							                                        >> centos.txt
if [ -f $PAM_D_LOGIN ]
	then
		if [ `cat $PAM_D_LOGIN | grep "pam_securetty.so" | grep -v "#" | wc -l` -gt 0 ]
			then
				cat $PAM_D_LOGIN | grep "pam_securetty.so" | grep -v "#"                >> centos.txt
		else
			echo "pam_securetty.so doesn't exist"			                                >> centos.txt
		fi
else
	echo "/etc/pam.d/login : File doesn't exist"				                          >> centos.txt
fi	
echo " "                                                                        >> centos.txt
echo " "									                                                      >> centos.txt


echo "*************************** Checklist  2.3. ****************************"
echo "========================================================================" >> centos.txt
echo "▶▶  Checklist  2.3.                                                " >> centos.txt

if [ `netstat -natp | awk '{print $7}' | grep -i "ftp" | wc -l` -gt 0 ]
	then
		if [ `cat /etc/ftpusers /etc/ftpd/ftpusers /etc/vsftpd/ftpusers /etc/vsftpd/user_list /etc/vsftpd.ftpusers /etc/vsftpd.user_list | grep -i "root" | grep -v "#" | wc -l` -eq 0 ]
			then
				echo "=========================================================■   Result : 취약   ■" >> centos.txt
				Array_Checklist_2_Result[2]="취약"
		else
			echo "=========================================================■   Result : 양호   ■" >> centos.txt
			Array_Checklist_2_Result[2]="양호"
		fi
else
	echo "=========================================================■   Result : 양호   ■" >> centos.txt
	Array_Checklist_2_Result[2]="양호"
fi

echo " :: 기준 - ftp가 사용중이지 않거나, ftpuser에 root가 존재하면 양호                                         " >> centos.txt
echo "========================================================================" >> centos.txt
echo " "                                                                        >> centos.txt

echo "[ Ftp Service ]"								                                          >> centos.txt
if [ `netstat -natp | awk '{print $7}' | grep -i "ftp" | wc -l` -ge 1 ]
	then
		echo "Ftp Service is Activated"	 				                                    >> centos.txt
	else
		echo "Ftp Sevice is Inactive"					                                      >> centos.txt
fi
echo " "									                                                      >> centos.txt
echo " "									                                                      >> centos.txt

echo "[ ftpusers ]"								                                              >> centos.txt
if [ -f /etc/ftpusers ]
	then
		echo "- /etc/vsftpd/ftpusers"							                                      >> centos.txt
		if [ `cat /etc/vsftpd/ftpusers | grep "root" | wc -l` -gt 0 ]
			then
				cat /etc/vsftpd/ftpusers | grep "root"		                              >> centos.txt
				echo " "									 >> centos.txt
				echo " "							>> centos.txt

		else
			echo "root doesn't exist"				                                          >> centos.txt
			echo " "									 >> centos.txt
			echo " "							>> centos.txt
		fi
else
	endif 2> /dev/null
fi

if [ -f /etc/ftpusers ]
	then
		echo "- /etc/ftpusers"							                                      >> centos.txt
		if [ `cat /etc/ftpusers | grep "root" | wc -l` -gt 0 ]
			then
				cat /etc/ftpusers | grep "root"		                              >> centos.txt
				echo " "									 >> centos.txt
				echo " "							>> centos.txt
		else
			echo "root doesn't exist"				                                          >> centos.txt
			echo " "									 >> centos.txt
			echo " "							>> centos.txt
		fi
else
	endif 2> /dev/null
fi

if [ -f /etc/ftpd/ftpusers ]
	then
		echo "- /etc/ftpd/ftpusers"							                                        >> centos.txt
		if [ `cat /etc/ftpd/ftpusers | grep "root" | wc -l` -gt 0 ]
			then
				cat /etc/ftpd/ftpusers | grep "root"		                                >> centos.txt
				echo " "									 >> centos.txt
				echo " "							>> centos.txt
		else
			echo "root doesn't exist"				                                          >> centos.txt
			echo " "									 >> centos.txt
			echo " "							>> centos.txt
		fi
else
	endif 2> /dev/null
fi

if [ -f /etc/vsftpd/ftpusers ]
	then
		echo "- /etc/vsftpd/ftpusers"							                                      >> centos.txt
		if [ `cat /etc/vsftpd/ftpusers | grep "root" | wc -l` -gt 0 ]
			then
				cat /etc/vsftpd/ftpusers | grep "root"		                              >> centos.txt
				echo " "									 >> centos.txt
				echo " "							>> centos.txt
		else
			echo "root doesn't exist"				                                          >> centos.txt
			echo " "									 >> centos.txt
			echo " "							>> centos.txt
		fi
else
	endif 2> /dev/null
fi

if [ -f /etc/vsftpd/user_list ]
	then
		echo "- /etc/vsftpd/user_list"							                                    >> centos.txt
		if [ `cat /etc/vsftpd/user_list | grep "root" | wc -l` -gt 0 ]
			then
				cat /etc/vsftpd/user_list | grep "root"		                              >> centos.txt
				echo " "									 >> centos.txt
				echo " "							>> centos.txt
		else
			echo "root doesn't exist"				                                          >> centos.txt
			echo " "									 >> centos.txt
			echo " "							>> centos.txt
		fi
else
	endif 2> /dev/null
fi

if [ -f /etc/vsftpd.ftpusers ]
	then
		echo "- /etc/vsftpd.ftpusers"							                                      >> centos.txt
		if [ `cat /etc/vsftpd.ftpusers | grep "root" | wc -l` -gt 0 ]
			then
				cat /etc/vsftpd.ftpusers | grep "root"		                              >> centos.txt
				echo " "									 >> centos.txt
				echo " "							>> centos.txt
		else
			echo "root doesn't exist"				                                          >> centos.txt
			echo " "									 >> centos.txt
			echo " "							>> centos.txt
		fi
else
	endif 2> /dev/null
fi

if [ -f /etc/vsftpd.user_list ]
	then
		echo "- /etc/vsftpd.user_list"							                                    >> centos.txt
		if [ `cat /etc/vsftpd.user_list | grep "root" | wc -l` -gt 0 ]
			then
				cat /etc/vsftpd.user_list | grep "root"		                              >> centos.txt
				echo " "									 >> centos.txt
				echo " "							>> centos.txt
		else
			echo "root doesn't exist"				                                          >> centos.txt
			echo " "									 >> centos.txt
			echo " "							>> centos.txt
		fi
else
	endif 2> /dev/null
fi

echo "*************************** Checklist  2.4. ****************************"
echo "========================================================================" >> centos.txt
echo "▶▶  Checklist  2.4.                                                " >> centos.txt

if [ `ps -ef | grep -i "ftp" | grep -v grep | wc -l` -gt 0 ]
	then
		if [ `cat /etc/passwd | egrep -i "^ftp|^anonymous" | wc -l` -gt 0 ]
			then
				if [ `cat /etc/vsftpd/vsftpd.conf | grep -i "anonymous_enable" | grep -i "yes" | wc -l` -gt 0 ]
					then
						echo "=========================================================■   Result : 취약   ■" >> centos.txt
						Array_Checklist_2_Result[3]="취약"
				else
					echo "=========================================================■   Result : 양호   ■" >> centos.txt
					Array_Checklist_2_Result[3]="양호"
				fi
		else
			echo "=========================================================■   Result : 양호   ■" >> centos.txt
			Array_Checklist_2_Result[3]="양호"
		fi
else
	echo "=========================================================■   Result : 양호   ■" >> centos.txt
	Array_Checklist_2_Result[3]="양호"
fi

echo "  :: 기준 - ftp를 사용하지 않거나, ftp 계정이 존재 하지 않을 경우 양호     " >> centos.txt
echo "            ftp 계정이 존재할 경우, anonymous_enable이 NO일 경우 양호       " >> centos.txt
echo "========================================================================" >> centos.txt
echo " "                                                                        >> centos.txt

echo "[ FTP Service ]"								                                          >> centos.txt
if [ `netstat -natp | awk '{print $7}' | grep -i "ftp" | wc -l` -ge 1 ]
	then
		netstat -natp | awk '{print $7}' | grep -i "ftp"	>> centos.txt
else
	echo "FTP Sevice is Inactive"						                                      >> centos.txt
fi
echo " "									                                                      >> centos.txt
echo " "									                                                      >> centos.txt

echo "[ /etc/passwd ]"								                                          >> centos.txt
echo "- FTP Account"								                                            >> centos.txt
if [ -f $PASSWD ]
	then
		if [ `cat $PASSWD | awk -F ":" '{print $1}' | egrep -i "ftp|anonymous" | wc -l` -ge 1 ]
			then
				cat $PASSWD | awk -F ":" '{print $1}' | egrep -i "ftp|anonymous"        >> centos.txt
		else
			echo "FTP Account doesn't exist"			                                    >> centos.txt
		fi
else
	echo "/etc/passwd : File doesn't exist"					                              >> centos.txt
fi
echo " "									                                                      >> centos.txt
echo " "									                                                      >> centos.txt

echo "[ /etc/vsftpd/vsftpd.conf ]"						                                  >> centos.txt
if [ -f $VSFTPD_CONF ]
	then
		if [ `cat $VSFTPD_CONF | grep "anonymous_enable" | wc -l` -gt 0 ]
			then
				cat $VSFTPD_CONF | grep "anonymous_enable"	                            >> centos.txt
		else
			echo "anonymous_enable doesn't exist"			                                >> centos.txt
		fi
else
	echo "/etc/vsftpd/vsftpd.conf : File doesn't exist"			                      >> centos.txt
fi
echo " "									                                                      >> centos.txt
echo " "									                                                      >> centos.txt


echo "*************************** Checklist  2.5. ****************************"
echo "========================================================================" >> centos.txt
echo "▶▶  Checklist  2.5.                                                " >> centos.txt

if [ `echo $shell | grep -i "csh" | wc -l` -eq 0 ]
then
	if [ `cat /etc/profile | grep -i "TMOUT" | egrep "[1-9]|[0-9][0-9]|[0-2][0-9][0-9]|300" | grep -v "#" | wc -l` -eq 1 ]
		then
			echo "=========================================================■   Result : 양호   ■" >> centos.txt
			Array_Checklist_2_Result[4]="양호"
	else
		echo "=========================================================■   Result : 취약   ■" >> centos.txt
		Array_Checklist_2_Result[4]="취약"
	fi
else
	if [ `cat /etc/csh.login | egrep -i "autologout" | egrep "[1-5]" | grep -v "#" | wc -l` -eq 1 ]
		then
			echo "=========================================================■   Result : 양호   ■" >> centos.txt
			Array_Checklist_2_Result[4]="양호"
	else
		echo "=========================================================■   Result : 취약   ■" >> centos.txt
		Array_Checklist_2_Result[4]="취약"
	fi
fi

echo "  :: 기준 - TMOUT이 300이하, csh에서는 autologout이 5이하면 양호                  " >> centos.txt
echo "========================================================================" >> centos.txt
echo " "                                                                        >> centos.txt

echo "[ /etc/profile ]"								                                          >> centos.txt
if [ -f $PROFILE ]
	then
		if [ `cat /$PROFILE | grep -i "TMOUT" | wc -l` -gt 0 ]
			then
				cat $PROFILE | grep -i "TMOUT"			                                    >> centos.txt
		else
			echo "TMOUT doesn't exist"				                                        >> centos.txt
		fi
else
	echo "/etc/profile : File doesn't exist"				                              >> centos.txt
fi
echo " "									                                                      >> centos.txt
echo " "									                                                      >> centos.txt

echo "[ /etc/csh.login ]"							                                          >> centos.txt
if [ -f $CSH_LOGIN ]
	then
		if [ `cat $CSH_LOGIN | egrep -i "autologout" | wc -l` -gt 0 ]
			then
				cat $CSH_LOGIN | egrep -i "autologout"                            >> centos.txt
		else
			echo "TMOUT doesn't exist"				                                        >> centos.txt
		fi
else
	echo "/etc/csh.login : File doesn't exist"				                            >> centos.txt
fi
echo " "									                                                      >> centos.txt
echo " "									                                                      >> centos.txt


echo "*************************** Checklist  2.6. ****************************"
echo "========================================================================" >> centos.txt
echo "▶▶  Checklist  2.6.                                                " >> centos.txt

if [ `find $XINETD_D/* | egrep -w "rsh|rlogin|rexec" | xargs grep -i "disable" | grep -i "no" | wc -l` -gt 0 ]
	then
		echo "=========================================================■   Result : 취약   ■" >> centos.txt
		Array_Checklist_2_Result[5]="취약"
else
	echo "=========================================================■   Result : 양호   ■" >> centos.txt
	Array_Checklist_2_Result[5]="양호"
fi

echo "  :: 기준 - rsh, rlogin, rexec (shell, login, exec) 구동중이지 않을 경우" >> centos.txt
echo "========================================================================" >> centos.txt
echo " "                                                                        >> centos.txt

echo "[ rsh, rlogin, rexec Process ]"						                                >> centos.txt
echo "- /etc/xinetd.d"								                                          >> centos.txt
if [ -d $XINETD_D ]
	then
		if [ `find $XINETD_D/* | egrep -w "rsh|rlogin|rexec" | xargs grep -i "disable" | grep -i "no" | wc -l` -gt 0 ]
			then
				find $XINETD_D/* | egrep -w "rsh|rlogin|rexec" | xargs grep -i "disable" | grep -i "no"	>> centos.txt
		else
			echo "rsh, rlogin, rexec Sevice is Inactive"		                          >> centos.txt
		fi
else
	echo "/etc/xinetd.d : Directory doesn't exist"				                        >> centos.txt
fi
echo " "									                                                      >> centos.txt
echo " "									                                                      >> centos.txt


echo "*************************** Checklist  2.7. ****************************"
echo "========================================================================" >> centos.txt
echo "▶▶  Checklist  2.7.                                                " >> centos.txt

if [ `ps -ef | grep "nfsd" | egrep -v "statdaemon|automountd|emi" | grep -v "grep" | wc -l` -gt 0 ]
	then
		if [ `cat /etc/exports | grep -v "^#" | grep -v "^ *$" | wc -l` -gt 0 ]
			then
				echo "=========================================================■   Result : 취약   ■" >> centos.txt
				Array_Checklist_2_Result[6]="취약"
		else
			echo "=========================================================■   Result : 양호   ■" >> centos.txt
			Array_Checklist_2_Result[6]="양호"
		fi
else
	echo "=========================================================■   Result : 양호   ■" >> centos.txt
	Array_Checklist_2_Result[6]="양호"
fi

echo "  :: 기준 - NFS 공유관련 취약점 점검(Everyone 공유가 있으면 취약)       " >> centos.txt
echo "========================================================================" >> centos.txt
echo " "                                                                        >> centos.txt

echo "[ NFS Service ]"								                                          >> centos.txt
if [ `ps -ef | grep "nfsd" | egrep -v "statdaemon|automountd|emi" | grep -v "grep" | wc -l` -gt 0 ]
	then
		ps -ef | grep "nfsd" | egrep -v "statdaemon|automountd|emi" | grep -v "grep"	>> centos.txt
	else
		echo "NFS Service is Inactive"					                                    >> centos.txt
fi
echo " "									                                                      >> centos.txt
echo " "									                                                      >> centos.txt

echo "[ /etc/exports ]"								                                          >> centos.txt
if [ -f $EXPORTS ]
	then
		if [ `cat $EXPORTS | grep -v "^#" | grep -v "^ *$" | wc -l` -gt 0 ]
			then
				cat $EXPORTS | grep -v "^#" | grep -v "^ *$"	                          >> centos.txt
		else
			echo "Directory doesn't exist"				                                    >> centos.txt
		fi
else
	echo "/etc/exports : File doesn't exist"				                              >> centos.txt
fi
echo " "									                                                      >> centos.txt
echo " "									                                                      >> centos.txt


echo "*************************** Checklist  3.1. ****************************"
echo "========================================================================" >> centos.txt
echo "▶▶  Checklist  3.1.                                                " >> centos.txt

if [ `ls -alL /etc/crontab /etc/cron.daily/* /etc/cron.hourly/* /etc/cron.monthly/* /etc/cron.weekly/* /var/spool/cron/* /var/spool/cron/crontabs/* /etc/cron.d/* /var/adm/cron/* | awk '{print $1}' | grep "........w." | wc -l` -eq 0 ]
	then
			echo "=========================================================■   Result : 양호   ■" >> centos.txt
			Array_Checklist_3_Result[0]="양호"
else
        echo "=========================================================■   Result : 취약   ■" >> centos.txt
	Array_Checklist_3_Result[0]="취약"
fi

echo "  :: 기준 - crontab에 관련된 파일의 권한에 other 쓰기권한이 없으면 양호 " >> centos.txt
echo "========================================================================" >> centos.txt
echo " "                                                                        >> centos.txt

echo "[ /etc/crontab ]"		                                 		                  >> centos.txt
if [ -f $CRONTAB ]
	then
		ls -alL $CRONTAB | head -n 10						                                                >> centos.txt
else
	echo "/etc/crontab : File doesn't exist"			                                >> centos.txt
fi
echo " "                                                                        >> centos.txt
echo " "                                                                        >> centos.txt

echo "[ /etc/cron.daily ]"		                               		                >> centos.txt
if [ -d $CRON_DAILY/ ]
	then
		ls -alL $CRON_DAILY/* | head -n 10						                                            >> centos.txt
else
	echo "/etc/cron.daily : Directory doesn't exist"			                        >> centos.txt
fi
echo " "                                                                        >> centos.txt

echo "[ /etc/cron.hourly ]"		                           	    	                >> centos.txt
if [ -d $CRON_HOURLY ]
	then
		ls -alL $CRON_HOURLY/* | head -n 10					                                          >> centos.txt
else
	echo "/etc/cron.hourly : Directory doesn't exist"			                        >> centos.txt
fi
echo " "                                                                        >> centos.txt
echo " "                                                                        >> centos.txt

echo "[ /etc/cron.monthly ]"		                           		                  >> centos.txt
if [ -d $CRON_MONTHLY ]
	then
		ls -alL $CRON_MONTHLY/* | head -n 10						                                          >> centos.txt
else
	echo "/etc/cron.monthly : Directory doesn't exist"			                      >> centos.txt
fi
echo " "                                                                        >> centos.txt
echo " "                                                                        >> centos.txt

echo "[ /etc/cron.weekly ]"		                                 	                >> centos.txt
if [ -d $CRON_WEEKLY ]
	then
		ls -alL $CRON_WEEKLY/* | head -n 10				                                            >> centos.txt
else
	echo "/etc/cron.weekly : Directory doesn't exist"			                        >> centos.txt
fi
echo " "                                                                        >> centos.txt
echo " "                                                                        >> centos.txt

echo "[ /var/spool/cron ]"		     		                                          >> centos.txt
if [ -d $CRON ]
	then
		ls -alL $CRON/* | head -n 10							                                                >> centos.txt
else
	echo "/var/spool/cron : Directory doesn't exist"			                        >> centos.txt
fi
echo " "                                                                        >> centos.txt
echo " "                                                                        >> centos.txt


echo "*************************** Checklist  3.2. ****************************"
echo "========================================================================" >> centos.txt
echo "▶▶  Checklist  3.2.                                                " >> centos.txt

if [ `echo $PATH | grep "\.:" | wc -l` -eq 0 ]
	then
		echo "=========================================================■   Result : 양호   ■" >> centos.txt
		Array_Checklist_3_Result[1]="양호"
else
	echo "=========================================================■   Result : 취약   ■" >> centos.txt
	Array_Checklist_3_Result[1]="취약"
fi

echo "  :: 기준 - . 이 없거나, PATH 맨 뒤에 존재하면 양호                     " >> centos.txt
echo "========================================================================" >> centos.txt
echo " "                                                                        >> centos.txt

echo "[ PATH ]"				                                 	                        >> centos.txt
echo $PATH									                                                    >> centos.txt
echo " "                                                                        >> centos.txt
echo " "                                                                        >> centos.txt


echo "*************************** Checklist  3.3. ****************************"
echo "========================================================================" >> centos.txt
echo "▶▶  Checklist  3.3.                                                " >> centos.txt

if [ `umask` -eq 22 -o `umask` -eq 27 ]
	then
		echo "=========================================================■   Result : 양호   ■" >> centos.txt
		Array_Checklist_3_Result[2]="양호"
else
	echo "=========================================================■   Result : 취약   ■" >> centos.txt
	Array_Checklist_3_Result[2]="취약"
fi
echo "  :: 기준 - UMASK 값이 022 또는 027이면 양호                            " >> centos.txt
echo "========================================================================" >> centos.txt
echo " "                                                                        >> centos.txt

echo "[ umask ]"								                                                >> centos.txt
umask										                                                        >> centos.txt
echo " "									                                                      >> centos.txt
echo " "									                                                      >> centos.txt

echo "[ /etc/profile ]"								                                          >> centos.txt
if [ -f $PROFILE ]
	then
		if [ `cat $PROFILE | grep -i umask | grep -v "^#" | wc -l` -gt 0 ]
			then
				cat $PROFILE | grep -i umask | grep -v "^#"	                            >> centos.txt
		else
			echo "umask doesn't exist"				                                        >> centos.txt
		fi
else
	echo "/etc/profile : File doesn't exist"				                              >> centos.txt
fi
echo " "									                                                      >> centos.txt
echo " "									                                                      >> centos.txt

echo "[ /etc/csh.login ]"							                                          >> centos.txt
if [ -f $CSH_LOGIN ]
	then
		if [ `cat $CSH_LOGIN | grep -i umask | grep -v "^#" | wc -l` -gt 0 ]
			then
				cat $CSH_LOGIN | grep -i umask | grep -v "^#"	                          >> centos.txt
		else
			echo "umask doesn't exist"				                                        >> centos.txt
		fi
else
	echo "/etc/csh.login : File doesn't exist"				                            >> centos.txt
fi
echo " "									                                                      >> centos.txt
echo " "									                                                      >> centos.txt

echo "[ /etc/csh.cshrc ]"							                                          >> centos.txt
if [ -f $CSH_CSHRC ]
	then
		if [ `cat $CSH_CSHRC | grep -i umask | grep -v "^#" | wc -l` -gt 0 ]
			then
				cat $CSH_CSHRC | grep -i umask | grep -v "^#"	                          >> centos.txt
		else
			echo "umask doesn't exist"				                                        >> centos.txt
		fi
else
	echo "/etc/csh.cshrc : File doesn't exist"				                            >> centos.txt
fi
echo " "									                                                      >> centos.txt
echo " "									                                                      >> centos.txt


echo "*************************** Checklist  3.4. ****************************"
echo "========================================================================" >> centos.txt
echo "▶▶  Checklist  3.4.                                                " >> centos.txt

if [ `ls -alL $HOSTS | awk '{print $1}' | grep "........w." | wc -l` -eq 0 ]
	then
		echo "=========================================================■   Result : 양호   ■" >> centos.txt
		Array_Checklist_3_Result[3]="양호"
else
       echo "=========================================================■   Result : 취약   ■" >> centos.txt
       Array_Checklist_3_Result[3]="취약"
fi

echo "  :: 기준 - /etc/hosts의 권한에 other 쓰기권한이 없으면 양호            " >> centos.txt
echo "========================================================================" >> centos.txt
echo " "                                                                        >> centos.txt

echo "[ /etc/hosts ]"								                                            >> centos.txt
if [ -f $HOSTS ]
	then
		ls -al $HOSTS						                                                    >> centos.txt
else
	echo "/etc/hosts : File doesn't exist"					                              >> centos.txt
fi
echo " "                                                                        >> centos.txt
echo " "                                                                        >> centos.txt


echo "*************************** Checklist  3.5. ****************************"
echo "========================================================================" >> centos.txt
echo "▶▶  Checklist  3.5.                                                " >> centos.txt

if [ `ls -alL $XINETD_CONF $XINETD_D/* $XINETD_CONF /etc/inetd.conf | awk '{print $1}' | grep "........w." | wc -l` -eq 0 ]
	then
			echo "=========================================================■   Result : 양호   ■" >> centos.txt
			Array_Checklist_3_Result[4]="양호"
else
        echo "=========================================================■   Result : 취약   ■" >> centos.txt
	Array_Checklist_3_Result[4]="취약"
fi

echo " :: 기준 - /etc/xinetd.conf(inetd.conf) 파일의 권한에 other 쓰기권한이 없으면 양호  " >> centos.txt
echo "========================================================================" >> centos.txt
echo " "                                                                        >> centos.txt

echo "[ /etc/xinetd.conf ]"							                                        >> centos.txt
if [ -f /$XINETD_CONF ]
	then
		ls -alL $XINETD_CONF						                                            >> centos.txt
else
	echo "/etc/xinetd.conf : File doesn't exist"				                          >> centos.txt
fi
echo " "									                                                      >> centos.txt 
echo " "									                                                      >> centos.txt 

echo "[ /etc/xinetd.d ]"							                                          >> centos.txt
if [ -d $XINETD_D ]
	then
		ls -alL $XINETD_D/*						                                              >> centos.txt
else
	echo "/etc/xinetd.d : Directory doesn't exist"			  	                      >> centos.txt
fi
echo " "									                                                      >> centos.txt 
echo " "									                                                      >> centos.txt 

echo "[ /etc/inetd.conf ]"							                                        >> centos.txt
if [ -f $INETD_CONF ]
	then
		ls -alL $INETD_CONF						                                              >> centos.txt
else
	echo "/etc/inetd.conf : File doesn't exist"				                            >> centos.txt
fi
echo " "									                                                      >> centos.txt 
echo " "									                                                      >> centos.txt 


echo "*************************** Checklist  3.6. ****************************"
echo "========================================================================" >> centos.txt
echo "▶▶  Checklist  3.6.                                                " >> centos.txt

if [ `ls -alL /etc/hosts.equiv | awk '{print $1}' | grep "........w." | wc -l` -eq 0 ]
	then
			echo "=========================================================■   Result : 양호   ■" >> centos.txt
			Array_Checklist_3_Result[5]="양호"
else
        echo "=========================================================■   Result : 취약   ■" >> centos.txt
	Array_Checklist_3_Result[5]="취약"
fi

echo "  :: 기준 - /etc/hosts.equiv 파일의 권한에 other 쓰기권한이 없으면 양호 " >> centos.txt
echo "========================================================================" >> centos.txt
echo " "                                                                        >> centos.txt

echo "[ /etc/hosts.equiv ]"							                                        >> centos.txt
if [ -f $HOSTS_EQUIV ]
	then
		ls -alL $HOSTS_EQUIV					                                              >> centos.txt
else
	echo "/etc/hosts.equiv : File doesn't exist"				                          >> centos.txt
fi
echo " "                                                                        >> centos.txt
echo " "                                                                        >> centos.txt


echo "*************************** Checklist  4.1. ****************************"
echo "========================================================================" >> centos.txt
echo "▶▶  Checklist  4.1.                                                " >> centos.txt

if [ `ls -alL /etc/services | awk '{print $1}' | grep "........w." | wc -l` -eq 0 ]
	then
		echo "=========================================================■   Result : 양호   ■" >> centos.txt
		Array_Checklist_4_Result[0]="양호"
else
	echo "=========================================================■   Result : 취약   ■" >> centos.txt
	Array_Checklist_4_Result[0]="취약"
fi

echo "  :: 기준 - /etc/services 파일의 권한에 other 쓰기권한이 없으면 양호    " >> centos.txt
echo "========================================================================" >> centos.txt
echo " "                                                                        >> centos.txt

echo "[ $SERVICES ]"								                                            >> centos.txt
if [ -f $SERVICES ]
	then
		ls -alL $SERVICES						                                                >> centos.txt
else
	echo "$SERVICES : File doesn't exist"					                                >> centos.txt
fi
echo " "									                                                      >> centos.txt 
echo " "									                                                      >> centos.txt 


echo "*************************** Checklist  4.2. ****************************"
echo "========================================================================" >> centos.txt
echo "▶▶  Checklist  4.2.                                                " >> centos.txt

if [ `find $XINETD_D/* | egrep -w "echo|discard|daytime|chargen|time|tftp|finger|sftp|uucp-path|nntp|ntp|netbios_ns|netbios_dgm|netbios_ssn|bftp|ldap|printer|talk|ntalk|uucp|pcserver|ldaps|ingreslock|www-ldap-gw|nfsd|dtspcd" | xargs grep -i "disable" | grep -i "no" | wc -l` -eq 0 ]
	then
		echo "=========================================================■   Result : 양호   ■" >> centos.txt
		Array_Checklist_4_Result[1]="양호"
else
	echo "=========================================================■   Result : 취약   ■" >> centos.txt
	Array_Checklist_4_Result[1]="취약"
fi

echo "  :: 기준 - 불필요한 서비스가 사용되고 있지 않으면 양호"			            >> centos.txt
echo "  echo, discard, daytime, chargen, time, tftp, finger, sftp, uucp-path" 	>> centos.txt
echo "  nntp, ntp, netbios_ns, netbios_dgm, netbios_ssn, bftp, ldap, printer"	  >> centos.txt
echo "  talk, ntalk, uucp, pcserver, ldaps, ingreslock, www-ldap-gw, nfsd,dtspcd" >> centos.txt
echo "========================================================================" >> centos.txt
echo " "                                                                        >> centos.txt 

echo "[ /etc/xinetd.d ]"							                                          >> centos.txt
if [ -d $XINETD_D ]
	then
		if [ `find $XINETD_D/* | egrep -w "echo|discard|daytime|chargen|time|tftp|finger|sftp|uucp-path|nntp|ntp|netbios_ns|netbios_dgm|netbios_ssn|bftp|ldap|printer|talk|ntalk|uucp|pcserver|ldaps|ingreslock|www-ldap-gw|nfsd|dtspcd" | xargs grep -i "disable" | wc -l` -gt 0 ]
			then
				find $XINETD_D/* | egrep -w "echo|discard|daytime|chargen|time|tftp|finger|sftp|uucp-path|nntp|ntp|netbios_ns|netbios_dgm|netbios_ssn|bftp|ldap|printer|talk|ntalk|uucp|pcserver|ldaps|ingreslock|www-ldap-gw|nfsd|dtspcd" | xargs grep -i "disable"	>> centos.txt
		else
			echo "Setting doesn't exist"				                                      >> centos.txt
		fi
else
	echo "/etc/xinetd.d : Directory doesn't exist"				                        >> centos.txt
fi
echo " "									                                                      >> centos.txt
echo " "									                                                      >> centos.txt


echo "*************************** Checklist  4.3. ****************************"
echo "========================================================================" >> centos.txt
echo "▶▶  Checklist  4.3.                                                " >> centos.txt

echo "=========================================================■   Result : N/A   ■" >> centos.txt
Array_Checklist_4_Result[2]="N/A"

echo "  :: 기준 - Banner에 O/S 및 버전 정보가 없을 경우 양호                         " >> centos.txt
echo "========================================================================" >> centos.txt
echo " "                                                                        >> centos.txt

echo "[ Service ]"								>> centos.txt
if [ `netstat -natp | awk '{print $7}' | egrep -i "telnet|ftp|sendmail|named" | wc -l` -gt 0 ]
	then
		netstat -natp | egrep -i "telnet|ftp|sendmail|named"	>> centos.txt
else
	echo "Telnet, Ftp, Smtp, Dns service is all Inactive"			                    >> centos.txt
fi
echo " "									                                                      >> centos.txt
echo " "									                                                      >> centos.txt

echo "[ Telnet Banner ]"							                                          >> centos.txt
if [ -f $ISSUE ]
	then
		if [ `cat $ISSUE | wc -l` -gt 0 ]
			then
				echo "- /etc/issue"						                                                  >> centos.txt
				cat $ISSUE					                                                    >> centos.txt
				echo " "									                                                      >> centos.txt
				echo " "									                                                      >> centos.txt
		else
			echo "Telnet Banner doesn't exist"			                                  >> centos.txt
			echo " "									                                                      >> centos.txt
			echo " "									                                                      >> centos.txt
		fi
else
	endif 2> /dev/null
fi

if [ -f $ISSUE_NET ]
	then
		if [ `cat $ISSUE_NET | wc -l` -gt 0 ]
			then
				echo "- /etc/issue.net"						                                              >> centos.txt
				cat $ISSUE_NET					                                                >> centos.txt
				echo " "									                                                      >> centos.txt
				echo " "									                                                      >> centos.txt
		else
			echo "Telnet Banner doesn't exist"			                                  >> centos.txt
			echo " "									                                                      >> centos.txt
			echo " "									                                                      >> centos.txt
		fi
else
	endif 2> /dev/null
fi

if [ -f /etc/default/telnetd ]
	then
		if [ `cat /etc/default/telnetd | grep -i "banner=" | grep -v "#" | wc -l` -gt 0 ]
			then
				echo "- /etc/default/telnetd"						                                              >> centos.txt
				cat /etc/default/telnetd | grep -i "banner=" | grep -v "#"					                                                >> centos.txt
				echo " "									                                                      >> centos.txt
				echo " "									                                                      >> centos.txt
		else
			echo "Telnet Banner doesn't exist"			                                  >> centos.txt
			echo " "									                                                      >> centos.txt
			echo " "									                                                      >> centos.txt
		fi
else
	endif 2> /dev/null
fi

if [ -f /etc/inetd.conf ]
	then
		if [ `cat /etc/inetd.conf | grep "telnetd" | grep -v "#" | grep "\-b" | grep "\/etc/issue" | wc -l` -gt 0 ]
			then
				echo "- /etc/inetd.conf"						                                              >> centos.txt
				cat /etc/inetd.conf | grep "telnetd" | grep -v "#" | grep "\-b" | grep "\/etc/issue"					                                                >> centos.txt
				echo " "									                                                      >> centos.txt
				echo " "									                                                      >> centos.txt
		else
			echo "Telnet Banner doesn't exist"			                                  >> centos.txt
			echo " "									                                                      >> centos.txt
			echo " "									                                                      >> centos.txt
		fi
else
	endif 2> /dev/null
fi

echo "[ FTP Banner ]"								                                            >> centos.txt
if [ -f $WELCOME_MSG ]
	then
		if [ `cat $WELCOME_MSG | grep -i "banner" | wc -l` -gt 0 ]
			then
				echo "- /etc/welcome.msg"						                                            >> centos.txt
				cat $WELCOME_MSG | grep -i "banner"		                                  >> centos.txt
				echo " "									                                                      >> centos.txt
				echo " "									                                                      >> centos.txt
		else
			echo "FTP Banner doesn't exist"				                                    >> centos.txt
			echo " "									                                                      >> centos.txt
			echo " "									                                                      >> centos.txt
		fi
else
	endif 2> /dev/null
fi

if [ -f $VSFTPD_CONF ]
	then
		if [ `cat $VSFTPD_CONF | grep -i "ftp_banner" | wc -l` -gt 0 ]
			then
				echo "- vsftpd.conf"						                                                >> centos.txt
				cat $VSFTPD_CONF | grep -i "ftp_banner"		                              >> centos.txt
				echo " "									                                                      >> centos.txt
				echo " "									                                                      >> centos.txt
		else
			echo "FTP Banner doesn't exist"				                                    >> centos.txt
			echo " "									                                                      >> centos.txt
			echo " "									                                                      >> centos.txt
		fi
else
	endif 2> /dev/null
fi

if [ -f $PROFTPD_CONF ]
	then
		if [ `cat $PROFTPD_CONF | grep -i "Serverldent" | wc -l` -gt 0 ]
			then
				echo "- proftpd.conf"						                                                >> centos.txt
				cat $PROFTPD_CONF | grep -i "Serverldent"	                              >> centos.txt
				echo " "									                                                      >> centos.txt
				echo " "									                                                      >> centos.txt
		else
			echo "FTP Banner doesn't exist"				                                    >> centos.txt
			echo " "									                                                      >> centos.txt
			echo " "									                                                      >> centos.txt
		fi
else
	endif 2> /dev/null
fi
		
if [ -f /etc/ftpaccess ]
	then
		if [ `cat /etc/ftpaccess | egrep -i "Greeting|terse" | wc -l` -gt 0 ]
			then
				echo "- /etc/ftpaccess"						                                              >> centos.txt
				cat /etc/ftpaccess | egrep -i "Greeting|terse"	                        >> centos.txt
				echo " "									                                                      >> centos.txt
				echo " "									                                                      >> centos.txt
		else
			echo "FTP Banner doesn't exist"				                                    >> centos.txt
			echo " "									                                                      >> centos.txt
			echo " "									                                                      >> centos.txt
		fi
else
	endif 2> /dev/null
fi

if [ -f /etc/ftpd/ftpaccess ]
	then
		if [ `cat /etc/ftpd/ftpaccess | grep -v "#" | egrep -i "suppresshostname.yes|suppressversion.yes" | wc -l` -gt 0 ]
			then
				echo "- /etc/ftpd/ftpaccess"						                                              >> centos.txt
				cat /etc/ftpd/ftpaccess | grep -v "#" | egrep -i "suppresshostname.yes|suppressversion.yes"	                        >> centos.txt
				echo " "									                                                      >> centos.txt
				echo " "									                                                      >> centos.txt
		else
			echo "FTP Banner doesn't exist"				                                    >> centos.txt
			echo " "									                                                      >> centos.txt
			echo " "									                                                      >> centos.txt
		fi
else
	endif 2> /dev/null
fi

echo "[ SMTP Banner ]"								                                          >> centos.txt
if [ -f $SENDMAIL_CF ]
	then
		if [ `cat $SENDMAIL_CF | grep -i "GreetingMessage" | wc -l` -gt 0 ]
			then
				echo "- /etc/mail/sendmail.cf"				                                          >> centos.txt
				cat $SENDMAIL_CF | grep -i "GreetingMessage"	                          >> centos.txt
				echo " "									                                                      >> centos.txt
				echo " "									                                                      >> centos.txt
		else
			echo "SMTP Banner doesn't exist"			                                    >> centos.txt
			echo " "									                                                      >> centos.txt
			echo " "									                                                      >> centos.txt
		fi
else
	endif 2> /dev/null
fi

echo "[ DNS Banner ]"								                                            >> centos.txt
if [ -f $NAMED_CONF ]
	then
		if [ `cat $NAMED_CONF | grep -i "version" | wc -l` -gt 0 ]
			then
				echo "- /etc/named.conf"						                                            >> centos.txt
				cat $NAMED_CONF | grep -i "version"		                                  >> centos.txt
				echo " "									                                                      >> centos.txt
				echo " "									                                                      >> centos.txt
		else
			echo "DNS Banner doesn't exist"				                                    >> centos.txt
			echo " "									                                                      >> centos.txt
			echo " "									                                                      >> centos.txt
		fi
else
	endif 2> /dev/null
fi
echo " "									                                                      >> centos.txt
echo " "									                                                      >> centos.txt


echo "*************************** Checklist  4.4. ****************************"
echo "========================================================================" >> centos.txt
echo "▶▶  Checklist  4.4.                                                " >> centos.txt

if [ `netstat -natp | awk '{print $7}' | grep -i "snmp" | wc -l` -gt 0 ]
	then
		if [ `cat /etc/snmp/conf/snmpd.conf /etc/snmp/snmpd.conf /etc/snmpd.conf /etc/SnmpAgent.d/snmpd.conf /etc/net-snmp/snmp/snmpd.conf | grep -v '^#' | egrep -i "public|private" | egrep -v "group|trap" | wc -l` -ge 1 ]
			then
				echo "=========================================================■   Result : 취약   ■" >> centos.txt
				Array_Checklist_4_Result[3]="취약"
			else
				echo "=========================================================■   Result : 양호   ■" >> centos.txt
				Array_Checklist_4_Result[3]="양호"
		fi
else
	echo "=========================================================■   Result : 양호   ■" >> centos.txt
	Array_Checklist_4_Result[3]="양호"
fi

echo "  :: 기준 - Community String 이 public, private 이 아닐 경우 양호              " >> centos.txt
echo "========================================================================" >> centos.txt
echo " "                                                                        >> centos.txt

echo "[ SNMP Service ]"								>> centos.txt
if [ `netstat -natp | awk '{print $7}' | grep -i "snmp" | wc -l` -gt 0 ]
	then
		netstat -natp | grep -i "snmp" >> centos.txt
else
	echo "SNMP service is Inactive"						                                    >> centos.txt
fi
echo " "									                                                      >> centos.txt
echo " "									                                                      >> centos.txt

echo "[ SNMP Community String ]"						                                    >> centos.txt
if [ -f /etc/snmp/conf/snmpd.conf ]
	then
		echo "- /etc/snmp/conf/snmpd.conf"						                                            >> centos.txt
		if [ `grep -v '^#' /etc/snmp/conf/snmpd.conf | egrep -i "public|private" | egrep -v "group|trap" | wc -l` -gt 0 ]
			then
				grep -v '^#' /etc/snmp/conf/snmpd.conf | egrep -i "public|private" | egrep -v "group|trap"	>> centos.txt
				echo " "									                                                      >> centos.txt
				echo " "									                                                      >> centos.txt

		else
			echo "SNMP Community String doesn't exist"		                            >> centos.txt
			echo " "									                                                      >> centos.txt
			echo " "									                                                      >> centos.txt
		fi
else
	endif 2> /dev/null
fi


if [ -f /etc/snmpd.conf ]
	then
		echo "- /etc/snmpd.conf"						                                            >> centos.txt
		if [ `grep -v '^#' /etc/snmpd.conf | egrep -i "public|private" | egrep -v "group|trap" | wc -l` -gt 0 ]
			then
				grep -v '^#' /etc/snmpd.conf | egrep -i "public|private" | egrep -v "group|trap"	>> centos.txt
				echo " "									                                                      >> centos.txt
				echo " "									                                                      >> centos.txt
		else
			echo "SNMP Community String doesn't exist"		                            >> centos.txt
			echo " "									                                                      >> centos.txt
			echo " "									                                                      >> centos.txt
		fi
else
	endif 2> /dev/null
fi


if [ -f /etc/snmp/snmpd.conf ]
	then
		echo "- /etc/snmp/snmpd.conf"						                                            >> centos.txt
		if [ `grep -v '^#' /etc/snmp/snmpd.conf | egrep -i "public|private" | egrep -v "group|trap" | wc -l` -gt 0 ]
			then
				grep -v '^#' /etc/snmp/snmpd.conf | egrep -i "public|private" | egrep -v "group|trap"	>> centos.txt
				echo " "									                                                      >> centos.txt
				echo " "									                                                      >> centos.txt
		else
			echo "SNMP Community String doesn't exist"		                            >> centos.txt
			echo " "									                                                      >> centos.txt
			echo " "									                                                      >> centos.txt
		fi
else
	endif 2> /dev/null
fi


if [ -f /etc/SnmpAgent.d/snmpd.conf ]
	then
		echo "- /etc/SnmpAgent.d/snmpd.conf"						                                            >> centos.txt
		if [ `grep -v '^#' /etc/SnmpAgent.d/snmpd.conf | egrep -i "public|private" | egrep -v "group|trap" | wc -l` -gt 0 ]
			then
				grep -v '^#' /etc/SnmpAgent.d/snmpd.conf | egrep -i "public|private" | egrep -v "group|trap"	>> centos.txt
				echo " "									                                                      >> centos.txt
				echo " "									                                                      >> centos.txt
		else
			echo "SNMP Community String doesn't exist"		                            >> centos.txt
			echo " "									                                                      >> centos.txt
			echo " "									                                                      >> centos.txt
		fi
else
	endif 2> /dev/null
fi

if [ -f /etc/net-snmp/snmp/snmpd.conf ]
	then
		echo "- /etc/net-snmp/snmp/snmpd.conf"						                                            >> centos.txt
		if [ `grep -v '^#' /etc/net-snmp/snmp/snmpd.conf | egrep -i "public|private" | egrep -v "group|trap" | wc -l` -gt 0 ]
			then
				grep -v '^#' /etc/net-snmp/snmp/snmpd.conf | egrep -i "public|private" | egrep -v "group|trap"	>> centos.txt
				echo " "									                                                      >> centos.txt
				echo " "									                                                      >> centos.txt
		else
			echo "SNMP Community String doesn't exist"		                            >> centos.txt
			echo " "									                                                      >> centos.txt
			echo " "									                                                      >> centos.txt
		fi
else
	endif 2> /dev/null
fi
echo " "									                                                      >> centos.txt
echo " "									                                                      >> centos.txt


echo "*************************** Checklist  5.1. ****************************"
echo "========================================================================" >> centos.txt
echo "▶▶  Checklist  5.1.                                                " >> centos.txt

if [ `ps -ef | grep -i "syslogd" | grep -v "grep" | wc -l` -gt 0 ]
	then
		if [ `cat /etc/syslog.conf /etc/rsyslog.conf | egrep -i "notice|info|debug" | grep -v "#" | wc -l` -eq 0 -a `cat /etc/syslog.conf /etc/rsyslog.conf | egrep -i "err|crit|alert" | egrep -i "console|sysmsg" | grep -v "#" | wc -l` -eq 0 -a `cat /etc/syslog.conf /etc/rsyslog.conf | grep -i "emerg" | grep "\*" | grep -v "#" | wc -l` -eq 0 ]
			then
				echo "=========================================================■   Result : 양호   ■" >> centos.txt
				Array_Checklist_5_Result[0]="양호"
		else
			echo "=========================================================■   Result : 취약   ■" >> centos.txt
			Array_Checklist_5_Result[0]="취약"
		fi
else
	echo "=========================================================■   Result : 양호   ■" >> centos.txt
	Array_Checklist_5_Result[0]="양호"
fi

echo "  :: 기준 - syslog에 info, alert, emerg 등 중요 로그 정보에 대한 로깅 설정     " >> centos.txt
echo "========================================================================" >> centos.txt
echo " "                                                                        >> centos.txt

echo "[ Syslog Process ]"							                                          >> centos.txt
if [ `ps -ef | grep -i "syslogd" | grep -v "grep" | wc -l` -gt 0 ]
	then
		ps -ef | grep -i "syslogd" | grep -v "grep"			                            >> centos.txt
else
	echo "Syslog Process is Inactive"					                                    >> centos.txt
fi
echo " "									                                                      >> centos.txt
echo " "                                                                        >> centos.txt

if [ `grep -i "yes" <<< $answer | wc -l` -ge 1 ]
	then
	if [ `grep -i "$" <<< $answer2 | wc -l` -ge 1 ]
		then
			echo "[syslog 저장 경로]" >> centos.txt
			echo $answer2			>> centos.txt
			echo " " >> centos.txt
			echo " " >> centos.txt
	else
		endif 2> /dev/null
	fi
else
	endif 2> /dev/null
fi

echo "[ /etc/syslog.conf ]"							                                        >> centos.txt
if [ -f $SYSLOG_CONF ]
	then
		if [ `cat $SYSLOG_CONF | egrep -i "notice|info|debug|err|crit|alert|emerg" | grep -v "#" | wc -l` -eq 0 ]
			then
				echo "Log is doesn't exist"			                                        >> centos.txt
		else
			cat $SYSLOG_CONF | egrep -i "notice|info|debug|err|crit|alert|emerg" | grep -v "#" >> centos.txt
		fi
else
	echo "/etc/syslog.conf : File doesn't exist"			                            >> centos.txt
fi
echo " "									                                                      >> centos.txt
echo " "                                                                        >> centos.txt

echo "[ /etc/rsyslog.conf ]"							                                        >> centos.txt
if [ -f /etc/rsyslog.conf ]
	then
		if [ `cat /etc/rsyslog.conf | egrep -i "notice|info|debug|err|crit|alert|emerg" | grep -v "#" | wc -l` -eq 0 ]
			then
				echo "Log is doesn't exist"			                                        >> centos.txt
		else
			cat /etc/rsyslog.conf | egrep -i "notice|info|debug|err|crit|alert|emerg" | grep -v "#" >> centos.txt
		fi
else
	echo "/etc/rsyslog.conf : File doesn't exist"			                            >> centos.txt
fi
echo " "									                                                      >> centos.txt
echo " "                                                                        >> centos.txt


echo "*************************** Checklist  5.2. ****************************"
echo "========================================================================" >> centos.txt
echo "▶▶  Checklist  5.2.                                                " >> centos.txt

if [ `cat /etc/syslog.conf /etc/rsyslog.conf | egrep -i "authpriv.info" | grep -v "#" | wc -l` -ge 1 ]
	then
		echo "=========================================================■   Result : 양호   ■" >> centos.txt
		Array_Checklist_5_Result[1]="양호"
else
	echo "=========================================================■   Result : 취약   ■" >> centos.txt
	Array_Checklist_5_Result[1]="취약"
fi

echo "  :: 기준 - (r)syslog.conf파일에 authpriv.info 설정이 되어 있을 경우 양호" >> centos.txt
echo "========================================================================" >> centos.txt
echo " "                                                                        >> centos.txt

echo "[ /etc/default/su ]"							                                        >> centos.txt
if [ -f /etc/default/su ]
	then
		if [ `cat /etc/default/su | grep -i "SULOG" | grep -v "#" | wc -l` -gt 0 ]
			then
				cat /etc/default/su | grep -i "SULOG"                    >> centos.txt
		else
			echo "sulog doesn't exist"				                                        >> centos.txt
		fi
else
	echo "/etc/default/su : File doesn't exist"			                              >> centos.txt
fi	
echo " "									                                                      >> centos.txt
echo " "									                                                      >> centos.txt


echo "[ /etc/login.defs ]"							                                        >> centos.txt
if [ -f $LOGIN_DEFS ]
	then
		if [ `cat $LOGIN_DEFS | grep -i "SULOG_FILE" | grep -v "#" | wc -l` -gt 0 ]
			then
				cat $LOGIN_DEFS | grep -i "SULOG_FILE"                    >> centos.txt
		else
			echo "sulog doesn't exist"				                                        >> centos.txt
		fi
else
	echo "/etc/login.defs : File doesn't exist"			                              >> centos.txt
fi	
echo " "									                                                      >> centos.txt
echo " "									                                                      >> centos.txt

echo "[ /etc/syslog.conf ]"							                                        >> centos.txt
if [ -f $SYSLOG_CONF ]
	then
		if [ `cat $SYSLOG_CONF | egrep -i "authpriv.info|auth.notice" | grep -v "#" | wc -l` -gt 0 ]
			then
				cat $SYSLOG_CONF | egrep -i "authpriv.info"                >> centos.txt
		else
			echo "sulog doesn't exist"				                                        >> centos.txt
		fi
else
	echo "/etc/syslog.conf : File doesn't exist"			                            >> centos.txt
fi	
echo " "									                                                      >> centos.txt
echo " "									                                                      >> centos.txt

echo "[ /etc/rsyslog.conf ]"							                                        >> centos.txt
if [ -f /etc/rsyslog.conf ]
	then
		if [ `cat /etc/rsyslog.conf | egrep -i "authpriv.info|auth.notice" | grep -v "#" | wc -l` -gt 0 ]
			then
				cat /etc/rsyslog.conf | egrep -i "authpriv.info"                >> centos.txt
		else
			echo "sulog.conf doesn't exist"				                                        >> centos.txt
		fi
else
	echo "/etc/rsyslog.conf : File doesn't exist"			                            >> centos.txt
fi	
echo " "									                                                      >> centos.txt
echo " "									                                                      >> centos.txt


echo "[ sulog ]"								                                                >> centos.txt
echo "- /var/log/sulog"						                                            >> centos.txt
if [ -f /var/log/sulog ]
	then
		if [ `cat /var/log/sulog | grep -v "#" | wc -l` -gt 0 ]
			then
				cat -b /var/log/sulog | grep -v "#" | tail			                                          >> centos.txt
		else
			echo "/var/log/sulog : Setting doesn't exist"			                                >> centos.txt
		fi
else
	echo "/var/log/sulog : File doesn't exist"			                                        >> centos.txt
fi	
echo " "									                                                      >> centos.txt
echo " "									                                                      >> centos.txt

echo "- /var/adm/sulog"						                                            >> centos.txt
if [ -f /var/adm/sulog ]
	then
		if [ `cat /var/adm/sulog | grep -v "#" | wc -l` -gt 0 ]
			then
				cat -b /var/adm/sulog | grep -v "#" | tail			                                          >> centos.txt
		else
			echo "/var/adm/sulog : Setting doesn't exist"			                                >> centos.txt
		fi
else
	echo "/var/adm/sulog : File doesn't exist"			                                        >> centos.txt
fi	
echo " "									                                                      >> centos.txt
echo " "									                                                      >> centos.txt


echo "*************************** Checklist  5.3. ****************************"
echo "========================================================================" >> centos.txt
echo "▶▶  Checklist  5.3.                                                " >> centos.txt

if [ `echo $answer_patch | grep -i "yes" | wc -l` -ge 1 ]
	then
		echo "=========================================================■   Result : 양호   ■" >> centos.txt
		Array_Checklist_5_Result[2]="양호"
else
	echo "=========================================================■   Result : 취약   ■" >> centos.txt
	Array_Checklist_5_Result[2]="취약"
fi

echo "  :: 기준 - 패치정책에 따라 주기적으로 적용하고 있을시 양호                    " >> centos.txt
echo "========================================================================" >> centos.txt
echo " "                                                                        >> centos.txt

rpm -qa | sort                                                                  >> centos.txt
echo " "                                                                        >> centos.txt
echo " "                                                                        >> centos.txt

echo "********************** System Security Check End ***********************"
echo "====================== System Security Check End =======================" >> centos.txt
echo " "									>> centos.txt
echo " "									>> centos.txt

echo "============================ User Answers! =============================" >> centos.txt
echo " "									>> centos.txt

echo "1. Do you use the specific path to record the 'syslogs'? [yes/no] "	>> centos.txt
echo $answer									>> centos.txt

if [ `grep -i "yes" <<< $answer | wc -l` -eq 1 ]
	then
		echo "- syslog : "						>> centos.txt
		echo $answer2							>> centos.txt
elif [ `grep -i "no" <<< $answer | wc -l` -eq 1 ]
	then
		endif 2> /dev/null
else
	endif 2> /dev/null
fi

echo "2. Does this server use an FTP service? [yes/no] "			>> centos.txt
echo $answer_ftp								>> centos.txt

echo "3. Is there a internal policy that patch the applications regularly? [yes/no] "	>> centos.txt
echo $answer_patch								>> centos.txt
echo " "									>> centos.txt
echo " "									>> centos.txt


echo "========================= Vulnerability Summary ========================" >> centos.txt
echo " "																		                                    >> centos.txt

for i in 1 2 3 4 5 6 7 8 9 10;
	do
		echo 1.$i.	Result - ${Array_Checklist_1_Result[i-1]}						              >> centos.txt
done
echo "------------------------------------------------------------------------" >> centos.txt
for i in 1 2 3 4 5 6 7;
	do
		echo 2.$i.	Result - ${Array_Checklist_2_Result[i-1]}						              >> centos.txt
done
echo "------------------------------------------------------------------------" >> centos.txt
for i in 1 2 3 4 5 6;
	do
		echo 3.$i.	Result - ${Array_Checklist_3_Result[i-1]}						              >> centos.txt
done
echo "------------------------------------------------------------------------" >> centos.txt
for i in 1 2 3 4;
	do
		echo 4.$i.	Result - ${Array_Checklist_4_Result[i-1]}						              >> centos.txt
done
echo "------------------------------------------------------------------------" >> centos.txt
for i in 1 2 3;
	do
		echo 5.$i.	Result - ${Array_Checklist_5_Result[i-1]}						              >> centos.txt
done
echo "========================================================================" >> centos.txt
echo " "                                                                        >> centos.txt 
