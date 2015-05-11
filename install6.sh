#!/bin/sh 


####################
## 0. yum install ##
####################

yum -y groupinstall "Development Tools"
yum -y groupinstall "Development Libraries"  

## /* System Update */
yum -y update
