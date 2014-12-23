#!/bin/sh 


####################
## 0. yum install ##
####################

yum groupinstall "Development Tools"
yum groupinstall "Development Libraries"  

## /* System Update */
yum -y update
