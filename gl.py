#!/usr/bin/env python
# -*- coding:utf-8 -*-
#---------------------------------------------------------------------------
#
#   Author:                lubo
#   E-mail:                454331202@qq.com
#   LastModified:          2014-05-23 11:18:31
#   Filename:              gl.py
#   Desc:
#
#---------------------------------------------------------------------------

headline1 = ''
headline2 = ''
mysql_headline1 = ''
mysql_headline2 = ''
ncpu      = 0        #Number of processors
# Options Flag
optflag   = 0        #whether input opt
timeFlag  = 0        # -t   : print current time
interval  = 1        # -i   : time(second) interval
my_load   = 0        # -l   : print load info
my_cpu    = 0        # -c   : print cpu  info
my_swap   = 0        # -s   : print swap info
my_disk   = None     # -d   : print disk info
my_net    = None     # -n   : print net info
mysql  = 0           # -mysql: print mysql status
mysql_conn =''      # mysql conn info
com   = 0;          # -com : print mysql status
innodb_hit  = 0     # -hit : Print Innodb Hit%
innodb_rows = 0     # -innodb_rows : Print Innodb Rows Status
innodb_pages= 0     # -innodb_pages: Innodb Buffer Pool Pages Status
innodb_data = 0     # -innodb_data : Innodb Data Status
innodb_log  = 0     # -innodb_log  : Innodb Log Status
innodb_status=0     # -innodb_status: Show Engine Innodb Status
threads     = 0     # -T   : Print Threads Status
bytes       = 0     # -B   : Print Bytes Status
my_port   = '3306'  # default prot 3306
my_socket =None     # sockfile
my_pwd    =None     # root user password
dbrt = 0            # -rt
lock_file=''
tcprstat_logfile=''
tcprstat_dir='/tmp/'
orz_logfile=None
old_console=''
logfile_by_day=0    # one day one logfile
# Variables For :
#-----> Get SysInfo (from /proc/stat): CPU
sys_cpu1   = (0,0,0,0,0,0,0,0)
total_1    = 0
#
#<----- Get SysInfo (from /proc/stat): CPU
#-----> Get SysInfo (from /proc/vmstat): SWAP
swap1 ={'pswpin':0,'pswpout':0}
swap_not_first = 0
#<----- Get SysInfo (from /proc/vmstat): SWAP
#-----> Get SysInfo (from /proc/net/dev): NET
net1 ={'recv':0,'send':0}
net_not_first = 0
#<----- Get SysInfo (from /proc/net/dev): NET
#-----> Get SysInfo (from /proc/diskstats): IO
sys_io1   = (0,0,0,0,0,0,0,0,0,0,0,0,0,0,0)
io_not_first  = 0;                                   # no print first value
#ncpu = `grep processor /proc/cpuinfo | wc -l`;     #/* Number of processors */
# grep "HZ" -R /usr/include/*
# /usr/include/asm-x86_64/param.h:#define HZ 100
HZ = 100
#<----- Get SysInfo (from /proc/diskstats): IO

#-----> Get Mysql Status
mystat1={"Com_select":0,
        "Com_delete":0 ,
        "Com_update":0,
        "Com_insert":0,
        "Innodb_buffer_pool_read_requests":0,
        "Innodb_rows_inserted":0,
        "Innodb_rows_updated":0,
        "Innodb_rows_deleted":0,
        "Innodb_rows_read":0,
        "Threads_created":0,
        "Bytes_received":0,
        "Bytes_sent":0,
        "Innodb_buffer_pool_pages_flushed":0,
        "Innodb_data_read":0,
        "Innodb_data_reads":0,
        "Innodb_data_writes":0,
        "Innodb_data_written":0,
        "Innodb_os_log_fsyncs":0,
        "Innodb_os_log_written":0}
mysql_no_first = 0
#<----- Get Mysql Status
HAS_COLOR=1
count=None     #times
python_version=''
