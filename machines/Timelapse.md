https://app.hackthebox.com/machines/452

## STEP 1
```sh
└─$ rustscan -a 10.129.227.113 --no-banner --scripts none
[!] File limit is lower than default batch size. Consider upping with --ulimit. May cause harm to sensitive servers
[!] Your file limit is very small, which negatively impacts RustScan's speed. Use the Docker image, or up the Ulimit with '--ulimit 5000'. 
Open 10.129.227.113:53
Open 10.129.227.113:88
Open 10.129.227.113:135
Open 10.129.227.113:139
Open 10.129.227.113:389
Open 10.129.227.113:445
Open 10.129.227.113:464
Open 10.129.227.113:3268
Open 10.129.227.113:3269
Open 10.129.227.113:5986
Open 10.129.227.113:9389
Open 10.129.227.113:49667
Open 10.129.227.113:49673
Open 10.129.227.113:49674
Open 10.129.227.113:49693
10.129.227.113 -> [53,88,135,139,389,445,464,3268,3269,5986,9389,49667,49673,49674,49693]
```

## STEP 2
匿名で共有フォルダ列挙  
(netexecやsmbmapでは列挙できなかった、きちんんと`-N`を指定しないといけないツールでないといけない感じ？)
```sh
└─$ smbclient -L '10.129.227.113' -N                        

        Sharename       Type      Comment
        ---------       ----      -------
        ADMIN$          Disk      Remote Admin
        C$              Disk      Default share
        IPC$            IPC       Remote IPC
        NETLOGON        Disk      Logon server share 
        Shares          Disk      
        SYSVOL          Disk      Logon server share 
Reconnecting with SMB1 for workgroup listing.
do_connect: Connection to 10.129.227.113 failed (Error NT_STATUS_RESOURCE_NAME_NOT_FOUND)
Unable to connect with SMB1 -- no workgroup available
```
