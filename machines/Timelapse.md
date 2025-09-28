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
