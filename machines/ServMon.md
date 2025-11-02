https://app.hackthebox.com/machines/240

## STEP 1
```sh
└─$ rustscan -a 10.129.227.77 --no-banner --scripts none
[!] File limit is lower than default batch size. Consider upping with --ulimit. May cause harm to sensitive servers
[!] Your file limit is very small, which negatively impacts RustScan's speed. Use the Docker image, or up the Ulimit with '--ulimit 5000'. 
Open 10.129.227.77:21
Open 10.129.227.77:22
Open 10.129.227.77:80
Open 10.129.227.77:139
Open 10.129.227.77:135
Open 10.129.227.77:445
Open 10.129.227.77:5666
Open 10.129.227.77:6063
Open 10.129.227.77:6699
Open 10.129.227.77:8443
Open 10.129.227.77:49669
Open 10.129.227.77:49664
Open 10.129.227.77:49665
Open 10.129.227.77:49668
Open 10.129.227.77:49666
Open 10.129.227.77:49667
Open 10.129.227.77:49670
10.129.227.77 -> [21,22,80,139,135,445,5666,6063,6699,8443,49669,49664,49665,49668,49666,49667,49670]
```
