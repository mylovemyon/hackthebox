## STEP 1
```sh
└─$ rustscan -a 10.129.12.81 --no-banner --scripts none
[!] File limit is lower than default batch size. Consider upping with --ulimit. May cause harm to sensitive servers
[!] Your file limit is very small, which negatively impacts RustScan's speed. Use the Docker image, or up the Ulimit with '--ulimit 5000'. 
Open 10.129.12.81:80
Open 10.129.12.81:135
Open 10.129.12.81:445
Open 10.129.12.81:50000
10.129.12.81 -> [80,135,445,50000]
```


## STEP 2
