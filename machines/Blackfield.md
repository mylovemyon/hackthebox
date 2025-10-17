## STEP 1
```sh
└─$ rustscan -a 10.129.152.107 --no-banner --scripts none
[!] File limit is lower than default batch size. Consider upping with --ulimit. May cause harm to sensitive servers
[!] Your file limit is very small, which negatively impacts RustScan's speed. Use the Docker image, or up the Ulimit with '--ulimit 5000'. 
Open 10.129.152.107:53
Open 10.129.152.107:88
Open 10.129.152.107:135
Open 10.129.152.107:389
Open 10.129.152.107:445
Open 10.129.152.107:593
Open 10.129.152.107:3268
Open 10.129.152.107:5985
10.129.152.107 -> [53,88,135,389,445,593,3268,5985]
```

## STEP 2
