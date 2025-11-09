https://app.hackthebox.com/machines/StreamIO

## STEP 1
```sh
└─$ rustscan -a 10.129.62.39 --no-banner --scripts none
[!] File limit is lower than default batch size. Consider upping with --ulimit. May cause harm to sensitive servers
[!] Your file limit is very small, which negatively impacts RustScan's speed. Use the Docker image, or up the Ulimit with '--ulimit 5000'. 
Open 10.129.62.39:53
Open 10.129.62.39:80
Open 10.129.62.39:88
Open 10.129.62.39:135
Open 10.129.62.39:139
Open 10.129.62.39:389
Open 10.129.62.39:443
Open 10.129.62.39:445
Open 10.129.62.39:464
Open 10.129.62.39:593
Open 10.129.62.39:636
Open 10.129.62.39:3268
Open 10.129.62.39:3269
Open 10.129.62.39:5985
Open 10.129.62.39:9389
Open 10.129.62.39:49667
Open 10.129.62.39:49677
Open 10.129.62.39:49678
Open 10.129.62.39:49705
Open 10.129.62.39:49731
10.129.62.39 -> [53,80,88,135,139,389,443,445,464,593,636,3268,3269,5985,9389,49667,49677,49678,49705,49731]
```


## STEP 2
