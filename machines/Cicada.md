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
