https://app.hackthebox.com/machines/662

## STEP 1
```sh
─$ rustscan -a 10.129.180.164 --no-banner --scripts none
[!] File limit is lower than default batch size. Consider upping with --ulimit. May cause harm to sensitive servers
[!] Your file limit is very small, which negatively impacts RustScan's speed. Use the Docker image, or up the Ulimit with '--ulimit 5000'. 
Open 10.129.180.164:53
Open 10.129.180.164:88
Open 10.129.180.164:139
Open 10.129.180.164:389
Open 10.129.180.164:445
Open 10.129.180.164:464
Open 10.129.180.164:593
Open 10.129.180.164:636
Open 10.129.180.164:3269
Open 10.129.180.164:3268
Open 10.129.180.164:5985
Open 10.129.180.164:9389
Open 10.129.180.164:49667
Open 10.129.180.164:49689
Open 10.129.180.164:49690
Open 10.129.180.164:49698
Open 10.129.180.164:49709
Open 10.129.180.164:49722
10.129.180.164 -> [53,88,139,389,445,464,593,636,3269,3268,5985,9389,49667,49689,49690,49698,49709,49722]
```
