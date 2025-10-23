https://app.hackthebox.com/machines/531

## STEP 1
```sh
└─$ rustscan -a 10.129.228.253 --no-banner --scripts none
[!] File limit is lower than default batch size. Consider upping with --ulimit. May cause harm to sensitive servers
[!] Your file limit is very small, which negatively impacts RustScan's speed. Use the Docker image, or up the Ulimit with '--ulimit 5000'. 
Open 10.129.228.253:53
Open 10.129.228.253:88
Open 10.129.228.253:593
Open 10.129.228.253:636
Open 10.129.228.253:1433
Open 10.129.228.253:3268
Open 10.129.228.253:3269
Open 10.129.228.253:5985
Open 10.129.228.253:9389
Open 10.129.228.253:49667
Open 10.129.228.253:49690
Open 10.129.228.253:49689
Open 10.129.228.253:49711
Open 10.129.228.253:49721
Open 10.129.228.253:49742
10.129.228.253 -> [53,88,593,636,1433,3268,3269,5985,9389,49667,49690,49689,49711,49721,49742]
```
