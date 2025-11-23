https://app.hackthebox.com/machines/Intelligence

## STEP 1
```sh
└─$ rustscan -a 10.129.95.154 --no-banner --scripts none
[!] File limit is lower than default batch size. Consider upping with --ulimit. May cause harm to sensitive servers
[!] Your file limit is very small, which negatively impacts RustScan's speed. Use the Docker image, or up the Ulimit with '--ulimit 5000'. 
Open 10.129.95.154:53
Open 10.129.95.154:80
Open 10.129.95.154:88
Open 10.129.95.154:135
Open 10.129.95.154:139
Open 10.129.95.154:389
Open 10.129.95.154:445
Open 10.129.95.154:464
Open 10.129.95.154:593
Open 10.129.95.154:636
Open 10.129.95.154:3269
Open 10.129.95.154:3268
Open 10.129.95.154:9389
Open 10.129.95.154:49668
Open 10.129.95.154:49693
Open 10.129.95.154:49694
Open 10.129.95.154:49713
Open 10.129.95.154:49718
10.129.95.154 -> [53,80,88,135,139,389,445,464,593,636,3269,3268,9389,49668,49693,49694,49713,49718]
```
