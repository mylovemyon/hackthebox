https://app.hackthebox.com/machines/401

## STEP 1
```sh
└─$ rustscan -a 10.129.100.185 --no-banner --scripts none
[!] File limit is lower than default batch size. Consider upping with --ulimit. May cause harm to sensitive servers
[!] Your file limit is very small, which negatively impacts RustScan's speed. Use the Docker image, or up the Ulimit with '--ulimit 5000'. 
Open 10.129.100.185:53
Open 10.129.100.185:80
Open 10.129.100.185:88
Open 10.129.100.185:135
Open 10.129.100.185:139
Open 10.129.100.185:389
Open 10.129.100.185:445
Open 10.129.100.185:464
Open 10.129.100.185:593
Open 10.129.100.185:636
Open 10.129.100.185:3268
Open 10.129.100.185:3269
Open 10.129.100.185:5985
Open 10.129.100.185:9389
Open 10.129.100.185:47001
Open 10.129.100.185:49665
Open 10.129.100.185:49667
Open 10.129.100.185:49664
Open 10.129.100.185:49666
Open 10.129.100.185:49674
Open 10.129.100.185:49671
Open 10.129.100.185:49675
Open 10.129.100.185:49677
Open 10.129.100.185:49681
Open 10.129.100.185:49697
10.129.100.185 -> [53,80,88,135,139,389,445,464,593,636,3268,3269,5985,9389,47001,49665,49667,49664,49666,49674,49671,49675,49677,49681,49697]
```


## STEP 2
