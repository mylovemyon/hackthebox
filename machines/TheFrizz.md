https://app.hackthebox.com/machines/652

## STEP 1
```sh
└─$ rustscan -a 10.129.232.168 --no-banner --scripts none
[!] File limit is lower than default batch size. Consider upping with --ulimit. May cause harm to sensitive servers
[!] Your file limit is very small, which negatively impacts RustScan's speed. Use the Docker image, or up the Ulimit with '--ulimit 5000'. 
Open 10.129.232.168:22
Open 10.129.232.168:53
Open 10.129.232.168:80
Open 10.129.232.168:88
Open 10.129.232.168:135
Open 10.129.232.168:139
Open 10.129.232.168:389
Open 10.129.232.168:445
Open 10.129.232.168:464
Open 10.129.232.168:593
Open 10.129.232.168:636
Open 10.129.232.168:3269
Open 10.129.232.168:3268
Open 10.129.232.168:9389
Open 10.129.232.168:49664
Open 10.129.232.168:49667
Open 10.129.232.168:49670
Open 10.129.232.168:61670
Open 10.129.232.168:61666
Open 10.129.232.168:61681
10.129.232.168 -> [22,53,80,88,135,139,389,445,464,593,636,3269,3268,9389,49664,49667,49670,61670,61666,61681]
```


## STEP 2
```sh
└─$ ffuf -c -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt -u http://frizzdc.frizz.htb/FUZZ 

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://frizzdc.frizz.htb/FUZZ
 :: Wordlist         : FUZZ: /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
________________________________________________

home                    [Status: 301, Size: 345, Words: 22, Lines: 10, Duration: 263ms]
Home                    [Status: 301, Size: 345, Words: 22, Lines: 10, Duration: 359ms]
con                     [Status: 403, Size: 306, Words: 22, Lines: 10, Duration: 263ms]
HOME                    [Status: 301, Size: 345, Words: 22, Lines: 10, Duration: 290ms]
aux                     [Status: 403, Size: 306, Words: 22, Lines: 10, Duration: 288ms]
prn                     [Status: 403, Size: 306, Words: 22, Lines: 10, Duration: 263ms]
:: Progress: [29999/29999] :: Job [1/1] :: 121 req/sec :: Duration: [0:03:47] :: Errors: 1 ::
```
