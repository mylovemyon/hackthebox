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
443番ポートの証明書からドメイン名を確認
```sh
└─$ openssl s_client -connect 10.129.62.39:443 | openssl x509 -nocert -ext subjectAltName
Connecting to 10.129.62.39
Can't use SSL_get_servername
depth=0 C=EU, CN=streamIO
verify error:num=18:self-signed certificate
verify return:1
depth=0 C=EU, CN=streamIO
verify error:num=10:certificate has expired
notAfter=Mar 24 07:03:28 2022 GMT
verify return:1
depth=0 C=EU, CN=streamIO
notAfter=Mar 24 07:03:28 2022 GMT
verify return:1
X509v3 Subject Alternative Name: 
    DNS:streamIO.htb, DNS:watch.streamIO.htb
^C
```
hosts編集
```sh
└─$ echo '10.129.62.39 streamio.htb watch.streamio.htb' | sudo tee -a /etc/hosts
10.129.62.39 streamio.htb watch.streamio.htb
```
443番アクセス  
<img src="https://github.com/mylovemyon/hackthebox_images/blob/main/StreamIO_01.png">  
列挙
```sh
└─$ ffuf -r  -u https://streamio.htb/FUZZ -c -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : https://streamio.htb/FUZZ
 :: Wordlist         : FUZZ: /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt
 :: Follow redirects : true
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
________________________________________________

admin                   [Status: 403, Size: 18, Words: 1, Lines: 1, Duration: 262ms]
js                      [Status: 403, Size: 1233, Words: 73, Lines: 30, Duration: 262ms]
images                  [Status: 403, Size: 1233, Words: 73, Lines: 30, Duration: 266ms]
css                     [Status: 403, Size: 1233, Words: 73, Lines: 30, Duration: 270ms]
Admin                   [Status: 403, Size: 18, Words: 1, Lines: 1, Duration: 480ms]
Images                  [Status: 403, Size: 1233, Words: 73, Lines: 30, Duration: 263ms]
fonts                   [Status: 403, Size: 1233, Words: 73, Lines: 30, Duration: 384ms]
CSS                     [Status: 403, Size: 1233, Words: 73, Lines: 30, Duration: 257ms]
ADMIN                   [Status: 403, Size: 18, Words: 1, Lines: 1, Duration: 259ms]
JS                      [Status: 403, Size: 1233, Words: 73, Lines: 30, Duration: 315ms]
Js                      [Status: 403, Size: 1233, Words: 73, Lines: 30, Duration: 506ms]
Css                     [Status: 403, Size: 1233, Words: 73, Lines: 30, Duration: 508ms]
IMAGES                  [Status: 403, Size: 1233, Words: 73, Lines: 30, Duration: 261ms]
Fonts                   [Status: 403, Size: 1233, Words: 73, Lines: 30, Duration: 316ms]
:: Progress: [29999/29999] :: Job [1/1] :: 118 req/sec :: Duration: [0:03:40] :: Errors: 1 ::
```


## STEP 3
サブドメインにアクセス  
<img src="https://github.com/mylovemyon/hackthebox_images/blob/main/StreamIO_02.png">  
列挙
```sh
└─$ ffuf -u https://watch.streamio.htb/FUZZ -c -w /usr/share/seclists/Discovery/Web-Content/raft-medium-files.txt 

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : https://watch.streamio.htb/FUZZ
 :: Wordlist         : FUZZ: /usr/share/seclists/Discovery/Web-Content/raft-medium-files.txt
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
________________________________________________

index.php               [Status: 200, Size: 2829, Words: 202, Lines: 79, Duration: 268ms]
favicon.ico             [Status: 200, Size: 1150, Words: 4, Lines: 1, Duration: 601ms]
search.php              [Status: 200, Size: 253887, Words: 12366, Lines: 7194, Duration: 734ms]
.                       [Status: 200, Size: 2829, Words: 202, Lines: 79, Duration: 337ms]
blocked.php             [Status: 200, Size: 677, Words: 28, Lines: 20, Duration: 337ms]
Search.php              [Status: 200, Size: 253887, Words: 12366, Lines: 7194, Duration: 269ms]
Index.php               [Status: 200, Size: 2829, Words: 202, Lines: 79, Duration: 565ms]
Favicon.ico             [Status: 200, Size: 1150, Words: 4, Lines: 1, Duration: 262ms]
favicon.ICO             [Status: 200, Size: 1150, Words: 4, Lines: 1, Duration: 278ms]
:: Progress: [17129/17129] :: Job [1/1] :: 131 req/sec :: Duration: [0:02:03] :: Errors: 0 ::
```
<img src="https://github.com/mylovemyon/hackthebox_images/blob/main/StreamIO_03.png">  
<img src="https://github.com/mylovemyon/hackthebox_images/blob/main/StreamIO_04.png">  
