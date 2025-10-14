## STEP 1
```sh
└─$ rustscan -a 10.129.228.120 --no-banner --scripts none
[!] File limit is lower than default batch size. Consider upping with --ulimit. May cause harm to sensitive servers
[!] Your file limit is very small, which negatively impacts RustScan's speed. Use the Docker image, or up the Ulimit with '--ulimit 5000'. 
Open 10.129.228.120:53
Open 10.129.228.120:80
Open 10.129.228.120:88
Open 10.129.228.120:135
Open 10.129.228.120:139
Open 10.129.228.120:389
Open 10.129.228.120:445
Open 10.129.228.120:464
Open 10.129.228.120:593
Open 10.129.228.120:636
Open 10.129.228.120:3268
Open 10.129.228.120:3269
Open 10.129.228.120:9389
Open 10.129.228.120:49667
Open 10.129.228.120:49673
Open 10.129.228.120:49674
Open 10.129.228.120:49695
Open 10.129.228.120:49725
10.129.228.120 -> [53,80,88,135,139,389,445,464,593,636,3268,3269,9389,49667,49673,49674,49695,49725]
```


## STEP 2
ドメイン名取得
```sh
└─$ netexec smb 10.129.228.120                                                                                     
SMB         10.129.228.120  445    G0               [*] Windows 10 / Server 2019 Build 17763 x64 (name:G0) (domain:flight.htb) (signing:True) (SMBv1:False)
```
hosts編集
```sh
└─$  echo '10.129.228.120 flight.htb' | sudo tee -a /etc/hosts
10.129.228.120 flight.htb
```
80番にアクセス  
めぼしい情報は特になし  
<img src="https://github.com/mylovemyon/hackthebox_images/blob/main/Flight_01.png">  
サブドメイン列挙  
別ウェブページを探索するため、サイズが異なるレスポンスを実施するドメインを調査
```sh
└─$ curl http://flight.htb -I
HTTP/1.1 200 OK
Date: Tue, 14 Oct 2025 08:07:10 GMT
Server: Apache/2.4.52 (Win64) OpenSSL/1.1.1m PHP/8.1.1
Last-Modified: Thu, 24 Feb 2022 05:58:10 GMT
ETag: "1b9d-5d8bd444f0080"
Accept-Ranges: bytes
Content-Length: 7069
Content-Type: text/html
```
schoolというサブドメイン発見
```sh
└─$ ffuf -c -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt -H 'Host: FUZZ.flight.htb' -u http://10.129.228.120 -fs 7069

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://10.129.228.120
 :: Wordlist         : FUZZ: /usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt
 :: Header           : Host: FUZZ.flight.htb
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
 :: Filter           : Response size: 7069
________________________________________________

school                  [Status: 200, Size: 3996, Words: 1045, Lines: 91, Duration: 286ms]
:: Progress: [19966/19966] :: Job [1/1] :: 129 req/sec :: Duration: [0:02:22] :: Errors: 0 ::
```
hosts追加
```sh
└─$ tail -n 1 /etc/hosts
10.129.171.253 flight.htb school.flight.htb
```


## STEP 3
school.flight.htbにアクセス  
<img src="https://github.com/mylovemyon/hackthebox_images/blob/main/Flight_02.png">  
ページ内の「Home」「About Us」「Blog」にリンクが設定されていた  
```sh
http://school.flight.htb/index.php?view=home.html
http://school.flight.htb/index.php?view=about.html
http://school.flight.htb/index.php?view=blog.html
```

phpでファイルインクルード処理を実施しているが、lfiの脆弱性があるかも
<img src="https://github.com/mylovemyon/hackthebox_images/blob/main/Flight_03.png">
