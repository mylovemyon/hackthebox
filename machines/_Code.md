## STEP 1
```sh
└─$ rustscan -a 10.129.121.111 --scripts none
.----. .-. .-. .----..---.  .----. .---.   .--.  .-. .-.
| {}  }| { } |{ {__ {_   _}{ {__  /  ___} / {} \ |  `| |
| .-. \| {_} |.-._} } | |  .-._} }\     }/  /\  \| |\  |
`-' `-'`-----'`----'  `-'  `----'  `---' `-'  `-'`-' `-'
The Modern Day Port Scanner.
________________________________________
: http://discord.skerritt.blog         :
: https://github.com/RustScan/RustScan :
 --------------------------------------
RustScan: Where '404 Not Found' meets '200 OK'.

[~] The config file is expected to be at "/home/kali/.rustscan.toml"
[!] File limit is lower than default batch size. Consider upping with --ulimit. May cause harm to sensitive servers
[!] Your file limit is very small, which negatively impacts RustScan's speed. Use the Docker image, or up the Ulimit with '--ulimit 5000'. 
Open 10.129.121.111:22
Open 10.129.121.111:5000
10.129.121.111 -> [22,5000]
```


## STEP 2
```sh
└─$ curl -I http://10.129.121.111:5000/
HTTP/1.1 200 OK
Server: gunicorn/20.0.4
Date: Tue, 22 Jul 2025 02:29:56 GMT
Connection: close
Content-Type: text/html; charset=utf-8
Content-Length: 3435
Vary: Cookie
```
