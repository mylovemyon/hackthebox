## STEP 1
```sh
└─$ rustscan -a 10.129.199.184 --scripts none
.----. .-. .-. .----..---.  .----. .---.   .--.  .-. .-.
| {}  }| { } |{ {__ {_   _}{ {__  /  ___} / {} \ |  `| |
| .-. \| {_} |.-._} } | |  .-._} }\     }/  /\  \| |\  |
`-' `-'`-----'`----'  `-'  `----'  `---' `-'  `-'`-' `-'
The Modern Day Port Scanner.
________________________________________
: http://discord.skerritt.blog         :
: https://github.com/RustScan/RustScan :
 --------------------------------------
 https://admin.tryhackme.com

[~] The config file is expected to be at "/home/kali/.rustscan.toml"
[!] File limit is lower than default batch size. Consider upping with --ulimit. May cause harm to sensitive servers
[!] Your file limit is very small, which negatively impacts RustScan's speed. Use the Docker image, or up the Ulimit with '--ulimit 5000'. 
Open 10.129.199.184:22
Open 10.129.199.184:80
10.129.199.184 -> [22,80]
```


## STEP 2
```sh
└─$ ffuf -c -w /usr/share/seclists/Discovery/Web-Content/common.txt -u http://10.129.199.184/FUZZ                      

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://10.129.199.184/FUZZ
 :: Wordlist         : FUZZ: /usr/share/seclists/Discovery/Web-Content/common.txt
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
________________________________________________

.git                    [Status: 301, Size: 315, Words: 20, Lines: 10, Duration: 309ms]
.git/HEAD               [Status: 200, Size: 23, Words: 2, Lines: 2, Duration: 764ms]
.htaccess               [Status: 403, Size: 279, Words: 20, Lines: 10, Duration: 2604ms]
.git/config             [Status: 200, Size: 92, Words: 9, Lines: 6, Duration: 2731ms]
.git/logs/              [Status: 200, Size: 1133, Words: 77, Lines: 18, Duration: 3629ms]
.hta                    [Status: 403, Size: 279, Words: 20, Lines: 10, Duration: 4614ms]
.htpasswd               [Status: 403, Size: 279, Words: 20, Lines: 10, Duration: 4625ms]
.git/index              [Status: 200, Size: 344667, Words: 814, Lines: 3250, Duration: 3624ms]
core                    [Status: 301, Size: 315, Words: 20, Lines: 10, Duration: 313ms]
files                   [Status: 301, Size: 316, Words: 20, Lines: 10, Duration: 354ms]
index.php               [Status: 200, Size: 13386, Words: 1368, Lines: 202, Duration: 412ms]
layouts                 [Status: 301, Size: 318, Words: 20, Lines: 10, Duration: 356ms]
modules                 [Status: 301, Size: 318, Words: 20, Lines: 10, Duration: 301ms]
robots.txt              [Status: 200, Size: 1198, Words: 114, Lines: 47, Duration: 298ms]
server-status           [Status: 403, Size: 279, Words: 20, Lines: 10, Duration: 292ms]
sites                   [Status: 301, Size: 316, Words: 20, Lines: 10, Duration: 575ms]
themes                  [Status: 301, Size: 317, Words: 20, Lines: 10, Duration: 299ms]
:: Progress: [4746/4746] :: Job [1/1] :: 96 req/sec :: Duration: [0:00:45] :: Errors: 0 ::
```


## STEP 3
```sh
└─$ git clone https://github.com/arthaud/git-dumper.git
Cloning into 'git-dumper'...
remote: Enumerating objects: 201, done.
remote: Counting objects: 100% (101/101), done.
remote: Compressing objects: 100% (44/44), done.
remote: Total 201 (delta 67), reused 59 (delta 57), pack-reused 100 (from 2)
Receiving objects: 100% (201/201), 61.32 KiB | 1.30 MiB/s, done.
Resolving deltas: 100% (104/104), done.


└─$ rm pyproject.toml
                                                                                                                                                                                                                                            

└─$ uv init -p 3.13
Initialized project `git-dumper`
                                                                                                                                                                                                                                            

└─$ uv add -r requirements.txt 
Using CPython 3.13.3 interpreter at: /usr/bin/python3.13
Creating virtual environment at: .venv
Resolved 15 packages in 1.24s
Prepared 3 packages in 896ms
Installed 14 packages in 7ms
 + beautifulsoup4==4.13.4
 + certifi==2025.6.15
 + cffi==1.17.1
 + charset-normalizer==3.4.2
 + cryptography==45.0.5
 + dulwich==0.23.1
 + idna==3.10
 + pycparser==2.22
 + pysocks==1.7.1
 + requests==2.32.4
 + requests-pkcs12==1.25
 + soupsieve==2.7
 + typing-extensions==4.14.0
 + urllib3==2.5.0


└─$ uv run git_dumper.py http://10.129.199.184/.git/ /home/kali/htb/smb/
/home/kali/htb/git-dumper/git_dumper.py:409: SyntaxWarning: invalid escape sequence '\g'
  modified_content = re.sub(UNSAFE, '# \g<0>', content, flags=re.IGNORECASE)
[-] Testing http://10.129.199.184/.git/HEAD [200]
[-] Testing http://10.129.199.184/.git/ [200]
[-] Fetching .git recursively
[-] Fetching http://10.129.199.184/.gitignore [404]
[-] Fetching http://10.129.199.184/.git/ [200]
[-] http://10.129.199.184/.gitignore responded with status code 404
[-] Fetching http://10.129.199.184/.git/objects/ [200]
[-] Fetching http://10.129.199.184/.git/hooks/ [200]
[-] Fetching http://10.129.199.184/.git/HEAD [200]
[-] Fetching http://10.129.199.184/.git/config [200]
[-] Fetching http://10.129.199.184/.git/description [200]
[-] Fetching http://10.129.199.184/.git/info/ [200]
[-] Fetching http://10.129.199.184/.git/logs/ [200]
[-] Fetching http://10.129.199.184/.git/COMMIT_EDITMSG [200]
[-] Fetching http://10.129.199.184/.git/index [200]
[-] Fetching http://10.129.199.184/.git/hooks/commit-msg.sample [200]
[-] Fetching http://10.129.199.184/.git/refs/ [200]
[-] Fetching http://10.129.199.184/.git/hooks/applypatch-msg.sample [200]
[-] Fetching http://10.129.199.184/.git/hooks/fsmonitor-watchman.sample [200]
[-] Fetching http://10.129.199.184/.git/hooks/post-update.sample [200]
[-] Fetching http://10.129.199.184/.git/hooks/pre-applypatch.sample [200]
[-] Fetching http://10.129.199.184/.git/hooks/pre-commit.sample [200]
[-] Fetching http://10.129.199.184/.git/branches/ [200]
[-] Fetching http://10.129.199.184/.git/hooks/pre-merge-commit.sample [200]
[-] Fetching http://10.129.199.184/.git/hooks/pre-push.sample [200]
[-] Fetching http://10.129.199.184/.git/hooks/pre-receive.sample [200]
[-] Fetching http://10.129.199.184/.git/hooks/prepare-commit-msg.sample [200]
[-] Fetching http://10.129.199.184/.git/hooks/pre-rebase.sample [200]
[-] Fetching http://10.129.199.184/.git/info/exclude [200]
[-] Fetching http://10.129.199.184/.git/hooks/update.sample [200]
[-] Fetching http://10.129.199.184/.git/logs/HEAD [200]
[-] Fetching http://10.129.199.184/.git/logs/refs/ [200]
[-] Fetching http://10.129.199.184/.git/refs/heads/ [200]
[-] Fetching http://10.129.199.184/.git/refs/tags/ [200]
[-] Fetching http://10.129.199.184/.git/objects/0a/ [200]
[-] Fetching http://10.129.199.184/.git/objects/0b/ [200]
~~~
```

tiffanny
BackDropJ2024DS2024
