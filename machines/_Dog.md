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

## STEP 4
```
johncusack@dog:~$ sudo -l
sudo -l
[sudo] password for johncusack: BackDropJ2024DS2024

Matching Defaults entries for johncusack on dog:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User johncusack may run the following commands on dog:
    (ALL : ALL) /usr/local/bin/bee


johncusack@dog:~$ ls -l /usr/local/bin/bee
ls -l /usr/local/bin/bee
lrwxrwxrwx 1 root root 26 Jul  9  2024 /usr/local/bin/bee -> /backdrop_tool/bee/bee.php


johncusack@dog:~$ ls -l /backdrop_tool/bee/bee.php
ls -l /backdrop_tool/bee/bee.php
-rwxr-xr-x 1 root root 2905 Jul  9  2024 /backdrop_tool/bee/bee.php
```
```php
johncusack@dog:~$ cat /backdrop_tool/bee/bee.php

cat /backdrop_tool/bee/bee.php
#!/usr/bin/env php
<?php
/**
 * @file
 * A command line utility for Backdrop CMS.
 */

// Exit gracefully with a meaningful message if installed within a web
// accessible location and accessed in the browser.
if (!bee_is_cli()) {
  echo bee_browser_load_html();
  die();
}

// Set custom error handler.
set_error_handler('bee_error_handler');

// Include files.
require_once __DIR__ . '/includes/miscellaneous.inc';
require_once __DIR__ . '/includes/command.inc';
require_once __DIR__ . '/includes/render.inc';
require_once __DIR__ . '/includes/filesystem.inc';
require_once __DIR__ . '/includes/input.inc';
require_once __DIR__ . '/includes/globals.inc';

// Main execution code.
bee_initialize_server();
bee_parse_input();
bee_initialize_console();
bee_process_command();
bee_print_messages();
bee_display_output();
exit();

/**
 * Custom error handler for `bee`.
 *
 * @param int $error_level
 *   The level of the error.
 * @param string $message
 *   Error message to output to the user.
 * @param string $filename
 *   The file that the error came from.
 * @param int $line
 *   The line number the error came from.
 * @param array $context
 *   An array of all variables from where the error was triggered.
 *
 * @see https://www.php.net/manual/en/function.set-error-handler.php
 * @see _backdrop_error_handler()
 */
function bee_error_handler($error_level, $message, $filename, $line, array $context = NULL) {
  require_once __DIR__ . '/includes/errors.inc';
  _bee_error_handler_real($error_level, $message, $filename, $line, $context);
}

/**
 * Detects whether the current script is running in a command-line environment.
 */
function bee_is_cli() {
  return (empty($_SERVER['SERVER_SOFTWARE']) && (php_sapi_name() == 'cli' || (is_numeric($_SERVER['argc']) && $_SERVER['argc'] > 0)));
}

/**
 * Return the HTML to display if this page is loaded in the browser.
 *
 * @return string
 *   The concatentated html to display.
 */
function bee_browser_load_html() {
  // Set the title to use in h1 and title elements.
  $title = "Bee Gone!";
  // Place a white block over "#!/usr/bin/env php" as this is output before
  // anything else.
  $browser_output = "<div style='background-color:white;position:absolute;width:15rem;height:3rem;top:0;left:0;z-index:9;'>&nbsp;</div>";
  // Add the bee logo and style appropriately.
  $browser_output .= "<img src='./images/bee.png' align='right' width='150' height='157' style='max-width:100%;margin-top:3rem;'>";
  // Add meaningful text.
  $browser_output .= "<h1 style='font-family:Tahoma;'>$title</h1>";
  $browser_output .= "<p style='font-family:Verdana;'>Bee is a command line tool only and will not work in the browser.</p>";
  // Add the document title using javascript when the window loads.
  $browser_output .= "<script>window.onload = function(){document.title='$title';}</script>";
  // Output the combined string.
  return $browser_output;
}
```
