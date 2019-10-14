# 0x94TR Scanner Burp Suite Extension

Operations occur on a direct query without any parameter target input..

Potential security weaknesses are reflected on The Burp screen, It has a payload list in itself,
finds vulnerabilities by doing bruteforce.. 

Features: 
What vulnerabilities can it find ?
<ul>
<li>GET-POST Error Based SQL Injection </li>
<li>GET-POST Blind SQL Injection </li>

<li>GET-POST Time Based SQL Injection </li>
<li>GET-POST Boolean Based SQL Injection </li>
<li>GET-POST Union Based SQL Injection </li>
<li>GET-POST Remote Command Execution</li>
<li>GET-POST PHP exec</li>
<li>GET-POST Local File Include</li>
<li>Header CRLF Injection</li>
<li>GET-POST Command Injection</li>
<li>GET-POST Open Redirect</li>
<li>GET-POST Cross-Site Scripting(XSS) </li>
<li>GET-POST LDAP Injection </li>
<li>GET-POST Xpath Injection </li>
<li>GET-POST Frame Injection </li>
<li>GET-POST SSI Injection </li>
<li>GET-POST Template Injection </li>
<li>GET-POST SSRF Injection </li>
<li>GET-POST XXE Injection </li>
<li>GET-POST Code Injection </li>
<li>HTTP Response Splitting</li>
<li>Blind Command Injection</li>
<li>Blind Remote Command Injection</li>
<li>Blind XPATH Injection</li>
<li>Header(Cookie/UserAgent/Referer/Accept-Language/Accept-Encoding/Accept-Charset) Injection</li>
<li>Expression Language Injection</li>
<li>XXE Injection</li>
<li>Directory Brute</li>
<li>File Brute</li>
<li>Default password Brute</li>
<li>Sef Url Xss </li>
<li>GET-POST Sensitive Params Information </li>

</ul>

# How does he find it ?

It automatically detects GET or POST requests,
by browsing the target site and tries payload based on returning errors.
<br>

# Setup1 
 <h4>Requirements:</h4><br>
Burp Suite Professional, 2.7.0 standalone: http://www.jython.org/downloads.html<br>
Manual installation:<br>
'Extender'->'Options'<br>
Click 'Select file' under 'Python environment'<br>
Choose jython-standalone-2.7.0.jar<br>
'Extender'->'Extensions'<br>
Click 'Add'<br>
Change 'Extension Type' to Python<br>
Choose 0x94TR.py<br>
Done!<br>
<img src=https://raw.githubusercontent.com/antichown/0x94TR/master/images/setup1.png>
 
 
# Setup2
<img src=https://raw.githubusercontent.com/antichown/0x94TR/master/images/setup2.png>
<br>
 
# Setup3
<img src=https://raw.githubusercontent.com/antichown/0x94TR/master/images/setup3.png>
<br>

# Usage

<img src=https://raw.githubusercontent.com/antichown/0x94TR/master/images/scope.jpg>
<br>

# Just browse the website!

<br>

<img src=https://raw.githubusercontent.com/antichown/0x94TR/master/images/xxe.png>
<br>



<img src=https://raw.githubusercontent.com/antichown/0x94TR/master/images/www.png>

 

# Watch the video<br>

[![0x94TR Burp Suite Extension](http://img.youtube.com/vi/HWMUSTBVovk/0.jpg)](http://www.youtube.com/watch?v=HWMUSTBVovk "0x94TR Burp Suite Extension")
